mod tcp;

use etherparse::{IpNumber, Ipv4HeaderSlice, TcpHeaderSlice};
use std::{collections::HashMap, io, net::Ipv4Addr};
use tun_tap::{Iface, Mode};

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct Quad {
    local: (Ipv4Addr, u16),
    remote: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    // Create a virtual tunnel nic
    let mut nic = Iface::new("tun0", Mode::Tun)?;

    let mut connections: HashMap<Quad, tcp::Connection> = Default::default();
    let mut buf = [0u8; 1504];
    loop {
        // Read from the tunnel nic
        let len = nic.recv(&mut buf)?;

        // Ignore if not IPv4 packet
        let proto = u16::from_be_bytes([buf[2], buf[3]]);
        if proto != 0x0800 {
            continue;
        }

        // Parse IPv4 packet
        let iphdr = match Ipv4HeaderSlice::from_slice(&buf[4..len]) {
            Err(_) => continue,
            Ok(iphdr) => {
                if iphdr.protocol() != IpNumber::TCP {
                    continue;
                }
                iphdr
            }
        };

        // Parse TCP segment
        let tcphdr = match TcpHeaderSlice::from_slice(&buf[4 + iphdr.slice().len()..len]) {
            Err(_) => continue,
            Ok(tcphdr) => tcphdr,
        };

        connections
            .entry(Quad {
                local: (iphdr.source_addr(), tcphdr.source_port()),
                remote: (iphdr.destination_addr(), tcphdr.destination_port()),
            })
            .or_default()
            .on_packet(&mut nic, &iphdr, &tcphdr)?;
    }
}
