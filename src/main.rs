mod tcp;

use etherparse::{IpNumber, Ipv4HeaderSlice, TcpHeaderSlice};
use std::{
    collections::{hash_map::Entry, HashMap},
    io,
    net::Ipv4Addr,
};
use tun_tap::{Iface, Mode};

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct Quad {
    local: (Ipv4Addr, u16),
    remote: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    // Create a virtual tunnel nic
    let mut nic = Iface::without_packet_info("tun0", Mode::Tun)?;

    let mut connections: HashMap<Quad, tcp::Connection> = Default::default();
    let mut buf = [0u8; 1500];
    loop {
        // Read from the tunnel nic
        let len = nic.recv(&mut buf)?;

        // Parse IPv4 packet
        let iphdr = match Ipv4HeaderSlice::from_slice(&buf[4..len]) {
            // Something other than IPv4
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

        match connections.entry(Quad {
            local: (iphdr.source_addr(), tcphdr.source_port()),
            remote: (iphdr.destination_addr(), tcphdr.destination_port()),
        }) {
            Entry::Occupied(mut connection) => {
                connection.get_mut().on_packet(&mut nic, &iphdr, &tcphdr)?;
            }
            Entry::Vacant(entry) => {
                if let Some(connection) = tcp::Connection::accept(&mut nic, &iphdr, &tcphdr)? {
                    entry.insert(connection);
                }
            }
        }
    }
}
