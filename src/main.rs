use etherparse::{IpNumber, Ipv4HeaderSlice, TcpHeaderSlice};
use std::io;
use tun_tap::{Iface, Mode};

fn print_connection_info(ip_packet: Ipv4HeaderSlice, tcp_segment: TcpHeaderSlice) {
    println!(
        "{}:{} -> {}:{}",
        ip_packet.source_addr(),
        tcp_segment.source_port(),
        ip_packet.destination_addr(),
        tcp_segment.destination_port()
    );
}

fn handle_frame(slice: &[u8]) {
    // Ignore if not IPv4 packet
    let proto = u16::from_be_bytes([slice[2], slice[3]]);
    if proto != 0x0800 {
        return;
    }

    // Parse IPv4 packet
    let ip_packet = match Ipv4HeaderSlice::from_slice(&slice[4..]) {
        Err(_) => return,
        Ok(ip_packet) => {
            if ip_packet.protocol() != IpNumber::TCP {
                return;
            }
            ip_packet
        }
    };

    // Parse TCP segment
    let tcp_segment = match TcpHeaderSlice::from_slice(&slice[4 + ip_packet.slice().len()..]) {
        Err(_) => return,
        Ok(tcp_segment) => tcp_segment,
    };

    // Print connection details
    print_connection_info(ip_packet, tcp_segment);
}

fn main() -> io::Result<()> {
    // Create a virtual tunnel nic
    let nic = Iface::new("tun0", Mode::Tun)?;

    let mut buf = [0u8; 1504];
    loop {
        // Read from the tunnel nic
        let len = nic.recv(&mut buf)?;

        handle_frame(&buf[..len]);
    }
}
