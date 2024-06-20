use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use std::io;
use tun_tap::Iface;

pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
}

pub struct Connection {
    state: State,
}

impl Default for Connection {
    fn default() -> Self {
        Connection {
            state: State::Listen,
        }
    }
}

impl Connection {
    pub fn on_packet<'a>(
        &self,
        nic: &mut Iface,
        iphdr: &'a Ipv4HeaderSlice,
        tcphdr: &'a TcpHeaderSlice,
    ) -> io::Result<()> {
        let mut buf = [0u8; 1500];
        match self.state {
            State::Closed => return Ok(()),
            State::Listen => {
                if !tcphdr.syn() {
                    // Only expected SYN packets!
                    return Ok(());
                }

                // Create a packet to conitnue establishing the connection
                let sequence_number = 0u32;
                let window_size = 0u16;
                let mut syn_ack_tcp = TcpHeader::new(
                    tcphdr.destination_port(),
                    tcphdr.source_port(),
                    sequence_number,
                    window_size,
                );

                syn_ack_tcp.syn = true;
                syn_ack_tcp.ack = true;

                let syn_ack_ip = Ipv4Header::new(
                    syn_ack_tcp.header_len_u16(),
                    64,
                    IpNumber::TCP,
                    iphdr.destination(),
                    iphdr.source(),
                )
                .unwrap();

                let unwritten = {
                    let mut unwritten = &mut buf[..];
                    syn_ack_ip.write(&mut unwritten)?;
                    syn_ack_tcp.write(&mut unwritten)?;
                    unwritten.len()
                };
                nic.send(&buf[..unwritten])?;
            }
            _ => {
                println!("Do something!");
            }
        }
        let data_len = iphdr.total_len() - (iphdr.slice().len() + tcphdr.slice().len()) as u16;

        println!(
            "{}:{} -> {}:{} || {}bytes!",
            iphdr.source_addr(),
            tcphdr.source_port(),
            iphdr.destination_addr(),
            tcphdr.destination_port(),
            data_len,
        );

        Ok(())
    }
}
