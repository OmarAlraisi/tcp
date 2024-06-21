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
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
}

/// State of the Send Sequence Space. (RFC 9293 - Section 3.3.1 - Figure 3)
///
/// ```
///             1         2          3          4
///        ----------|----------|----------|----------
///               SND.UNA    SND.NXT    SND.UNA
///                                    +SND.WND
///
///  1 - old sequence numbers that have been acknowledged
///  2 - sequence numbers of unacknowledged data
///  3 - sequence numbers allowed for new data transmission
///  4 - future sequence numbers that are not yet allowed
/// ```
struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: usize,
    /// segment acknowledgment number used for last window update
    wl2: usize,
    /// initial send sequence number
    iss: u32,
}

// For example if a segment has a SEG.SEQ of 1234 and its data has a length of 1250, then the next segment
// should have a SEG.SEQ of 2483

/// State of the Receive Sequence Space. (RFC 9293 - Section 3.3.1 - Figure 4)
///
/// ```
///    1          2          3
///             ----------|----------|----------
///                    RCV.NXT    RCV.NXT
///                              +RCV.WND
///
///  1 - old sequence numbers that have been acknowledged
///  2 - sequence numbers allowed for new reception
///  3 - future sequence numbers that are not yet allowed
/// ```
struct RecvSequenceSpace {
    /// receive next
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept<'a>(
        nic: &mut Iface,
        iphdr: &'a Ipv4HeaderSlice,
        tcphdr: &'a TcpHeaderSlice,
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];
        if !tcphdr.syn() {
            // Only expected SYN packets!
            return Ok(None);
        }

        let iss = 0;
        let mut connection = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss + 1,
                wnd: 0,
                up: false,
                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                nxt: 0,
                wnd: 0,
                up: false,
                irs: 0,
            },
        };

        // Keep track of sender info
        connection.recv.irs = tcphdr.sequence_number();
        connection.recv.nxt = tcphdr.sequence_number() + 1;
        connection.recv.wnd = tcphdr.window_size();

        // Decide what we are sending them
        connection.send.iss = 0;
        connection.send.una = connection.send.iss;
        connection.send.nxt = connection.send.una;
        connection.send.wnd = 10;

        // Create a packet to conitnue establishing the connection
        let mut syn_ack_tcp = TcpHeader::new(
            tcphdr.destination_port(),
            tcphdr.source_port(),
            connection.send.iss,
            connection.send.wnd,
        );
        syn_ack_tcp.acknowledgment_number = connection.recv.nxt;
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

        syn_ack_tcp.checksum = syn_ack_tcp
            .calc_checksum_ipv4(&syn_ack_ip, &[])
            .expect("Failed to calculate checksum");

        let unwritten = {
            let mut unwritten = &mut buf[..];
            syn_ack_ip.write(&mut unwritten)?;
            syn_ack_tcp.write(&mut unwritten)?;
            unwritten.len()
        };
        nic.send(&buf[..buf.len() - unwritten])?;
        let data_len = iphdr.total_len() - (iphdr.slice().len() + tcphdr.slice().len()) as u16;

        println!(
            "{}:{} -> {}:{} || {}bytes!",
            iphdr.source_addr(),
            tcphdr.source_port(),
            iphdr.destination_addr(),
            tcphdr.destination_port(),
            data_len,
        );

        Ok(Some(connection))
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut Iface,
        iphdr: &'a Ipv4HeaderSlice,
        tcphdr: &'a TcpHeaderSlice,
    ) -> io::Result<()> {
        Ok(())
    }
}
