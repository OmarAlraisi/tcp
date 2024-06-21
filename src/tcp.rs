use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use std::io;
use tun_tap::Iface;

pub enum State {
    SynRcvd,
    Estab,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    iphdr: Ipv4Header,
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
    /// unacknowledged
    una: u32,
    /// next
    nxt: u32,
    /// window
    wnd: u16,
    /// urgent pointer
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
    /// next
    nxt: u32,
    /// window
    wnd: u16,
    /// urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

impl Connection {
    /// When accepting a new connection
    pub fn accept<'a>(
        nic: &mut Iface,
        iphdr: &'a Ipv4HeaderSlice,
        tcphdr: &'a TcpHeaderSlice,
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];
        if !tcphdr.syn() {
            return Ok(None);
        }

        // Create tcp and ip headers to send a syn_ack packet
        let iss = 0;
        let window_size = 10;
        let mut syn_ack = TcpHeader::new(
            tcphdr.destination_port(),
            tcphdr.source_port(),
            iss,
            window_size,
        );
        syn_ack.acknowledgment_number = tcphdr.sequence_number() + 1;
        syn_ack.syn = true;
        syn_ack.ack = true;

        // TODO: Shouldn't use the same window size set by the sender
        let mut connection = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss + 1,
                wnd: window_size,
                up: false,
                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                nxt: tcphdr.sequence_number() + 1,
                wnd: tcphdr.window_size(),
                up: false,
                irs: tcphdr.sequence_number(),
            },
            iphdr: Ipv4Header::new(
                syn_ack.header_len_u16(),
                64,
                IpNumber::TCP,
                iphdr.destination(),
                iphdr.source(),
            )
            .expect("Payload is too big!"),
        };

        // Write the packet to the buffer and send it to the nic
        syn_ack.checksum = syn_ack
            .calc_checksum_ipv4(&connection.iphdr, &[])
            .expect("Failed to calculate checksum!");

        connection
            .iphdr
            .set_payload_len(syn_ack.header_len() + 0)
            .expect("Payload size too big!");

        let unwritten = {
            let mut unwritten = &mut buf[..];
            connection.iphdr.write(&mut unwritten)?;
            syn_ack.write(&mut unwritten)?;
            unwritten.len()
        };
        nic.send(&buf[..buf.len() - unwritten])?;

        Ok(Some(connection))
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut Iface,
        tcphdr: &'a TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<()> {
        // Acceptable ACK check. (RFC 9293 - Section 4.3)
        if !in_range_wrap(
            self.send.una,
            tcphdr.acknowledgment_number(),
            self.send.nxt.wrapping_add(1),
        ) {
            return Ok(());
        }

        // Validate segment. (RFC 9293 - Section 4.3)
        // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        let seqn = tcphdr.sequence_number();
        match (data.len(), self.recv.wnd) {
            (0, 0) => {
                if seqn != self.recv.nxt {
                    return Ok(());
                }
            }
            (0, _) => {
                if !in_range_wrap(
                    self.recv.nxt.wrapping_sub(1),
                    seqn,
                    self.recv.nxt.wrapping_add(self.recv.wnd as u32),
                ) {
                    return Ok(());
                }
            }
            (_, 0) => return Ok(()),
            (_, _) => {
                if !(in_range_wrap(
                    self.recv.nxt.wrapping_sub(1),
                    seqn,
                    self.recv.nxt.wrapping_add(self.recv.wnd as u32),
                ) && in_range_wrap(
                    self.recv.nxt.wrapping_sub(1),
                    seqn + data.len() as u32 - 1,
                    self.recv.nxt.wrapping_add(self.recv.wnd as u32),
                )) {
                    return Ok(());
                }
            }
        }

        let mut buf = [0u8; 1500];
        match self.state {
            State::SynRcvd => {
                if !(tcphdr.ack() && !tcphdr.syn()) {
                    return Ok(());
                }

                let mut rst_tcp = TcpHeader::new(
                    tcphdr.destination_port(),
                    tcphdr.source_port(),
                    self.send.nxt,
                    self.send.wnd,
                );
                self.send.nxt = tcphdr.sequence_number() + 1;

                rst_tcp.rst = true;

                let unwritten = {
                    let mut unwritten = &mut buf[..];
                    self.iphdr.write(&mut unwritten)?;
                    rst_tcp.write(&mut unwritten)?;
                    unwritten.len()
                };
                nic.send(&buf[..buf.len() - unwritten])?;
                self.state = State::Estab;
                Ok(())
            }
            State::Estab => Ok(()),
        }
    }
}

/// Checks if `x` is in the range of [`start`, `end`] exclusive.
///
/// Since start and end can wrap, we have three cases:
///
/// ---
///
/// - Case I: `start` and `end` are equal
/// ```
///
///                                
///        ---------------|---------------
///                     start
///                      end
///
///  Validitiy: No value of x can be in the range.
/// ```
///
/// - Case II: `start` and `end` are not equal and there is no wrapping:
/// ```
///
///             1         2          3
///        ----------|----------|----------
///                start       end
///
///  Validity: x is in the range iff it falls in the `2` area.
///
///  Condition: x > start && x < end
/// ```
///
/// ---
///
/// - Case III: `start` and `end` are not equal and there is wrapping:
/// ```
///
///             1         2          3
///        ----------|----------|----------
///                 end       start
///
///  Validity: x is in the range iff it fall in either area `1` or area `3`.
///
///  Condition: x > start || x < end
/// ```
fn in_range_wrap(start: u32, x: u32, end: u32) -> bool {
    use std::cmp::Ordering;
    match start.cmp(&end) {
        // Case I
        Ordering::Equal => false,

        // Case II
        Ordering::Less => x > start && x < end,

        // Case III
        Ordering::Greater => x < end || x > start,
    }
}
