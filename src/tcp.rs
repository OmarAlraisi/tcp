use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use std::io::{self, Write};
use tun_tap::Iface;

pub enum State {
    SynRcvd,
    Estab,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match self {
            State::SynRcvd => false,
            State::Estab => true,
        }
    }
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    iphdr: Ipv4Header,
    tcphdr: TcpHeader,
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
    /// Takes a nic and payload and writes an IP packet to the nic
    /// Returns a result containing the number of payload bytes written to the nic
    fn write(&mut self, nic: &mut Iface, payload: &[u8]) -> io::Result<usize> {
        // Set the ip header payload
        self.iphdr
            .set_payload_len(self.tcphdr.header_len() + payload.len())
            .expect("Payload length is too big!");

        // Set the tcp header seqn, ackn, and checksum
        self.tcphdr.sequence_number = self.send.nxt;
        self.tcphdr.acknowledgment_number = self.recv.nxt;
        self.tcphdr.checksum = self
            .tcphdr
            .calc_checksum_ipv4(&self.iphdr, &[])
            .expect("Payload is too big!");

        // Write to buffer and then to the nic
        let mut buf = [0u8; 1500];
        let (unwritten, payload_bytes) = {
            let mut unwritten = &mut buf[..];
            self.iphdr.write(&mut unwritten)?;
            self.tcphdr.write(&mut unwritten)?;
            let payload_bytes = unwritten.write(payload)?;
            (unwritten.len(), payload_bytes)
        };
        nic.send(&buf[..buf.len() - unwritten])?;

        // Update the send next sequence number
        self.send.nxt = self
            .send
            .nxt
            .wrapping_add(payload_bytes as u32)
            .wrapping_add(if self.tcphdr.syn || self.tcphdr.fin {
                1
            } else {
                0
            });

        Ok(payload_bytes)
    }

    /// Prepares TCP RST packets
    // fn send_rst<'a>(&mut self, nic: &mut Iface, tcphdr: &'a TcpHeaderSlice) -> io::Result<()> {
    //     if !self.state.is_synchronized() {
    //         if tcphdr.ack() {
    //             // Use the acknowledgment number from the received segment for the sequence number
    //             self.tcphdr.sequence_number = tcphdr.acknowledgment_number();
    //         } else {
    //             // Use zero for the sequence number
    //             self.tcphdr.sequence_number = 0;
    //         }
    //     }
    //     self.tcphdr.rst = true;

    //     self.write(nic, &[])?;
    //     Ok(())
    // }

    fn reset_tcphdr_flags(&mut self) {
        self.tcphdr.cwr = false;
        self.tcphdr.ece = false;
        self.tcphdr.urg = false;
        self.tcphdr.ack = false;
        self.tcphdr.psh = false;
        self.tcphdr.rst = false;
        self.tcphdr.syn = false;
        self.tcphdr.fin = false;
    }

    /// When accepting a new connection
    pub fn accept<'a>(
        nic: &mut Iface,
        iphdr: &'a Ipv4HeaderSlice,
        tcphdr: &'a TcpHeaderSlice,
    ) -> io::Result<Option<Self>> {
        if !tcphdr.syn() {
            // TODO: Send RST (RFC 9293 - Section 3.5.1 - Group 1)
            return Ok(None);
        }

        // Create tcp and ip headers to send a syn_ack packet
        let iss = 0;
        let window_size = 10;
        let mut connection = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss,
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
            iphdr: Ipv4Header::new(0, 64, IpNumber::TCP, iphdr.destination(), iphdr.source())
                .expect("Payload is too big!"),
            tcphdr: TcpHeader::new(
                tcphdr.destination_port(),
                tcphdr.source_port(),
                iss,
                window_size,
            ),
        };
        connection.tcphdr.syn = true;
        connection.tcphdr.ack = true;

        connection.write(nic, &[])?;

        Ok(Some(connection))
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut Iface,
        tcphdr: &'a TcpHeaderSlice,
        payload: &[u8],
    ) -> io::Result<()> {
        // Acceptable ACK check. (RFC 9293 - Section 4.3)
        if !in_range_wrap(
            self.send.una,
            tcphdr.acknowledgment_number(),
            self.send.nxt.wrapping_add(1),
        ) {
            if !self.state.is_synchronized() {
                // TODO: Send RST (RFC 9293 - Section 3.5.1 - Group 2)
                // self.send_rst(nic, tcphdr)?;
            }
            return Ok(());
        }

        // Validate segment. (RFC 9293 - Section 4.3)
        let seg_seq = tcphdr.sequence_number();
        let seg_len = payload.len() as u32 + if tcphdr.syn() || tcphdr.fin() { 1 } else { 0 };
        match (seg_len, self.recv.wnd) {
            (0, 0) => {
                if seg_seq != self.recv.nxt {
                    return Ok(());
                }
            }
            (0, _) => {
                if !in_range_wrap(
                    self.recv.nxt.wrapping_sub(1),
                    seg_seq,
                    self.recv.nxt.wrapping_add(self.recv.wnd as u32),
                ) {
                    return Ok(());
                }
            }
            (_, 0) => return Ok(()),
            (_, _) => {
                if !(in_range_wrap(
                    self.recv.nxt.wrapping_sub(1),
                    seg_seq,
                    self.recv.nxt.wrapping_add(self.recv.wnd as u32),
                ) && in_range_wrap(
                    self.recv.nxt.wrapping_sub(1),
                    seg_seq + seg_len - 1,
                    self.recv.nxt.wrapping_add(self.recv.wnd as u32),
                )) {
                    return Ok(());
                }
            }
        }

        // Reset the tcp header flags regardless of the handler
        self.reset_tcphdr_flags();
        match self.state {
            State::SynRcvd => {
                // Since we only sent a syn segment, this has to be acking our syn segment
                if !tcphdr.ack() {
                    return Ok(());
                }

                // Update the connection's state
                self.state = State::Estab;

                // Set the sequence number and the flags for the tcp header
                self.tcphdr.fin = true;

                // Write to the nic
                self.write(nic, &[])?;

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
