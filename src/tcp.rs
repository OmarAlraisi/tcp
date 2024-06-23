use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use std::cmp::Ordering;
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
        let mut buf = [0u8; 1500];

        // Set the ip header payload
        let payload_len = {
            let full_payload = self.iphdr.header_len() + self.tcphdr.header_len() + payload.len();
            match buf.len().cmp(&full_payload) {
                Ordering::Less | Ordering::Equal => buf.len() - self.iphdr.header_len(),
                Ordering::Greater => self.tcphdr.header_len() + payload.len(),
            }
        };
        self.iphdr
            .set_payload_len(payload_len)
            .expect("Payload length is too big!");

        // Set the tcp header seqn, ackn, and checksum
        self.tcphdr.sequence_number = self.send.nxt;
        self.tcphdr.acknowledgment_number = self.recv.nxt;
        self.tcphdr.checksum = self
            .tcphdr
            .calc_checksum_ipv4(&self.iphdr, &[])
            .expect("Payload is too big!");

        // Write to buffer and then to the nic
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

    // TODO: This function should send the packets itself rather than using Connection::write,
    //       because it needs careful handling of the sequence and acknowledgement numbers, it
    //       should also not modify the connection send and receive sequence spaces.
    /// Sends TCP RST packets
    ///
    /// In accordance to RFC 9293 - Section 3.5.1, an RST packet is sent in when a TCP packet
    /// arrives that isn't intended for the current connection. And should handled based on the
    /// STATE group rules.
    ///
    /// --- 
    ///
    /// **Group 1**: The connection is in the `CLOSED` state.
    ///
    /// Send RST: True
    ///
    /// If the incoming segment has the ACK bit set, the reset takes its sequence number from the 
    /// ACK field of the segment; otherwise, the reset has sequence number zero and the ACK field 
    /// is set to the sum of the sequence number and segment length of the incoming segment. The 
    /// connection remains in the CLOSED state.
    ///
    /// **Group 2**: The connection is not yet in a synchronized state.
    ///
    /// Send RST: True
    ///
    /// If the incoming segment has an ACK field, the reset takes its sequence number from the ACK 
    /// field of the segment; otherwise, the reset has sequence number zero and the ACK field is 
    /// set to the sum of the sequence number and segment length of the incoming segment. The 
    /// connection remains in the same state.
    ///
    /// **Group 3**: The connection is in a synchronized state.
    ///
    /// Send RST: False
    ///
    /// Must be responded to with an empty acknowledgment segment (without any user data) 
    /// containing the current send sequence number and an acknowledgment indicating the next 
    /// sequence number expected to be received, and the connection remains in the same state.
    ///
    fn send_rst<'a>(
        &mut self,
        nic: &mut Iface,
        tcphdr: &'a TcpHeaderSlice,
        payload: &[u8],
    ) -> io::Result<()> {
        if !self.state.is_synchronized() {
            self.tcphdr.sequence_number = if tcphdr.ack() {
                tcphdr.acknowledgment_number()
            } else {
                0
            }
            .wrapping_add(payload.len() as u32);

            self.tcphdr.acknowledgment_number =
                tcphdr.sequence_number().wrapping_add(payload.len() as u32);
        }
        self.tcphdr.rst = true;
        self.tcphdr.ack = true;

        self.write(nic, &[])?;
        Ok(())
    }

    /// Resets all tcp header flags
    ///
    /// This function should be called as soon as a packet is recieved to avoid reusing flags.
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
                // Send RST (RFC 9293 - Section 3.5.1 - Group 2)
                self.send_rst(nic, tcphdr, payload)?;
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
    match start.cmp(&end) {
        Ordering::Equal => false,
        Ordering::Less => x > start && x < end,
        Ordering::Greater => x < end || x > start,
    }
}
