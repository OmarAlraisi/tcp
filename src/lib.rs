mod tcp;
use std::collections::hash_map::Entry;
use std::{
    collections::{HashMap, VecDeque},
    io::{
        self,
        prelude::{Read, Write},
    },
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    thread,
};

const TRANSMISSION_QLEN_SIZE: usize = 1000 * 1500;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct Quad {
    local: (Ipv4Addr, u16),
    remote: (Ipv4Addr, u16),
}

#[derive(Default)]
struct ConnectionManager {
    connections: HashMap<Quad, tcp::Connection>,
    pending: HashMap<u16, VecDeque<Quad>>,
}

type TcpHandler = Arc<Mutex<ConnectionManager>>;

pub struct Tcp {
    ih: TcpHandler,
    jh: thread::JoinHandle<()>,
}

impl Tcp {
    /// Creates a new NIC and initializes the connection manager state
    pub fn init() -> io::Result<Self> {
        let nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
        let ih: TcpHandler = Arc::default();
        let cm = ih.clone();
        let jh = thread::spawn(move || {
            let _nic = nic;
            let _cm = cm;
            let _buf = [0u8; 1500];

            // TODO: This thread is for managing timers and recieving packets from the nic.
            unimplemented!()
        });
        Ok(Tcp { ih, jh })
    }

    /// Binds to a new port.
    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        let mut cm = self.ih.lock().unwrap();

        match cm.pending.entry(port) {
            Entry::Vacant(e) => {
                e.insert(VecDeque::new());
            }
            Entry::Occupied(_) => {
                return Err(io::Error::new(io::ErrorKind::AddrInUse, "port is bound!"));
            }
        }
        drop(cm);

        Ok(TcpListener {
            port,
            ih: self.ih.clone(),
        })
    }
}

pub struct TcpListener {
    port: u16,
    ih: TcpHandler,
}

impl TcpListener {
    fn try_accept(&mut self, buf: &mut [u8]) -> io::Result<TcpStream> {
        let mut ih = self.ih.lock().unwrap();
        if let Some(quad) = ih
            .pending
            .get_mut(&self.port)
            .expect("port closed while listener is active!")
            .pop_back()
        {
            Ok(TcpStream {
                quad,
                ih: self.ih.clone(),
            })
        } else {
            // TODO: block
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no connection to accept.",
            ))
        }
    }
}

pub struct TcpStream {
    quad: Quad,
    ih: TcpHandler,
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut cm = self.ih.lock().unwrap();
        let connection = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream terminated unexpectedly!",
            )
        })?;

        if connection.inbuf.is_empty() {
            // TODO: block
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no bytes to read.",
            ));
        }

        let (head, tail) = connection.inbuf.as_slices();
        let mut nread = std::cmp::min(head.len(), buf.len());
        buf.copy_from_slice(&head[..nread]);
        let tread = std::cmp::min(buf.len() - nread, tail.len());
        buf.copy_from_slice(&tail[..tread]);
        nread += tread;
        drop(connection.inbuf.drain(..nread));

        drop(cm);

        Ok(nread)
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut cm = self.ih.lock().unwrap();
        let connection = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream terminated unexpectedly!",
            )
        })?;

        if connection.outbuf.len() >= TRANSMISSION_QLEN_SIZE {
            // TODO: block user
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many bytes buffered.",
            ));
        }

        let nwrite = std::cmp::min(buf.len(), TRANSMISSION_QLEN_SIZE - connection.outbuf.len());
        connection.outbuf.extend(&buf[..nwrite]);
        drop(cm);

        Ok(nwrite)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut cm = self.ih.lock().unwrap();
        let connection = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream terminated unexpectedly!",
            )
        })?;

        if connection.outbuf.is_empty() {
            Ok(())
        } else {
            // TODO: block until outbuf is empty
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "outgoing buffer is not yet flushed",
            ))
        }
    }
}

impl TcpStream {
    pub fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        // TODO: send a FIN
        unimplemented!()
    }
}
