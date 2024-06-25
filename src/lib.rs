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

type InterfaceHandle = Arc<Mutex<ConnectionManager>>;

pub struct Interface {
    ih: InterfaceHandle,
    jh: thread::JoinHandle<()>,
}

impl Interface {
    pub fn new() -> io::Result<Self> {
        let nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
        let ih: InterfaceHandle = Arc::default();
        let jh = {
            let cm = ih.clone();
            thread::spawn(move || {
                let _nic = nic;
                let _cm = cm;
                let _buf = [0u8; 1500];
                // TODO:
                unimplemented!()
            })
        };
        Ok(Interface { ih, jh })
    }

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
    ih: InterfaceHandle,
}

impl TcpListener {
    fn try_accept(&mut self, buf: &mut [u8]) -> io::Result<TcpStream> {
        let mut ih = self.ih.lock().unwrap();
        match ih
            .pending
            .get_mut(&self.port)
            .expect("port closed while listening")
            .pop_front()
        {
            Some(quad) => Ok(TcpStream {
                quad,
                ih: self.ih.clone(),
            }),
            None => {
                // TODO: block
                Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "no connection to accept",
                ))
            }
        }
    }
}

pub struct TcpStream {
    quad: Quad,
    ih: InterfaceHandle,
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unimplemented!()
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        unimplemented!()
    }

    fn flush(&mut self) -> std::io::Result<()> {
        unimplemented!()
    }
}
