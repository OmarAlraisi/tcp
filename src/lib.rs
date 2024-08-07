mod tcp;

use etherparse::{IpNumber, Ipv4HeaderSlice, TcpHeaderSlice};
use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    io::{
        self,
        prelude::{Read, Write},
    },
    net::{Ipv4Addr, SocketAddrV4},
    os::fd::BorrowedFd,
    sync::{Arc, Condvar, Mutex, OnceLock},
    thread,
};

// TODO: CHANGEME
const TRANSMISSION_QLEN_SIZE: usize = 1000 * 1500;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct Quad {
    local: (Ipv4Addr, u16),
    remote: (Ipv4Addr, u16),
}

#[derive(Default, Debug)]
struct ConnectionManager {
    terminate: bool,
    connections: HashMap<Quad, tcp::Connection>,
    pending: HashMap<u16, VecDeque<Quad>>,
}

#[derive(Default, Debug)]
struct ConnHandler {
    conn_manager: Mutex<ConnectionManager>,

    // TODO: make the condvars per connection (i.e. per quad)
    pending_cvar: Condvar,
    receive_cvar: Condvar,
    send_cvar: Condvar,
    estab_cvar: Condvar,
}

type ConnectionHandler = Arc<ConnHandler>;

pub struct Tcp {
    /// Conection handler
    conn_handler: Option<ConnectionHandler>,
    join_handler: Option<thread::JoinHandle<io::Result<()>>>,
}

impl Drop for Tcp {
    fn drop(&mut self) {
        // Set connection manager's terminate to true
        self.conn_handler
            .as_mut()
            .unwrap()
            .conn_manager
            .lock()
            .unwrap()
            .terminate = true;

        // Drop the connection manager
        drop(self.conn_handler.take());

        // Wait for the packet processing thread to finish
        self.join_handler.take().unwrap().join().unwrap().unwrap();
    }
}

fn packet_loop(conn_handler: ConnectionHandler) -> io::Result<()> {
    let mut buf = [0u8; 1500];
    let nic = NIC::get_mut_ref()?;
    loop {
        use nix::poll;
        use std::os::unix::io::AsRawFd;
        let mut pfd = unsafe {
            [poll::PollFd::new(
                BorrowedFd::borrow_raw(nic.lock().unwrap().as_raw_fd()),
                poll::PollFlags::POLLIN,
            )]
        };
        let n = poll::poll(&mut pfd[..], poll::PollTimeout::from(10u8))?;
        assert_ne!(n, -1);
        // Read from the tunnel nic
        // TODO: Set timeout for the recv
        let len = nic.lock().unwrap().recv(&mut buf)?;

        // TODO: if conn_manager.terminate && Arc get_strong_refs(conn_manager) == 1; then tear
        // down all connections and return.

        let mut offset = 0;
        // Parse IPv4 packet
        let iphdr = match Ipv4HeaderSlice::from_slice(&buf[offset..len]) {
            // Something other than IPv4
            Err(_) => continue,
            Ok(iphdr) => {
                if iphdr.protocol() != IpNumber::TCP {
                    continue;
                }
                offset += iphdr.slice().len();
                iphdr
            }
        };

        // Parse TCP segment
        let tcphdr = match TcpHeaderSlice::from_slice(&buf[offset..len]) {
            Err(_) => continue,
            Ok(tcphdr) => {
                offset += tcphdr.slice().len();
                tcphdr
            }
        };

        let mut cm_lock = conn_handler.conn_manager.lock().unwrap();
        let cm = &mut *cm_lock;
        let quad = Quad {
            local: (iphdr.destination_addr(), tcphdr.destination_port()),
            remote: (iphdr.source_addr(), tcphdr.source_port()),
        };
        match cm.connections.entry(quad) {
            Entry::Occupied(mut connection) => {
                let available = connection.get_mut().on_packet(&tcphdr, &buf[offset..len])?;

                // remove the connection from the connections map if closed
                if connection.get().is_closed() {
                    connection.remove();
                    continue;
                }

                // TODO: compare before/after and do the following only if they differ
                drop(cm_lock);
                if available.contains(tcp::Available::READ) {
                    conn_handler.receive_cvar.notify_all();
                }
                if available.contains(tcp::Available::WRITE) {
                    // TODO: do something similar to the receive_cvar
                }
            }
            Entry::Vacant(entry) => {
                if let Some(pending) = cm.pending.get_mut(&tcphdr.destination_port()) {
                    if let Some(connection) = tcp::Connection::accept(&iphdr, &tcphdr)? {
                        entry.insert(connection);
                        pending.push_front(quad);
                        drop(cm_lock);
                        conn_handler.pending_cvar.notify_all();
                    }
                }
            }
        }
    }
}

struct NIC;

impl NIC {
    fn init() -> io::Result<()> {
        let nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
        unsafe {
            NIC_ONCE_LOCK
                .set(Arc::new(Mutex::new(nic)))
                .expect("failed to set NIC");
        }
        Ok(())
    }

    fn get_mut_ref() -> io::Result<Arc<Mutex<tun_tap::Iface>>> {
        let nic;
        unsafe {
            nic = NIC_ONCE_LOCK
                .get_mut()
                .expect("failed to get mutable reference to the NIC")
                .clone();
        }
        Ok(nic)
    }
}

pub(crate) static mut NIC_ONCE_LOCK: OnceLock<Arc<Mutex<tun_tap::Iface>>> = OnceLock::new();

impl Tcp {
    /// Creates a new NIC and initializes the connection manager state
    pub fn init() -> io::Result<Self> {
        NIC::init()?;
        let conn_handler: ConnectionHandler = Arc::default();
        let join_handler = {
            let cm = conn_handler.clone();
            thread::spawn(move || packet_loop(cm))
        };
        Ok(Tcp {
            conn_handler: Some(conn_handler),
            join_handler: Some(join_handler),
        })
    }

    /// Binds to a new port.
    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        let mut cm = self
            .conn_handler
            .as_mut()
            .unwrap()
            .conn_manager
            .lock()
            .unwrap();

        match cm.pending.entry(port) {
            Entry::Vacant(e) => {
                e.insert(VecDeque::new());
            }
            Entry::Occupied(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "port already bound!",
                ));
            }
        }
        drop(cm);

        Ok(TcpListener {
            port,
            conn_handler: self.conn_handler.as_mut().unwrap().clone(),
        })
    }

    /// Connects to a remote host
    pub fn connect(&mut self, addr: SocketAddrV4) -> io::Result<TcpStream> {
        let my_ip: Ipv4Addr = std::env::var("MY_IP")
            .unwrap()
            .parse()
            .expect("local host doesn't have a valid IP");
        let quad = Quad {
            local: (my_ip, 9182u16),
            remote: (addr.ip().to_owned(), addr.port()),
        };
        let connection = tcp::Connection::establish_connection(quad.remote.0, quad.remote.1)?;
        let conn_handler = self.conn_handler.as_mut().unwrap().clone();
        let mut cm = conn_handler.conn_manager.lock().unwrap();

        assert!(cm.connections.insert(quad, connection).is_none());

        loop {
            let connection = cm.connections.get(&quad).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "stream terminated unexpectedly",
                )
            })?;

            if connection.is_established() {
                println!("finally");
                return Ok(TcpStream {
                    quad,
                    conn_handler: self.conn_handler.as_ref().unwrap().clone(),
                });
            }

            cm = conn_handler.estab_cvar.wait(cm).unwrap();
        }
    }
}

#[derive(Debug)]
pub struct TcpListener {
    port: u16,
    conn_handler: Arc<ConnHandler>,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut cm = self.conn_handler.conn_manager.lock().unwrap();
        let pending = cm
            .pending
            .remove(&self.port)
            .expect("port closed while listener is active!");

        for quad in pending {
            // TODO: terminate connection
            // cm.connections.get_mut(&quad)

            unimplemented!()
        }
    }
}
impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {
        let mut cm = self.conn_handler.conn_manager.lock().unwrap();
        loop {
            if let Some(quad) = cm
                .pending
                .get_mut(&self.port)
                .expect("port closed while listener is active!")
                .pop_back()
            {
                return Ok(TcpStream {
                    quad,
                    conn_handler: self.conn_handler.clone(),
                });
            }
            cm = self.conn_handler.pending_cvar.wait(cm).unwrap();
        }
    }
}

pub struct TcpStream {
    quad: Quad,
    conn_handler: ConnectionHandler,
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut cm = self.conn_handler.conn_manager.lock().unwrap();
        loop {
            let connection = cm.connections.get(&self.quad).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "stream terminated unexpectedly",
                )
            })?;

            if connection.inbuf.is_empty() && connection.is_recv_closed() {
                // no more data to read, close stream
                return Ok(0);
            }

            if !connection.inbuf.is_empty() {
                let connection = cm.connections.get_mut(&self.quad).unwrap();

                // TODO: detect FIN and return nread 0

                let (head, tail) = connection.inbuf.as_slices();
                let mut nread = std::cmp::min(head.len(), buf.len());
                buf[..nread].copy_from_slice(&head[..nread]);
                let tread = std::cmp::min(buf.len() - nread, tail.len());
                buf[nread..nread + tread].copy_from_slice(&head[..tread]);
                nread += tread;
                drop(connection.inbuf.drain(..nread));

                return Ok(nread);
            }

            cm = self.conn_handler.receive_cvar.wait(cm).unwrap();
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut cm = self.conn_handler.conn_manager.lock().unwrap();
        while cm
            .connections
            .get(&self.quad)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "stream terminated unexpectedly!",
                )
            })?
            .outbuf
            .len()
            >= TRANSMISSION_QLEN_SIZE
        {
            cm = self.conn_handler.send_cvar.wait(cm).unwrap();
        }

        let connection = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream terminated unexpectedly!",
            )
        })?;
        let nwrite = std::cmp::min(buf.len(), TRANSMISSION_QLEN_SIZE - connection.outbuf.len());
        connection.outbuf.extend(&buf[..nwrite]);

        Ok(nwrite)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut cm = self.conn_handler.conn_manager.lock().unwrap();
        loop {
            let connection = cm.connections.get(&self.quad).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "stream terminated unexpectedly!",
                )
            })?;

            if connection.outbuf.is_empty() {
                return Ok(());
            }

            cm = self.conn_handler.send_cvar.wait(cm).unwrap();
        }
    }
}

impl TcpStream {
    pub fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        // TODO: send a FIN
        unimplemented!()
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut _cm = self.conn_handler.conn_manager.lock().unwrap();
        // TODO: send a FIN
        // TODO: _eventually_ remove the self.quad's connection from cm.connections
    }
}
