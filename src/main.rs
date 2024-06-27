use ruts_tcp::Tcp;
use std::{
    io::{self, Read},
    thread,
};

fn main() -> io::Result<()> {
    let mut tcp = Tcp::init()?;
    let mut listener = tcp.bind(8080)?;
    let jh: thread::JoinHandle<io::Result<()>> = thread::spawn(move || loop {
        let mut stream = listener.accept()?;
        println!("Got new stream connection");
        loop {
            let mut buf = [0; 1024];
            stream.read(&mut buf)?;
            let got = String::from_utf8_lossy(&buf[..]);
            println!("Got: {}", got);
        }
    });

    jh.join().unwrap()
}
