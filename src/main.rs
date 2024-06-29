use ruts_tcp::Tcp;
use std::io::{self, Read};

fn main() -> io::Result<()> {
    let mut tcp = Tcp::init()?;
    let mut listener = tcp.bind(8080)?;
    while let Ok(mut stream) = listener.accept() {
        println!("Received a connection");
        let mut buf = [0; 1024];
        stream.read(&mut buf)?;
        println!("Got: {}", String::from_utf8_lossy(&buf));
    }

    Ok(())
}
