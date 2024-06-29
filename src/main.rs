use ruts_tcp::Tcp;
use std::io::{self, Read};

fn main() -> io::Result<()> {
    let mut tcp = Tcp::init()?;
    let mut listener = tcp.bind(8080)?;
    while let Ok(mut stream) = listener.accept() {
        let mut buf = [0; 1024];
        loop {
            let len = stream.read(&mut buf)?;
            if len == 0 {
                break;
            }
            println!("Got a message of {} bytes long.\n{}", len, String::from_utf8_lossy(&buf[..len]));
        }
    }

    Ok(())
}
