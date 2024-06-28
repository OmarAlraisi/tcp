use ruts_tcp::Tcp;
use std::{
    io::{self, Read},
    thread,
};

fn main() -> io::Result<()> {
    let mut tcp = Tcp::init()?;
    let mut listener = tcp.bind(8080)?;
    while let Ok(mut stream) = listener.accept() {
        println!("Got new stream connection");
        // thread::spawn(move || {
        //     let mut buf = [0; 1024];
        //     loop {
        //         stream.read(&mut buf).unwrap();
        //         println!("Got: {}", String::from_utf8_lossy(&buf));
        //     }
        // });
    } 

    Ok(())
}
