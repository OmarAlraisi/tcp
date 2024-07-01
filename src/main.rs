use ruts_tcp::Tcp;
use std::{
    io::{self, Read, Write},
    net::SocketAddrV4,
    thread::sleep,
    time::Duration,
};

fn main() -> io::Result<()> {
    let mut tcp = Tcp::init()?;

    // Server
    let mut listener = tcp.bind(8080)?;
    let server_jh = std::thread::spawn(move || {
        while let Ok(mut stream) = listener.accept() {
            let mut buf = [0; 1024];
            loop {
                let len = stream.read(&mut buf).unwrap();
                if len == 0 {
                    break;
                }
                println!(
                    "Got a message of {} bytes long.\n{}",
                    len,
                    String::from_utf8_lossy(&buf[..len])
                );
            }
        }
    });

    // TODO: test by sending to another application
    // Client
    std::thread::spawn(move || {
        sleep(Duration::new(10, 0));
        println!("Now trying");
        if let Ok(mut client) = tcp.connect(SocketAddrV4::new("192.168.1.2".parse().unwrap(), 8080))
        {
            println!("Now running");
            client
                .write(String::from("Hello, world!").as_bytes())
                .unwrap();

            let mut buf = [0; 1024];
            let len = client.read(&mut buf).unwrap();
            println!("{}", String::from_utf8_lossy(&buf[..len]));

            // client.close();
        } else {
            println!("Failed somehow");
        }
    })
    .join()
    .unwrap();

    server_jh.join().unwrap();

    Ok(())
}
