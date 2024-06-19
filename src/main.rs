use tun_tap::{Iface, Mode};
use std::io;

fn main() -> io::Result<()> {
    let nic = Iface::new("tun0", Mode::Tun)?;
    let mut buf = [0u8; 1504];

    loop{
        let len = nic.recv(&mut buf)?;
        let flags = u16::from_be_bytes([buf[0], buf[1]]);
        let proto = u16::from_be_bytes([buf[2], buf[3]]);

        if proto != 0x0800 {
            continue;
        }

        println!("Received {} bytes (flags: {:x}, proto: {:x}): {:?}", len - 4, flags, proto, &buf[4..len]);
    }
}
