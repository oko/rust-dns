#![allow(dead_code,unused_imports,unused_must_use,unused_assignments)]

extern crate dns;

use std::io::net::udp::UdpSocket;
use std::io::net::ip::{Ipv4Addr, SocketAddr};
use std::io::BufReader;
use std::rand;

use dns::msg::{DNSMessageReader,Message};
//use dns::msg::record::{Question,ResourceRecord};
use dns::number;

fn main() {
    let mut socket: UdpSocket;
    let mut bind_count = 0u;
    let mut bound = false;
    loop {
        let addr = SocketAddr { ip: Ipv4Addr(0, 0, 0, 0), port: ((rand::random::<u16>() % 16382) + 49152) };
        socket = match UdpSocket::bind(addr) {
            Ok(s) => {
                bound = true;
                s
            },
            Err(_) => {
                if bind_count < 1000 {
                    bind_count += 1;
                    continue;
                } else {
                    break;
                }
            },
        };
        if bound { break; }
    }
    let mut buf = [0u8, ..65507];

    //let tx_id = rand::random::<u16>();
    //let mut msg = Message::new(tx_id, true, number::OpCode::Query, false, false, true, false, false, false, number::RCode::NoError);
    let snd_buf = [0xb,0x8d,0x1,0x0,0x0,0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x8,0x66,0x61,0x63,0x65,0x62,0x6f,0x6f,0x6b,0x3,0x63,0x6f,0x6d,0x0,0x0,0x1,0x0,0x1];
    let snd_sa = SocketAddr { ip: Ipv4Addr(8, 8, 8, 8), port: 53 };
    socket.send_to(&snd_buf, snd_sa);
    println!("Sent packet");

    match socket.recv_from(&mut buf) {
        Ok((_,_)) => {
            let mut r = BufReader::new(&buf);
            println!("{}", r.read_dns_message());
        }
        Err(e) => println!("Couldn't receive a datagram: {}", e)
    }
    drop(socket);
}