#![allow(dead_code,unused_imports,unused_must_use,unused_assignments)]
#![feature(slicing_syntax)]

extern crate dns;

use std::io::net::udp::UdpSocket;
use std::io::net::ip::{Ipv4Addr, SocketAddr};
use std::io::BufReader;
use std::io;
use std::rand;

use dns::hp::{Message,Name,read_dns_message};
use dns::msg;
use dns::msg::DNSMessageWriter;
use dns::number;

fn main() {

    let args = std::os::args();
    let mut domain: &str;
    if args.len() < 2 {
        domain = "";
    } else {
        domain = args[1].as_slice();
    }

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
    let mut snd_buf = [0u8, ..65507];

    let tx_id = rand::random::<u16>();
    let mut msg = msg::Message::new(tx_id, true, number::OpCode::Query, false, false, true, false, false, false, number::RCode::NoError);
    let mut q = msg::record::Question::new();
    for s in domain.split('.') {
        if !s.is_empty() {
            q.qname.labels.push(String::from_str(s));
        }
    }
    msg.questions.push(q);
    let size: u64;
    {
        let mut w = io::BufWriter::new(&mut snd_buf);
        size = w.write_dns_message(&msg).ok().unwrap();
    }

    let snd_sa = SocketAddr { ip: Ipv4Addr(8, 8, 8, 8), port: 53 };
    socket.send_to(snd_buf[0..size as uint], snd_sa);
    println!("Request to {}: txid {}", snd_sa, tx_id);
    match socket.recv_from(&mut buf) {
        Ok((amt, src)) => {
            let m = read_dns_message(buf[0..amt]);
            println!("Response from {}:\n{}", src, m);
        },
        Err(e) => println!("Couldn't receive a datagram: {}", e),
    }

    drop(socket);
}