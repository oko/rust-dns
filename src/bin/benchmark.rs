#![allow(dead_code,unused_imports,unused_must_use,unused_assignments)]

extern crate dns;

use std::io::net::udp::UdpSocket;
use std::io::net::ip::{Ipv4Addr, SocketAddr};
use std::io::BufReader;
use std::rand;

//use dns::msg::{DNSMessageReader,Message};
//use dns::msg::record::{Question,ResourceRecord};
//use dns::number;

use dns::hp::read_dns_message;

fn main() {
    let buf = include_bin!("../../tests/packets/net1-rs.bin");
    let npr = 4i;
    for _ in range(0, npr) {
        spawn(move || {
            for i in range(0, 1000000i / npr) {
                let buf2 = buf.clone();
                let m = read_dns_message(buf2).ok().unwrap();
                m.id;
                if i % 1000 == 0 { println!("completed {}",i); }
            }
        });
    }
}