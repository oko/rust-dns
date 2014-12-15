extern crate dns;

use dns::msg::{Message,DNSMessageReader};
use dns::msg::record::ResourceRecord;
use std::io;

fn check_std_query_recursive(m: &Message) {
    assert_eq!(m.flags, 0x0100);
    assert_eq!(m.questions.len(), 1);
    assert_eq!(m.answers.len(), 0);
    assert_eq!(m.nameservers.len(), 0);
    assert_eq!(m.additionals.len(), 0);
}
fn check_std_query_norecurse(m: &Message) {
    assert_eq!(m.flags, 0x0000);
    assert_eq!(m.questions.len(), 1);
    assert_eq!(m.answers.len(), 0);
    assert_eq!(m.nameservers.len(), 0);
    assert_eq!(m.additionals.len(), 0);
}
fn check_std_response_recursive(m: &Message, q: uint, a: uint, n: uint, x: uint) {
    assert_eq!(m.flags, 0x8180);
    assert_eq!(m.questions.len(), q);
    assert_eq!(m.answers.len(), a);
    assert_eq!(m.nameservers.len(), n);
    assert_eq!(m.additionals.len(), x);
}
fn check_std_response_norecurse(m: &Message, q: uint, a: uint, n: uint, x: uint) {
    assert_eq!(m.flags, 0x8000);
    assert_eq!(m.questions.len(), q);
    assert_eq!(m.answers.len(), a);
    assert_eq!(m.nameservers.len(), n);
    assert_eq!(m.additionals.len(), x);
}

#[test]
fn test_parse_fb1_rq() {
    let rq = include_bin!("packets/fb1-rq.bin");
    let m = Message::from_buf(rq).ok().unwrap();
    assert_eq!(m.id, 0x0b8d);
    assert_eq!(m.flags, 0x0100);
    assert_eq!(m.questions.len(), 1);
    assert_eq!(m.answers.len(), 0);
    assert_eq!(m.nameservers.len(), 0);
    assert_eq!(m.additionals.len(), 0);
}
#[test]
fn test_parse_fb1_rs() {
    let rs = include_bin!("packets/fb1-rs.bin");
    let m = Message::from_buf(rs).ok().unwrap();
    assert_eq!(m.id, 0x0b8d);
    assert_eq!(m.flags, 0x8180);
    assert_eq!(m.questions.len(), 1);
    assert_eq!(m.answers.len(), 1);
    assert_eq!(m.nameservers.len(), 0);
    assert_eq!(m.additionals.len(), 0);
}

#[test]
fn test_parse_comns1_rs() {
    let rs = include_bin!("packets/comns1-rs.bin");
    let mut r = io::BufReader::new(rs);
    let m = match r.read_dns_message() {
            Ok(msg) => msg,
            Err(e) => {
                println!("{}", e);
                return;
            }
        };
    assert_eq!(m.id, 0x363a);
    assert_eq!(m.flags, 0x8000);
    assert_eq!(m.questions.len(), 1);
    assert_eq!(m.answers.len(), 0);
    assert_eq!(m.nameservers.len(), 13);
    assert_eq!(m.additionals.len(), 14);
}

#[test]
fn test_parse_net1_rq() {
    let rq = include_bin!("packets/net1-rq.bin");
    let mut r = io::BufReader::new(rq);
    let m = match r.read_dns_message() {
            Ok(msg) => msg,
            Err(e) => {
                println!("{}", e);
                return;
            }
        };

    assert_eq!(m.id, 0xe1c9);
    check_std_query_norecurse(&m);
}

#[test]
fn test_parse_net1_rs() {
    let rs = include_bin!("packets/net1-rs.bin");
    let mut r = io::BufReader::new(rs);
    let mut m = match r.read_dns_message() {
            Ok(msg) => msg,
            Err(e) => {
                println!("{}", e);
                return;
            }
        };

    assert_eq!(m.id, 0xe1c9);
    check_std_response_norecurse(&m, 1, 0, 13, 15);
    let q = m.questions[0].clone();
    assert_eq!(format!("{}",q.qname).as_slice(), "net.");
}