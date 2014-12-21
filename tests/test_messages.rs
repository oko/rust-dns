#![allow(dead_code)]

extern crate dns;

use dns::msg::{Message,DNSMessageReader,DNSMessageWriter,Name};

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

fn write_test(m: &Message, buf: &[u8]) {
    let mut wbuf = [0u8, ..4096];
    let mut size = 0;
    {
        let mut w = io::BufWriter::new(&mut wbuf);
        size = w.write_dns_message(m).ok().unwrap();
    }
    assert_eq!(buf.as_slice(), wbuf.slice_to(size as uint));
}

#[test]
fn test_parse_fb1_rq() {
    let rq = include_bin!("packets/fb1-rq.bin");
    let m = Message::from_buf(rq).ok().unwrap();
    assert_eq!(m.id, 0x0b8d);
    check_std_query_recursive(&m);
}
#[test]
fn test_parse_fb1_rs() {
    let rs = include_bin!("packets/fb1-rs.bin");
    let m = Message::from_buf(rs).ok().unwrap();
    assert_eq!(m.id, 0x0b8d);
    check_std_response_recursive(&m, 1, 1, 0, 0);
}

#[test]
fn test_parse_comns1_rs() {
    let rs = include_bin!("packets/comns1-rs.bin");
    let mut r = io::BufReader::new(rs);
    let m = r.read_dns_message().ok().unwrap();
    assert_eq!(m.id, 0x363a);
    check_std_response_norecurse(&m, 1, 0, 13, 14);
}

#[test]
fn test_write_comns1_rs() {
    let rs = include_bin!("packets/comns1-rs.bin");
    let mut r = io::BufReader::new(rs);
    let m = r.read_dns_message().ok().unwrap();
    write_test(&m, rs);
}

#[test]
fn test_parse_net1_rq() {
    let rq = include_bin!("packets/net1-rq.bin");
    let mut r = io::BufReader::new(rq);
    let m = r.read_dns_message().ok().unwrap();

    assert_eq!(m.id, 0xe1c9);
    check_std_query_norecurse(&m);
}

#[test]
fn test_write_net1_rq() {
    let rs = include_bin!("packets/net1-rq.bin");
    let mut r = io::BufReader::new(rs);
    let m = r.read_dns_message().ok().unwrap();
    write_test(&m, rs);
}

#[test]
fn test_parse_net1_rs() {
    let rs = include_bin!("packets/net1-rs.bin");
    let mut r = io::BufReader::new(rs);
    let m = r.read_dns_message().ok().unwrap();

    assert_eq!(m.id, 0xe1c9);
    check_std_response_norecurse(&m, 1, 0, 13, 15);
    let q = m.questions[0].clone();
    assert_eq!(format!("{}",q.qname).as_slice(), "net.");
    let mut a_ct: uint = 0;
    for a in m.nameservers.iter() {
        let n = Name::parse_decompressed(a.rdata.as_slice()).ok().unwrap();
        if format!("{}",n).as_slice() == "a.gtld-servers.net." { a_ct += 1; }
        if format!("{}",n).as_slice() == "b.gtld-servers.net." { a_ct += 1; }
        if format!("{}",n).as_slice() == "c.gtld-servers.net." { a_ct += 1; }
        if format!("{}",n).as_slice() == "d.gtld-servers.net." { a_ct += 1; }
        if format!("{}",n).as_slice() == "e.gtld-servers.net." { a_ct += 1; }
        if format!("{}",n).as_slice() == "f.gtld-servers.net." { a_ct += 1; }
        if format!("{}",n).as_slice() == "g.gtld-servers.net." { a_ct += 1; }
        if format!("{}",n).as_slice() == "h.gtld-servers.net." { a_ct += 1; }
        if format!("{}",n).as_slice() == "i.gtld-servers.net." { a_ct += 1; }
        if format!("{}",n).as_slice() == "j.gtld-servers.net." { a_ct += 1; }
        if format!("{}",n).as_slice() == "k.gtld-servers.net." { a_ct += 1; }
        if format!("{}",n).as_slice() == "l.gtld-servers.net." { a_ct += 1; }
        if format!("{}",n).as_slice() == "m.gtld-servers.net." { a_ct += 1; }
    }
    assert_eq!(a_ct, 13);
}

#[test]
fn test_write_net1_rs() {
    let rs = include_bin!("packets/net1-rs.bin");
    let mut r = io::BufReader::new(rs);
    let m = r.read_dns_message().ok().unwrap();
    write_test(&m, rs);
}
