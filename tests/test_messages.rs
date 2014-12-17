#![allow(dead_code)]

extern crate dns;

use dns::hp::{Message,Name,read_dns_message};

static NET1_RS: &'static [u8] = include_bin!("packets/net1-rs.bin");
static NET1_RQ: &'static [u8] = include_bin!("packets/net1-rq.bin");
static FB1_RS: &'static [u8] = include_bin!("packets/fb1-rs.bin");
static FB1_RQ: &'static [u8] = include_bin!("packets/fb1-rq.bin");
static COMNS1_RS: &'static [u8] = include_bin!("packets/comns1-rs.bin");

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
    let m = match read_dns_message(FB1_RQ) {
        Ok(x) => x,
        Err(e) => { println!("err: {}",e); panic!("FAIL"); },
    };
    assert_eq!(m.id, 0x0b8d);
    check_std_query_recursive(&m);
}
#[test]
fn test_parse_fb1_rs() {
    let m = match read_dns_message(FB1_RS) {
        Ok(x) => x,
        Err(e) => { println!("err: {}",e); panic!("FAIL"); },
    };
    assert_eq!(m.id, 0x0b8d);
    check_std_response_recursive(&m, 1, 1, 0, 0);
}

#[test]
fn test_parse_comns1_rs() {
    let m = match read_dns_message(COMNS1_RS) {
        Ok(x) => x,
        Err(e) => { println!("err: {}",e); panic!("FAIL"); },
    };
    assert_eq!(m.id, 0x363a);
    check_std_response_norecurse(&m, 1, 0, 13, 14);
    let mut a_ct: uint = 0;
    for a in m.nameservers.iter() {
        assert_eq!(a.rttl, 172800);
        
        let n = Name::from_rdata(a).ok().unwrap().to_string();
        if n.as_slice() == "a.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "b.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "c.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "d.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "e.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "f.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "g.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "h.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "i.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "j.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "k.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "l.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "m.gtld-servers.net." { a_ct += 1; }
    }
    assert_eq!(a_ct, 13);
}

#[test]
fn test_parse_net1_rq() {
    let m = match read_dns_message(NET1_RQ) {
        Ok(x) => x,
        Err(e) => { println!("err: {}",e); panic!("FAIL"); },
    };

    assert_eq!(m.id, 0xe1c9);
    check_std_query_norecurse(&m);
}

#[test]
fn test_parse_net1_rs() {
    let m = match read_dns_message(NET1_RS) {
        Ok(x) => x,
        Err(e) => { println!("err: {}",e); panic!("FAIL"); },
    };
    assert_eq!(m.id, 0xe1c9);
    assert_eq!(m.flags, 0x8000);

    let q = m.questions[0].clone();
    assert_eq!(format!("{}",q.qname).as_slice(), "net.");
    check_std_response_norecurse(&m, 1, 0, 13, 15);
    let mut a_ct: uint = 0;
    for a in m.nameservers.iter() {
        assert_eq!(a.rttl, 172800);
        
        let n = Name::from_rdata(a).ok().unwrap().to_string();
        if n.as_slice() == "a.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "b.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "c.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "d.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "e.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "f.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "g.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "h.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "i.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "j.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "k.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "l.gtld-servers.net." { a_ct += 1; }
        if n.as_slice() == "m.gtld-servers.net." { a_ct += 1; }
    }
    assert_eq!(a_ct, 13);
}