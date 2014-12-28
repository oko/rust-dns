use super::{read_dns_message,read_dns_question,read_dns_resource_record,read_dns_name};
use super::{Message,Name,Label};

use std::str;
static NET1_RS: &'static [u8] = include_bin!("../../tests/packets/net1-rs.bin");

fn check_std_response_norecurse(m: &Message, q: uint, a: uint, n: uint, x: uint) {
    assert_eq!(m.flags, 0x8000);
    assert_eq!(m.questions.len(), q);
    assert_eq!(m.answers.len(), a);
    assert_eq!(m.nameservers.len(), n);
    assert_eq!(m.additionals.len(), x);
}

#[test]
fn test_label_create() {
    // Maximum label length is 63 octets
    let l63 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_bytes();
    let l64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_bytes();
    let l0 = "".as_bytes();
    assert!(Label::from_slice(l63).is_ok());
    assert!(Label::from_slice(l64).is_err());
}

#[test]
fn test_label_eq() {
    let l1 = Label::from_slice("cat".as_bytes()).ok().unwrap();
    let l2 = Label::from_slice("Cat".as_bytes()).ok().unwrap();
    let l3 = Label::from_slice("CAT".as_bytes()).ok().unwrap();
    let l4 = Label::from_slice("cat1".as_bytes()).ok().unwrap();
    let l5 = Label::from_slice("cat2".as_bytes()).ok().unwrap();
    let l6 = Label::from_slice("Cat1".as_bytes()).ok().unwrap();
    
    // Case insensitivity tests
    assert_eq!(l1, l2);
    assert_eq!(l2, l3);
    assert_eq!(l1, l3);
    assert_eq!(l4, l6);

    // Basic inequality tests
    assert!(l4 != l5);
    assert!(l5 != l6);

    let mut b1 = [0x63u8, 0x61, 0x74, 0x31];
    let mut b2 = [0x63u8, 0x61, 0x74, 0x31];
    for i in range(0, 256u) {
        let x = i as u8;
        let y = if x > 0 { x - 1 } else { 255 };
        b1[3] = x;
        b2[3] = y;
        assert!(Label::from_slice(&b1) != Label::from_slice(&b2));
        b2[3] = x;
        assert!(Label::from_slice(&b1) == Label::from_slice(&b2));
    }
}
#[test]
fn test_label_ord() {
    let l = Label::from_slice("CAt".as_bytes()).ok().unwrap();
    let l0 = Label::from_slice("Cat".as_bytes()).ok().unwrap();
    let l1 = Label::from_slice("Cat1".as_bytes()).ok().unwrap();
    let l2 = Label::from_slice("cat1".as_bytes()).ok().unwrap();
    let l3 = Label::from_slice("cat2".as_bytes()).ok().unwrap();

    // Test ordering (DNSSEC canonical)
    assert!(l < l0);
    assert!(l0 < l1);
    assert!(l1 < l2);
    assert!(l2 < l3);
    assert!(l1 < l3);

    let mut b1 = [0x63u8, 0x61, 0x74, 0x00];
    let mut b2 = [0x63u8, 0x61, 0x74, 0x01];
    let mut b3 = [0x63u8, 0x61, 0x74, 0x02];
    let l1 = Label::from_slice(&b1).ok().unwrap();
    let l2 = Label::from_slice(&b2).ok().unwrap();
    let l3 = Label::from_slice(&b3).ok().unwrap();

    // Test ordering (DNSSEC canonical)
    assert!(l1 < l2);
    assert!(l2 < l3);
    assert!(l1 < l3);
}

#[test]
fn test_name_ord() {
    // ---> Begin RFC4034 testcases
    let n1 = "\x07axample\x00".as_bytes();
    let n2 = "\x07EXAMPLE\x00".as_bytes();
    let n3 = "\x01a\x07example\x00".as_bytes();
    let n4 = "\x08yljkjljk\x01a\x07example\x00".as_bytes();
    let n5 = "\x01Z\x01a\x07example\x00".as_bytes();
    let n6 = "\x04zABC\x01a\x07example\x00".as_bytes();
    let n7 = "\x01z\x07example\x00".as_bytes();
    let n8 = "\x01\x01\x01z\x07example\x00".as_bytes();
    let n9 = "\x01*\x01z\x07example\x00".as_bytes();
    let v = vec!(n1, n2, n3, n4, n5, n6, n7, n8, n9);
    let mut v2 = v.iter().map( |x| -> Name {
        read_dns_name(*x, &mut 0).ok().unwrap()
    }
    );
    let mut this = v2.next().unwrap();
    let mut that = v2.next().unwrap();
    while let Some(next) = v2.next() {
        this = that;
        that = next;
        assert!(this < that);
    }
    let n1 = "\x01*\x01z\x07example\x00".as_bytes();
    let n2 = "\x01\x01\x01z\x07example\x00".as_bytes();
    let n3 = "\x01z\x07example\x00".as_bytes();
    let n4 = "\x04zABC\x01a\x07example\x00".as_bytes();
    let n5 = "\x01Z\x01a\x07example\x00".as_bytes();
    let n6 = "\x08yljkjljk\x01a\x07example\x00".as_bytes();
    let n7 = "\x01a\x07example\x00".as_bytes();
    let n8 = "\x07EXAMPLE\x00".as_bytes();
    let n9 = "\x07axample\x00".as_bytes();
    let v = vec!(n1, n2, n3, n4, n5, n6, n7, n8, n9);
    let mut v2 = v.iter().map( |x| -> Name {
        read_dns_name(*x, &mut 0).ok().unwrap()
    }
    );
    let mut this = v2.next().unwrap();
    let mut that = v2.next().unwrap();
    while let Some(next) = v2.next() {
        this = that;
        that = next;
        assert!(this > that);
    }
    // <--- End RFC4034 testcases

    let mut v3 = vec!(
        "\x01A\x00".as_bytes(),
        "\x01a\x00".as_bytes(),
        "\x01b\x00".as_bytes(),
        "\x01c\x00".as_bytes(),
        "\x01d\x00".as_bytes(),
        "\x01c\x01d\x00".as_bytes(),
        "\x01B\x01c\x01d\x00".as_bytes(),
        "\x01b\x01C\x01d\x00".as_bytes(),
        "\x01b\x01c\x01d\x00".as_bytes(),
        "\x01\x10\x01b\x01c\x01d\x00".as_bytes(),
        "\x01\x11\x01b\x01c\x01d\x00".as_bytes(),
        "\x01\x12\x01b\x01c\x01d\x00".as_bytes(),
        "\x01\x13\x01b\x01c\x01d\x00".as_bytes(),
        "\x01\x14\x01b\x01c\x01d\x00".as_bytes(),
        );
    let mut v4 = v3.iter().map( |x| -> Name {
        //println!("{}", read_dns_name(*x, &mut 0));
        read_dns_name(*x, &mut 0).ok().unwrap()
    }
    );
    let mut this = v4.next().unwrap();
    let mut that = v4.next().unwrap();
    assert!(this < that);
    while let Some(next) = v4.next() {
        this = that;
        that = next;
        assert!(this < that);
    }

    let mut v5 = vec!(
        "\x01\x14\x01b\x01c\x01d\x00".as_bytes(),
        "\x01\x13\x01b\x01c\x01d\x00".as_bytes(),
        "\x01\x12\x01b\x01c\x01d\x00".as_bytes(),
        "\x01\x11\x01b\x01c\x01d\x00".as_bytes(),
        "\x01\x10\x01b\x01c\x01d\x00".as_bytes(),
        "\x01b\x01c\x01d\x00".as_bytes(),
        "\x01b\x01C\x01d\x00".as_bytes(),
        "\x01B\x01c\x01d\x00".as_bytes(),
        "\x01c\x01d\x00".as_bytes(),
        "\x01d\x00".as_bytes(),
        "\x01c\x00".as_bytes(),
        "\x01b\x00".as_bytes(),
        "\x01a\x00".as_bytes(),
        "\x01A\x00".as_bytes(),
        );
    let mut v6 = v5.iter().map( |x| -> Name {
        //println!("{}", read_dns_name(*x, &mut 0));
        read_dns_name(*x, &mut 0).ok().unwrap()
    }
    );
    let mut this = v6.next().unwrap();
    let mut that = v6.next().unwrap();
    assert!(this > that);
    while let Some(next) = v6.next() {
        this = that;
        that = next;
        assert!(this > that);
    }

    read_dns_name(n1, &mut 0).ok().unwrap();
}

#[test]
fn test_read_dns_message() {
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

#[test]
fn test_bounds_checks() {
    let m = read_dns_message(NET1_RS[0..NET1_RS.len()-2]).err();
}
