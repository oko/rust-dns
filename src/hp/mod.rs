pub use super::number::types::Type;
pub use super::number::classes::Class;
pub use super::number::rcodes::RCode;
pub use super::number::opcodes::OpCode;
pub use super::number::errors::IdentifierError;

use std::io;
use std::str;
use std::fmt;

use self::util::{_read_be_u16,_read_be_i32};

mod util;

#[deriving(PartialEq,Show,Clone)]
pub struct Message<'n> {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question<'n>>,
    pub answers: Vec<ResourceRecord<'n>>,
    pub nameservers: Vec<ResourceRecord<'n>>,
    pub additionals: Vec<ResourceRecord<'n>>,
}

#[deriving(PartialEq,Show,Clone)]
pub struct Question<'n> {
    pub qname: Name<'n>,
    pub qtype: Type,
    pub qclass: Class,
}

#[deriving(PartialEq,Show,Clone)]
pub struct ResourceRecord<'n> {
    pub rname: Name<'n>,
    pub rtype: Type,
    pub rclass: Class,
    pub rttl: i32,
    pub rdlen: u16,
    pub rdata: uint,
    pub context: &'n [u8],
}

#[deriving(PartialEq,Eq,Hash,Clone)]
pub struct Name<'n> {
    labels: Vec<&'n str>,
}
impl<'n> Name<'n> {
    #[inline]
    pub fn to_string(&self) -> String {
        format!("{}.", self.labels.connect("."))
    }
    pub fn from_rdata<'r>(rr: &'r ResourceRecord) -> io::IoResult<Name<'r>> {
        let mut i = rr.rdata;
        read_dns_name(rr.context, &mut i)
    }
}
impl<'n> fmt::Show for Name<'n> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

pub fn read_dns_message<'b>(buf: &'b [u8]) -> io::IoResult<Message<'b>> {
    if buf.len() < 12 { return Err(io::standard_error(io::InvalidInput)); }
    let mut i = 0u;
    let id = _read_be_u16(buf, &mut i);
    let flags = _read_be_u16(buf, &mut i);
    let qdcount = _read_be_u16(buf, &mut i);
    let ancount = _read_be_u16(buf, &mut i);
    let nscount = _read_be_u16(buf, &mut i);
    let adcount = _read_be_u16(buf, &mut i);
    
    let mut msg = Message {
        id: id,
        flags: flags,
        questions: Vec::new(),
        answers: Vec::new(),
        nameservers: Vec::new(),
        additionals: Vec::new(),
    };


    for n in range(0, qdcount) { msg.questions.push(try!(read_dns_question(buf, &mut i))) }
    for n in range(0, ancount) { msg.answers.push(try!(read_dns_resource_record(buf, &mut i))) }
    for n in range(0, nscount) { msg.nameservers.push(try!(read_dns_resource_record(buf, &mut i))) }
    for n in range(0, adcount) { msg.additionals.push(try!(read_dns_resource_record(buf, &mut i))) }

    
    Ok(msg)
}

fn read_dns_question<'b>(buf: &'b [u8], idx: &mut uint) -> io::IoResult<Question<'b>> {
    let q = Question {
        qname: try!(read_dns_name(buf, idx)),
        qtype: match Type::from_u16(_read_be_u16(buf, idx)) {
            Ok(val) => val,
            Err(_) => return Err(io::standard_error(io::InvalidInput)),
        },
        qclass: match Class::from_u16(_read_be_u16(buf, idx)) {
            Ok(val) => val,
            Err(_) => return Err(io::standard_error(io::InvalidInput)),
        },
    };
    Ok(q)
}

fn read_dns_resource_record<'b>(buf: &'b [u8], idx: &mut uint) -> io::IoResult<ResourceRecord<'b>> {
    let mut r = ResourceRecord {
        rname: try!(read_dns_name(buf, idx)),
        rtype: match Type::from_u16(_read_be_u16(buf, idx)) {
            Ok(val) => val,
            Err(_) => return Err(io::standard_error(io::InvalidInput)),
        },
        rclass: match Class::from_u16(_read_be_u16(buf, idx)) {
            Ok(val) => val,
            Err(_) => return Err(io::standard_error(io::InvalidInput)),
        },
        rttl: _read_be_i32(buf, idx),
        rdlen: _read_be_u16(buf, idx),
        rdata: *idx,
        context: buf,
    };
    *idx += (r.rdlen as uint);
    Ok(r)
}

fn read_dns_name<'b>(buf: &'b [u8], idx: &mut uint) -> io::IoResult<Name<'b>> {

    let mut labels: Vec<&str> = Vec::with_capacity(8);

    let mut follow = false;
    let mut return_to = 0u;
    // Read in labels
    loop {
        // Get the next label's size
        let llen = buf[*idx];

        if llen == 0 {
            // Zero length labels are the root, so we're done

            break;
        } else if (llen & 0xC0) == 0xC0 {
            // Labels with the two high order bits set (0xC0)
            // are pointers.

            // If this is the first pointer encountered, store
            // the current reader location to restore later.
            if !follow {
                return_to = *idx+2;
                follow = true;
            }

            // Seek to the pointer location
            *idx = buf[*idx+1] as uint;
            continue;
        } else {
            let offset = 1 + (llen as uint);
            let str_read = str::from_utf8(buf[*idx+1..*idx+offset]);
            *idx += offset;
            match str_read {
                Some(s) => {
                    labels.push(s);
                },
                None => return Err(io::standard_error(io::InvalidInput)),
            }
        }
    }

    if follow {
        // Restore the reader location to the byte after the first
        // pointer followed during the read.
        *idx = return_to;
    } else {
        // Or just push the index up by one if we aren't reading.
        *idx += 1;
    }

    Ok(Name { labels: labels })
}

#[cfg(test)]
mod test_hp {
    
    use super::read_dns_message;
    use super::Message;
    use super::Name;
    static NET1_RS: &'static [u8] = include_bin!("../../tests/packets/net1-rs.bin");

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
}