pub use super::number::types::Type;
pub use super::number::classes::Class;
pub use super::number::rcodes::RCode;
pub use super::number::opcodes::OpCode;
pub use super::number::errors::IdentifierError;
pub use super::name::{Name,DNSNameReader};
pub use super::number::DNSNumberReader;

use self::record::{Question,ResourceRecord,DNSResourceRecordReader,DNSQuestionReader};
use std::io;
use std::collections::hash_map::HashMap;

pub mod record;
pub mod recordtypes;

#[deriving(Show,Clone)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub nameservers: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

static HFLAG_MASK_QR: u16 = 0x8000;
static HFLAG_MASK_AA: u16 = 0x0400;
static HFLAG_MASK_TC: u16 = 0x0200;
static HFLAG_MASK_RD: u16 = 0x0100;
static HFLAG_MASK_RA: u16 = 0x0080;
static HFLAG_MASK_OPCODE: u16 = 0x7800;
//static HFLAG_MASK_Z: u16 = 0x0040; // Currently unused
static HFLAG_MASK_AD: u16 = 0x0020;
static HFLAG_MASK_CD: u16 = 0x0010;
static HFLAG_MASK_RCODE: u16 = 0x000F;

impl Message {
    pub fn new(
        id: u16,
        query: bool,
        opcode: OpCode,
        authoritative: bool,
        truncated: bool,
        recursion_desired: bool,
        recursion_available: bool,
        authenticated: bool,
        checking_disabled: bool,
        response_code: RCode,
        ) -> Message {
        let flags =  
          0u16 | (if query {0} else {HFLAG_MASK_QR})
               | (if authoritative {HFLAG_MASK_AA} else {0})
               | (if truncated {HFLAG_MASK_TC} else {0})
               | (if recursion_desired {HFLAG_MASK_RD} else {0})
               | (if recursion_available {HFLAG_MASK_RA} else {0})
               | ((((opcode as u8) as u16) << 11) & HFLAG_MASK_OPCODE)
               | (if authenticated {HFLAG_MASK_AD} else {0})
               | (if checking_disabled {HFLAG_MASK_CD} else {0})
               | ((response_code as u16) & HFLAG_MASK_RCODE);
        Message { id: id, flags: flags, questions: Vec::new(), answers: Vec::new(), nameservers: Vec::new(), additionals: Vec::new() } 
    }
    pub fn is_query(&self) -> bool {
        (self.flags & HFLAG_MASK_QR) == 0
    }
    pub fn is_response(&self) -> bool {
        (self.flags & HFLAG_MASK_QR) != 0
    }
    pub fn get_opcode(&self) -> Result<OpCode, IdentifierError> {
        OpCode::from_u8(((self.flags & HFLAG_MASK_OPCODE) >> 11) as u8)
    }
    pub fn is_authoritative(&self) -> bool {
        (self.flags & HFLAG_MASK_AA) != 0
    }
    pub fn is_truncated(&self) -> bool {
        (self.flags & HFLAG_MASK_TC) != 0
    }
    pub fn recursion_desired(&self) -> bool {
        (self.flags & HFLAG_MASK_RD) != 0
    }
    pub fn recursion_available(&self) -> bool {
        (self.flags & HFLAG_MASK_RA) != 0
    }
    pub fn is_authenticated(&self) -> bool {
        (self.flags & HFLAG_MASK_AD) != 0
    }
    pub fn checking_disabled(&self) -> bool {
        (self.flags & HFLAG_MASK_CD) != 0
    }
    pub fn response_code(&self) -> Result<RCode, IdentifierError> {
        RCode::from_u16(self.flags & HFLAG_MASK_RCODE)
    }
    pub fn from_buf(buf: &[u8]) -> io::IoResult<Message> {
        let mut reader = io::BufReader::new(buf);
        let mut message = Message { id: 0, flags: 0, questions: Vec::new(), answers: Vec::new(), nameservers: Vec::new(), additionals: Vec::new() };
        message.id = try!(reader.read_be_u16());
        message.flags = try!(reader.read_be_u16());

        let message_qc = try!(reader.read_be_u16());
        let message_rc = try!(reader.read_be_u16());
        let message_nc = try!(reader.read_be_u16());
        let message_ac = try!(reader.read_be_u16());

        for i in range(0, message_qc) { message.questions.push(Question::new()); }
        for i in range(0, message_rc) { message.answers.push(ResourceRecord::new()); }
        for i in range(0, message_nc) { message.nameservers.push(ResourceRecord::new()); }
        for i in range(0, message_ac) { message.additionals.push(ResourceRecord::new()); }

        drop(reader);
        Ok(message)
    }
}

pub trait DNSMessageReader {
    fn read_dns_message(&mut self) -> io::IoResult<Message>;
}
impl<'a> DNSMessageReader for io::BufReader<'a> {
    fn read_dns_message(&mut self) -> io::IoResult<Message> {
        let mut message = Message { id: 0, flags: 0, questions: Vec::new(), answers: Vec::new(), nameservers: Vec::new(), additionals: Vec::new() };
        message.id = try!(self.read_be_u16());
        message.flags = try!(self.read_be_u16());

        let message_qc = try!(self.read_be_u16());
        let message_rc = try!(self.read_be_u16());
        let message_nc = try!(self.read_be_u16());
        let message_ac = try!(self.read_be_u16());

        for i in range(0, message_qc) { message.questions.push(try!(self.read_dns_question())); }
        for i in range(0, message_rc) { message.answers.push(try!(self.read_dns_resource_record())); }
        for i in range(0, message_nc) { message.nameservers.push(try!(self.read_dns_resource_record())); }
        for i in range(0, message_ac) { message.additionals.push(try!(self.read_dns_resource_record())); }
        Ok(message)
    }
}

pub trait DNSMessageWriter {
    fn write_dns_message(&mut self, message: &Message) -> io::IoResult<u64>;
}

impl<'a> DNSMessageWriter for io::BufWriter<'a> {

    // Prototype implementation. Far too many allocations.
    // It also has bugs related to zero-length labels and the like.
    //
    // TODO: rewrite this entire sucker.
    fn write_dns_message(&mut self, message: &Message) -> io::IoResult<u64> {
        let mut pointer_map: HashMap<Name,u64> = HashMap::new();
        try!(self.write_be_u16(message.id));
        try!(self.write_be_u16(message.flags));
        try!(self.write_be_u16(message.questions.len() as u16));
        try!(self.write_be_u16(message.answers.len() as u16));
        try!(self.write_be_u16(message.nameservers.len() as u16));
        try!(self.write_be_u16(message.additionals.len() as u16));

        fn insert(w: &mut io::BufWriter, map: &mut HashMap<Name,u64>, x: &Name) -> io::IoResult<()> {
            if x.labels.len() == 0 {
                try!(w.write_u8(0));
            } else {
                let mut n = x.clone();
                loop {
                    match map.get(&n) {
                        Some(&y) => {
                            try!(w.write_u8(0xc0));
                            try!(w.write_u8(y as u8));
                            return Ok(());
                        },
                        None => {
                            if n.labels.len() > 0 { map.insert(n.clone(), try!(w.tell())); }
                            match n.reduce() {
                                Some((np, nn)) => {
                                    n = nn;
                                    try!(w.write_u8(np.len() as u8));
                                    try!(w.write_str(np.as_slice()));
                                    continue;
                                },
                                None => {
                                    try!(w.write_u8(0));
                                    break;
                                }
                            };
                            break;
                        }
                    }
                }
            }
            return Ok(());
        };

        fn write_rr(w: &mut io::BufWriter, map: &mut HashMap<Name,u64>, r: &ResourceRecord) -> io::IoResult<()> {
            try!(insert(w, map, &r.rname));
            try!(w.write_be_u16(r.rtype as u16));
            try!(w.write_be_u16(r.rclass as u16));
            try!(w.write_be_i32(r.rttl as i32));
            try!(w.write_be_u16(r.rdlen as u16));
            match r.rtype {
                Type::CNAME |
                 Type::MB |
                 Type::MD |
                 Type::MG |
                 Type::MR |
                 Type::NS |
                 Type::PTR
                 => {
                    let n = try!(Name::parse_decompressed(r.rdata.as_slice()));
                    try!(insert(w, map, &n));
                },
                _ => {
                    try!(w.write(r.rdata.as_slice()));
                },
            }
            Ok(())
        }

        for q in message.questions.iter() {
            try!(insert(self, &mut pointer_map, &q.qname));
            try!(self.write_be_u16(q.qtype as u16));
            try!(self.write_be_u16(q.qclass as u16));
        }

        for a in message.answers.iter() {
            try!(write_rr(self, &mut pointer_map, a));
        }

        for a in message.nameservers.iter() {
            try!(write_rr(self, &mut pointer_map, a));
        }

        for a in message.additionals.iter() {
            try!(write_rr(self, &mut pointer_map, a));
        }


        Ok(try!(self.tell()))
    }
}

#[cfg(test)]
mod test_message {
    use super::{DNSMessageReader,DNSMessageWriter,Message,OpCode,RCode};
    use std::io;
    #[test]
    fn test_flags_from_u16() {
        let f = Message { id: 0x1234, flags: 0x8180, questions: Vec::new(), answers: Vec::new(), nameservers: Vec::new(), additionals: Vec::new() };
        
        assert!(!f.is_query());
        assert!(f.is_response());
        assert!(f.get_opcode().ok().unwrap() == OpCode::Query);
        assert!(!f.is_authoritative());
        assert!(!f.is_truncated());
        assert!(f.recursion_desired());
        assert!(f.recursion_available());
        assert!(!f.is_authenticated());
        assert!(!f.checking_disabled());
        assert!(f.response_code().ok().unwrap() == RCode::NoError);
    }
    #[test]
    fn test_flags_to_u16() {
        let m = Message::new(0x1234, false, OpCode::Query, false, false, true, true, false, false, RCode::NoError);
        assert_eq!(m.flags, 0x8180);
    }
    #[test]
    fn test_from_to_buf() {
        let buf = [0xbu8, 0x8d, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x8, 0x66, 0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b, 0x3, 0x63, 0x6f, 0x6d
, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x3, 0x30, 0x0, 0x4, 0xad, 0xfc, 0x78, 0x6];

        let mut r = io::BufReader::new(&buf);
        let m = match r.read_dns_message() {
            Ok(msg) => msg,
            Err(e) => {
                println!("{}", e);
                return;
            }
        };
        let mut wbuf = [0u8, ..4096];
        let mut size = 0;
        {
            let mut w = io::BufWriter::new(&mut wbuf);
            size = w.write_dns_message(&m).ok().unwrap();
        }
        println!("buf sizes: {}, {}", buf.len(), size);
        println!("rbuf: {}", buf.as_slice());
        println!("wbuf: {}", wbuf.slice_to(size as uint));
        assert_eq!(buf.as_slice(), wbuf.slice_to(size as uint));
        //assert_eq!(m.flags, 0x8180);
    }
}