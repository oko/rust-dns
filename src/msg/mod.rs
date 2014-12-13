pub use super::number::types::Type;
pub use super::number::classes::Class;
pub use super::number::rcodes::RCode;
pub use super::number::opcodes::OpCode;
pub use super::number::errors::IdentifierError;
pub use super::name::Name;

use self::record::{Question,ResourceRecord};

mod record;

pub struct Message {
    id: u16,
    flags: u16,
    questions: Vec<Question>,
    answers: Vec<ResourceRecord>,
    nameservers: Vec<ResourceRecord>,
    additionals: Vec<ResourceRecord>,
}

static HFLAG_MASK_QR: u16 = 0x8000;
static HFLAG_MASK_AA: u16 = 0x0400;
static HFLAG_MASK_TC: u16 = 0x0200;
static HFLAG_MASK_RD: u16 = 0x0100;
static HFLAG_MASK_RA: u16 = 0x0080;
static HFLAG_MASK_OPCODE: u16 = 0x7800;
static HFLAG_MASK_Z: u16 = 0x0040;
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
}

#[cfg(test)]
mod test_message {
    use super::{Message,OpCode,RCode};
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
}