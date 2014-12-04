pub use super::rcode::RCode;
pub use super::opcode::OpCode;

pub struct Header {
	id: u16,
	flags: u16,
	qdcount: u16,
	ancount: u16,
	nscount: u16,
	arcount: u16,
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

impl Header {
	pub fn is_query(&self) -> bool {
		(self.flags & HFLAG_MASK_QR) == 0
	}
	pub fn is_response(&self) -> bool {
		(self.flags & HFLAG_MASK_QR) != 0
	}
	pub fn get_opcode(&self) -> OpCode {
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
	pub fn response_code(&self) -> RCode {
		RCode::from_u16(self.flags & HFLAG_MASK_RCODE)
	}
}

#[cfg(test)]
mod test_header {
	use super::{Header,OpCode,RCode};
	#[test]
	fn test_flags() {
		let h = Header {
			id: 0x1234,
			flags: 0x8180,
			qdcount: 0,
			ancount: 0,
			nscount: 0,
			arcount: 0,
		};
		
		assert!(!h.is_query());
		assert!(h.is_response());
		assert!(h.get_opcode() == OpCode::Query);
		assert!(!h.is_authoritative());
		assert!(!h.is_truncated());
		assert!(h.recursion_desired());
		assert!(h.recursion_available());
		assert!(!h.is_authenticated());
		assert!(!h.checking_disabled());
		assert!(h.response_code() == RCode::NoError);
	}
}