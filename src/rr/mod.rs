//! Resource record handling module.

use std::rand;
pub use self::rrtype::RRType;
pub use self::rrclass::RRClass;

mod name;
mod rrclass;
mod rrtype;
mod rrtypes;

trait RData {
    fn to_rdata(&self) -> Vec<u8>;
    fn from_rdata(&mut [u8], _ignored: Option<Self>) -> Result<Self, &'static str>;
}

pub struct RR<T> {
    pub name: Vec<String>,
    pub rrtype: RRType,
    pub rrclass: RRClass,
    pub ttl: TTL,
    pub rdata: Vec<u8>,
}

pub struct TTL(i32);

impl TTL {
	/// Generate a TTL of one-half hour (30 minutes).
	pub fn half_hour() -> TTL {
		TTL(1800)
	}
	/// Generate a TTL of one (1) hour.
	pub fn one_hour() -> TTL {
		TTL(3600)
	}
	/// Generate a TTL of one (1) day.
	pub fn one_day() -> TTL {
		TTL(3600*24)
	}
	/// Generate a TTL of one (1) week.
	pub fn one_week() -> TTL {
		TTL(3600*24*7)
	}
	/// Generate a TTL of one (1) month (30 days).
	pub fn one_month() -> TTL {
		TTL(3600*24*30)
	}
	// Add an offset of *t* seconds where 0 < *t* <= 60
	// to a TTL.
	pub fn random_offset(ttl: TTL) -> TTL {
		let TTL(ival) = ttl;
		let shift = if ival > 30 {
			30
		} else {
			0
		};
		TTL(ival - shift + (
			(rand::random::<u16>() % 60) as i32
			) + 1)
	}
}

#[cfg(test)]
mod test_ttl {
	use super::TTL;

    #[test]
    fn test_ttl_value() {
    	let ttl = TTL(600i32);
    	let TTL(ival) = ttl;
    	assert_eq!(ival, 600i32);
    }

    #[test]
    fn test_ttl_generators() {
    	let TTL(half_hour) = TTL::half_hour();
    	assert_eq!(half_hour, 1800i32);
    	let TTL(one_hour) = TTL::one_hour();
    	assert_eq!(one_hour, 3600i32);
    	let TTL(one_day) = TTL::one_day();
    	assert_eq!(one_day, 3600i32 * 24i32);
    	let TTL(one_week) = TTL::one_week();
    	assert_eq!(one_week, 3600i32 * 24i32 * 7i32);
    	let TTL(one_month) = TTL::one_month();
    	assert_eq!(one_month, 3600i32 * 24i32 * 30i32);
    }

    #[test]
    fn test_ttl_randomize() {
    	for ignore in range(0u, 1000) {
	    	let TTL(ival) = TTL::random_offset(TTL(600));
	    	assert!(570i32 < ival && ival <= 630i32, "ERR{}", ival);
	    }
	}
}