//! Resource record handling module.

use std::rand;
pub use self::rrtype::RRType;

mod rrtype;
mod rrtypes;

pub struct RR {
    pub name: Vec<String>,
    pub rrtype: RRType,
    pub rrclass: RRClass,
    pub ttl: TTL,
    pub rdata: Vec<u8>,
}

impl RR {
}

#[repr(u16)]
#[deriving(PartialEq,Show)]
pub enum RRClass {
	IN = 1,
	CH = 3,
	HS = 4,
	NONE = 254,
	ANY = 255,
	Reserved = 0,
}

impl RRClass {
	pub fn from_u16(u16val: u16) -> RRClass {
		match u16val {
			1 => RRClass::IN,
			3 => RRClass::CH,
			4 => RRClass::HS,
			254 => RRClass::NONE,
			255 => RRClass::ANY,
			_ => RRClass::Reserved,
		}
	}

	pub fn to_u16(class: RRClass) -> u16 {
		class as u16
	}
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
mod test_rrclass {
    use super::RRClass;

    #[test]
    fn test_rrclass_value() {
    	let rrc = RRClass::IN;
    	match rrc as u16 {
    		1 => assert!(true),
    		_ => assert!(false),
    	}
    }
    #[test]
    fn test_rrclass_identity() {
        let defined_rrtypes = [
            1u16,
            3u16,
            4u16,
            254u16,
            255u16,
        ];

        // Fuzz all 65536 values possible for QTYPE
        'rng: for val_u in range(0, 65536u) {
            let val: u16 = val_u as u16;
            'defs: for &defval in defined_rrtypes.iter() {
                // Do some checks on defined QTYPEs
                if defval == val {
                    // Make sure it doesn't translate to reserved
                    assert!(RRClass::Reserved != RRClass::from_u16(val));

                    // Make sure converstion from-to-from u16
                    // has the same result.
                    let from_u16 = RRClass::from_u16(val);
                    let to_u16 = from_u16 as u16;
                    assert!(from_u16 == RRClass::from_u16(to_u16));
                    assert!(to_u16 == RRClass::to_u16(from_u16));

                    // If we're good, we can stop checking
                    // the defined QTYPEs list and go to the
                    // next value.
                    continue 'rng;
                }
            }
            // Check everything else is reserved
            assert!(RRClass::Reserved == RRClass::from_u16(val));
        }
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