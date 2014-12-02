use std::rand;

mod rrtype;

#[repr(u16)]
#[deriving(PartialEq,Show)]
pub enum RRType {
    A       =   1u16,
    NS      =   2u16,
    CNAME   =   5u16,
    SOA     =   6u16,
    WKS     =   11u16,
    PTR     =   12u16,
    HINFO   =   13u16,
    MINFO   =   14u16,
    MX      =   15u16,
    TXT     =   16u16,
    RP      =   17u16,
    AFSDB   =   18u16,
    SIG     =   24u16,
    KEY     =   25u16,
    AAAA    =   28u16,
    LOC     =   29u16,
    SRV     =   33u16,
    NAPTR   =   35u16,
    KX      =   36u16,
    CERT    =   37u16,
    DNAME   =   39u16,
    APL     =   42u16,
    DS      =   43u16,
    SSHFP   =   44u16,
    IPSECKEY=   45u16,
    RRSIG   =   46u16,
    NSEC    =   47u16,
    DNSKEY  =   48u16,
    DHCID   =   49u16,
    NSEC3   =   50u16,
    NSEC3PARAM  =   51u16,
    TLSA    =   52u16,
    HIP     =   55u16,
    CDS     =   59u16,
    CDNSKEY =   60u16,
    SPF     =   99u16,
    TKEY    =   249u16,
    TSIG    =   250u16,
    CAA     =   257u16,
    TA      =   32768u16,
    DLV     =   32769u16,
    RESERVED=   0u16,
}

impl RRType {
    /// Convert a `u16` integer to a `RRType` record. Undefined values are
    /// mapped to `RRType::RESERVED`.
    pub fn from_u16(u16val: u16) -> RRType {
        match u16val {
            1u16 => RRType::A,
            2u16 => RRType::NS,
            5u16 => RRType::CNAME,
            6u16 => RRType::SOA,
            11u16 => RRType::WKS,
            12u16 => RRType::PTR,
            13u16 => RRType::HINFO,
            14u16 => RRType::MINFO,
            15u16 => RRType::MX,
            16u16 => RRType::TXT,
            17u16 => RRType::RP,
            18u16 => RRType::AFSDB,
            24u16 => RRType::SIG,
            25u16 => RRType::KEY,
            28u16 => RRType::AAAA,
            29u16 => RRType::LOC,
            33u16 => RRType::SRV,
            35u16 => RRType::NAPTR,
            36u16 => RRType::KX,
            37u16 => RRType::CERT,
            39u16 => RRType::DNAME,
            42u16 => RRType::APL,
            43u16 => RRType::DS,
            44u16 => RRType::SSHFP,
            45u16 => RRType::IPSECKEY,
            46u16 => RRType::RRSIG,
            47u16 => RRType::NSEC,
            48u16 => RRType::DNSKEY,
            49u16 => RRType::DHCID,
            50u16 => RRType::NSEC3,
            51u16 => RRType::NSEC3PARAM,
            52u16 => RRType::TLSA,
            55u16 => RRType::HIP,
            59u16 => RRType::CDS,
            60u16 => RRType::CDNSKEY,
            99u16 => RRType::SPF,
            249u16 => RRType::TKEY,
            250u16 => RRType::TSIG,
            257u16 => RRType::CAA,
            32768u16 => RRType::TA,
            32769u16 => RRType::DLV,
            _ => RRType::RESERVED,
        }
    }
    pub fn to_u16(rrtype: RRType) -> u16 {
        rrtype as u16
    }
}

#[repr(u16)]
#[deriving(PartialEq,Show)]
pub enum RRClass {
	IN = 1,
	CH = 3,
	HS = 4,
	NONE = 254,
	ANY = 255,
	RESERVED = 0,
}

impl RRClass {
	pub fn from_u16(u16val: u16) -> RRClass {
		match u16val {
			1 => RRClass::IN,
			3 => RRClass::CH,
			4 => RRClass::HS,
			254 => RRClass::NONE,
			255 => RRClass::ANY,
			_ => RRClass::RESERVED,
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

#[allow(unused_variables)]
#[allow(dead_code)]
#[cfg(test)]
mod test {
    use super::RRType;
	use super::TTL;
    use super::RRClass;
    
    /// Quick and dirty u16 match checking.
    #[test]
    fn test_rrtype_value() {
        let qt = RRType::A;
        match qt as u16 {
            1 =>    assert!(true),
            _ =>    assert!(false),
        };
    }

    /// Test that defined `QTYPE`s have corresponding variants, and check
    /// that defined `QTYPE` variants translate to/from their u16 values.
    /// Also checks that undefined `QTYPE`s are mapped to `RESERVED`.
    #[test]
    fn test_rrtype_identity() {
        let defined_rrtypes = [
            1u16,
            2u16,
            5u16,
            6u16,
            11u16,
            12u16,
            13u16,
            14u16,
            15u16,
            16u16,
            17u16,
            18u16,
            24u16,
            25u16,
            28u16,
            29u16,
            33u16,
            35u16,
            36u16,
            37u16,
            39u16,
            42u16,
            43u16,
            44u16,
            45u16,
            46u16,
            47u16,
            48u16,
            49u16,
            50u16,
            51u16,
            52u16,
            55u16,
            59u16,
            60u16,
            99u16,
            249u16,
            250u16,
            257u16,
            32768u16,
            32769u16,
        ];

        // Fuzz all 65536 values possible for QTYPE
        'rng: for val_u in range(0, 65536u) {
            let val: u16 = val_u as u16;
            'defs: for &defval in defined_rrtypes.iter() {
                // Do some checks on defined QTYPEs
                if defval == val {
                    // Make sure it doesn't translate to reserved
                    assert!(RRType::RESERVED != RRType::from_u16(val));

                    // Make sure converstion from-to-from u16
                    // has the same result.
                    let from_u16 = RRType::from_u16(val);
                    let to_u16 = from_u16 as u16;
                    assert!(from_u16 == RRType::from_u16(to_u16));
                    assert!(to_u16 == RRType::to_u16(from_u16));

                    // If we're good, we can stop checking
                    // the defined QTYPEs list and go to the
                    // next value.
                    continue 'rng;
                }
            }
            // Check everything else is reserved
            assert!(RRType::RESERVED == RRType::from_u16(val));
        }
    }

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
                    assert!(RRClass::RESERVED != RRClass::from_u16(val));

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
            assert!(RRClass::RESERVED == RRClass::from_u16(val));
        }
    }

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