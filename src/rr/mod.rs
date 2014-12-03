//! Resource record handling module.

use std::rand;

mod rrtypes;

#[repr(u16)]
#[deriving(PartialEq,Show)]
pub enum RRType {
    A           = 1,
    NS          = 2,
    CNAME       = 5,
    SOA         = 6,
    WKS         = 11,
    PTR         = 12,
    HINFO       = 13,
    MINFO       = 14,
    MX          = 15,
    TXT         = 16,
    RP          = 17,
    AFSDB       = 18,
    X25         = 19,
    ISDN        = 20,
    RT          = 21,
    NSAP        = 22,
    NSAPPTR     = 23,
    SIG         = 24,
    KEY         = 25,
    PX          = 26,
    GPOS        = 27,
    AAAA        = 28,
    LOC         = 29,
    EID         = 31,
    NIMLOC      = 32,
    SRV         = 33,
    ATMA        = 34,
    NAPTR       = 35,
    KX          = 36,
    CERT        = 37,
    DNAME       = 39,
    SINK        = 40,
    OPT         = 41,
    APL         = 42,
    DS          = 43,
    SSHFP       = 44,
    IPSECKEY    = 45,
    RRSIG       = 46,
    NSEC        = 47,
    DNSKEY      = 48,
    DHCID       = 49,
    NSEC3       = 50,
    NSEC3PARAM  = 51,
    TLSA        = 52,
    HIP         = 55,
    NINFO       = 56,
    RKEY        = 57,
    TALINK      = 58,
    CDS         = 59,
    CDNSKEY     = 60,
    OPENPGPKEY  = 61,
    SPF         = 99,
    UINFO       = 100,
    UID         = 101,
    GID         = 102,
    UNSPEC      = 103,
    NID         = 104,
    L32         = 105,
    L64         = 106,
    LP          = 107,
    EUI48       = 108,
    EUI64       = 109,
    TKEY        = 249,
    TSIG        = 250,
    IXFR        = 251,
    AXFR        = 252,
    MAILB       = 253,
    STAR        = 255,
    URI         = 256,
    CAA         = 257,
    TA          = 32768,
    DLV         = 32769,
    Reserved    = 65535,
}

impl RRType {
    /// Convert a `u16` integer to a `RRType` record. Undefined values are
    /// mapped to `RRType::RESERVED`.
	pub fn from_u16(val: u16) -> RRType {
	    match val {
	        1      => RRType::A,
	        2      => RRType::NS,
	        5      => RRType::CNAME,
	        6      => RRType::SOA,
	        11     => RRType::WKS,
	        12     => RRType::PTR,
	        13     => RRType::HINFO,
	        14     => RRType::MINFO,
	        15     => RRType::MX,
	        16     => RRType::TXT,
	        17     => RRType::RP,
	        18     => RRType::AFSDB,
	        19     => RRType::X25,
	        20     => RRType::ISDN,
	        21     => RRType::RT,
	        22     => RRType::NSAP,
	        23     => RRType::NSAPPTR,
	        24     => RRType::SIG,
	        25     => RRType::KEY,
	        26     => RRType::PX,
	        27     => RRType::GPOS,
	        28     => RRType::AAAA,
	        29     => RRType::LOC,
	        31     => RRType::EID,
	        32     => RRType::NIMLOC,
	        33     => RRType::SRV,
	        34     => RRType::ATMA,
	        35     => RRType::NAPTR,
	        36     => RRType::KX,
	        37     => RRType::CERT,
	        39     => RRType::DNAME,
	        40     => RRType::SINK,
	        41     => RRType::OPT,
	        42     => RRType::APL,
	        43     => RRType::DS,
	        44     => RRType::SSHFP,
	        45     => RRType::IPSECKEY,
	        46     => RRType::RRSIG,
	        47     => RRType::NSEC,
	        48     => RRType::DNSKEY,
	        49     => RRType::DHCID,
	        50     => RRType::NSEC3,
	        51     => RRType::NSEC3PARAM,
	        52     => RRType::TLSA,
	        55     => RRType::HIP,
	        56     => RRType::NINFO,
	        57     => RRType::RKEY,
	        58     => RRType::TALINK,
	        59     => RRType::CDS,
	        60     => RRType::CDNSKEY,
	        61     => RRType::OPENPGPKEY,
	        99     => RRType::SPF,
	        100    => RRType::UINFO,
	        101    => RRType::UID,
	        102    => RRType::GID,
	        103    => RRType::UNSPEC,
	        104    => RRType::NID,
	        105    => RRType::L32,
	        106    => RRType::L64,
	        107    => RRType::LP,
	        108    => RRType::EUI48,
	        109    => RRType::EUI64,
	        249    => RRType::TKEY,
	        250    => RRType::TSIG,
	        251    => RRType::IXFR,
	        252    => RRType::AXFR,
	        253    => RRType::MAILB,
	        255    => RRType::STAR,
	        256    => RRType::URI,
	        257    => RRType::CAA,
	        32768  => RRType::TA,
	        32769  => RRType::DLV,
	        65535  => RRType::Reserved,
	        _ => RRType::Reserved,
	    }
	}
    pub fn to_u16(rrtype: RRType) -> u16 {
        rrtype as u16
    }
    pub fn from_str(val: &str) -> RRType {
	    match val {
	        "A"          => RRType::A,
	        "NS"         => RRType::NS,
	        "CNAME"      => RRType::CNAME,
	        "SOA"        => RRType::SOA,
	        "WKS"        => RRType::WKS,
	        "PTR"        => RRType::PTR,
	        "HINFO"      => RRType::HINFO,
	        "MINFO"      => RRType::MINFO,
	        "MX"         => RRType::MX,
	        "TXT"        => RRType::TXT,
	        "RP"         => RRType::RP,
	        "AFSDB"      => RRType::AFSDB,
	        "X25"        => RRType::X25,
	        "ISDN"       => RRType::ISDN,
	        "RT"         => RRType::RT,
	        "NSAP"       => RRType::NSAP,
	        "NSAPPTR"    => RRType::NSAPPTR,
	        "SIG"        => RRType::SIG,
	        "KEY"        => RRType::KEY,
	        "PX"         => RRType::PX,
	        "GPOS"       => RRType::GPOS,
	        "AAAA"       => RRType::AAAA,
	        "LOC"        => RRType::LOC,
	        "EID"        => RRType::EID,
	        "NIMLOC"     => RRType::NIMLOC,
	        "SRV"        => RRType::SRV,
	        "ATMA"       => RRType::ATMA,
	        "NAPTR"      => RRType::NAPTR,
	        "KX"         => RRType::KX,
	        "CERT"       => RRType::CERT,
	        "DNAME"      => RRType::DNAME,
	        "SINK"       => RRType::SINK,
	        "OPT"        => RRType::OPT,
	        "APL"        => RRType::APL,
	        "DS"         => RRType::DS,
	        "SSHFP"      => RRType::SSHFP,
	        "IPSECKEY"   => RRType::IPSECKEY,
	        "RRSIG"      => RRType::RRSIG,
	        "NSEC"       => RRType::NSEC,
	        "DNSKEY"     => RRType::DNSKEY,
	        "DHCID"      => RRType::DHCID,
	        "NSEC3"      => RRType::NSEC3,
	        "NSEC3PARAM" => RRType::NSEC3PARAM,
	        "TLSA"       => RRType::TLSA,
	        "HIP"        => RRType::HIP,
	        "NINFO"      => RRType::NINFO,
	        "RKEY"       => RRType::RKEY,
	        "TALINK"     => RRType::TALINK,
	        "CDS"        => RRType::CDS,
	        "CDNSKEY"    => RRType::CDNSKEY,
	        "OPENPGPKEY" => RRType::OPENPGPKEY,
	        "SPF"        => RRType::SPF,
	        "UINFO"      => RRType::UINFO,
	        "UID"        => RRType::UID,
	        "GID"        => RRType::GID,
	        "UNSPEC"     => RRType::UNSPEC,
	        "NID"        => RRType::NID,
	        "L32"        => RRType::L32,
	        "L64"        => RRType::L64,
	        "LP"         => RRType::LP,
	        "EUI48"      => RRType::EUI48,
	        "EUI64"      => RRType::EUI64,
	        "TKEY"       => RRType::TKEY,
	        "TSIG"       => RRType::TSIG,
	        "IXFR"       => RRType::IXFR,
	        "AXFR"       => RRType::AXFR,
	        "MAILB"      => RRType::MAILB,
	        "STAR"       => RRType::STAR,
	        "URI"        => RRType::URI,
	        "CAA"        => RRType::CAA,
	        "TA"         => RRType::TA,
	        "DLV"        => RRType::DLV,
	        "Reserved"   => RRType::Reserved,
	        _ => RRType::Reserved,
	    }
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
#[cfg(test)]
mod test_rrtype {
    use super::RRType;
    
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
							    19u16,
							    20u16,
							    21u16,
							    22u16,
							    23u16,
							    24u16,
							    25u16,
							    26u16,
							    27u16,
							    28u16,
							    29u16,
							    31u16,
							    32u16,
							    33u16,
							    34u16,
							    35u16,
							    36u16,
							    37u16,
							    39u16,
							    40u16,
							    41u16,
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
							    56u16,
							    57u16,
							    58u16,
							    59u16,
							    60u16,
							    61u16,
							    99u16,
							    100u16,
							    101u16,
							    102u16,
							    103u16,
							    104u16,
							    105u16,
							    106u16,
							    107u16,
							    108u16,
							    109u16,
							    249u16,
							    250u16,
							    251u16,
							    252u16,
							    253u16,
							    255u16,
							    256u16,
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
                    assert!(RRType::Reserved != RRType::from_u16(val));

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
            assert!(RRType::Reserved == RRType::from_u16(val));
        }
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