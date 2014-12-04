#[repr(u16)]
#[deriving(PartialEq,Show)]
pub enum RCode {
    NoError  = 0,
    FormErr  = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp   = 4,
    Refused  = 5,
    YXDomain = 6,
    YXRRSet  = 7,
    NXRRSet  = 8,
    NotAuth  = 9,
    NotZone  = 10,
    BADVERS  = 16,
    BADKEY   = 17,
    BADTIME  = 18,
    BADMODE  = 19,
    BADNAME  = 20,
    BADALG   = 21,
    BADTRUNC = 22,
    Reserved = 65535,
    
}

impl RCode {
    /// Convert a `u16` integer to a `RCode` variant. Undefined values are
    /// mapped to `RCode::Reserved`.
    pub fn from_u16(val: u16) -> RCode {
        match val {
            0     => RCode::NoError,
            1     => RCode::FormErr,
            2     => RCode::ServFail,
            3     => RCode::NXDomain,
            4     => RCode::NotImp,
            5     => RCode::Refused,
            6     => RCode::YXDomain,
            7     => RCode::YXRRSet,
            8     => RCode::NXRRSet,
            9     => RCode::NotAuth,
            10    => RCode::NotZone,
            16    => RCode::BADVERS,
            17    => RCode::BADKEY,
            18    => RCode::BADTIME,
            19    => RCode::BADMODE,
            20    => RCode::BADNAME,
            21    => RCode::BADALG,
            22    => RCode::BADTRUNC,
            65535 => RCode::Reserved,
            
            _ => RCode::Reserved,
        }
    }
    pub fn to_u16(rcode: RCode) -> u16 {
        rcode as u16
    }
    pub fn from_str(val: &str) -> RCode {
        match val {
            "NoError"  => RCode::NoError,
            "FormErr"  => RCode::FormErr,
            "ServFail" => RCode::ServFail,
            "NXDomain" => RCode::NXDomain,
            "NotImp"   => RCode::NotImp,
            "Refused"  => RCode::Refused,
            "YXDomain" => RCode::YXDomain,
            "YXRRSet"  => RCode::YXRRSet,
            "NXRRSet"  => RCode::NXRRSet,
            "NotAuth"  => RCode::NotAuth,
            "NotZone"  => RCode::NotZone,
            "BADVERS"  => RCode::BADVERS,
            "BADKEY"   => RCode::BADKEY,
            "BADTIME"  => RCode::BADTIME,
            "BADMODE"  => RCode::BADMODE,
            "BADNAME"  => RCode::BADNAME,
            "BADALG"   => RCode::BADALG,
            "BADTRUNC" => RCode::BADTRUNC,
            "Reserved" => RCode::Reserved,
            
            _ => RCode::Reserved,
        }
    }
    
    pub fn get_description(variant: RCode) -> &'static str {
        match variant {
            RCode::NoError  => "No Error",
            RCode::FormErr  => "Format Error",
            RCode::ServFail => "Server Failure",
            RCode::NXDomain => "Non-Existent Domain",
            RCode::NotImp   => "Not Implemented",
            RCode::Refused  => "Query Refused",
            RCode::YXDomain => "Name Exists when it should not",
            RCode::YXRRSet  => "RR Set Exists when it should not",
            RCode::NXRRSet  => "RR Set that should exist does not",
            RCode::NotAuth  => "Server Not Authoritative for zone",
            RCode::NotZone  => "Name not contained in zone",
            RCode::BADVERS  => "Bad OPT Version",
            RCode::BADKEY   => "Key not recognized",
            RCode::BADTIME  => "Signature out of time window",
            RCode::BADMODE  => "Bad TKEY Mode",
            RCode::BADNAME  => "Duplicate key name",
            RCode::BADALG   => "Algorithm not supported",
            RCode::BADTRUNC => "Bad Truncation",
            RCode::Reserved => "",
            
        }
    }
}

#[cfg(test)]
mod test_rcode {
    use super::RCode;
    
    /// Quick and dirty u16 match checking.
    #[test]
    fn test_rcode_value() {
        
        let qt = RCode::NoError;
        match qt as u16 {
            0 =>    assert!(true),
            _ =>    assert!(false),
        };
    }

    /// Test that defined `QTYPE`s have corresponding variants, and check
    /// that defined `QTYPE` variants translate to/from their u16 values.
    /// Also checks that undefined `QTYPE`s are mapped to `Reserved`.
    #[test]
    fn test_rcode_identity() {
        let defined_rcodes = [
                                0u16,
                                1u16,
                                2u16,
                                3u16,
                                4u16,
                                5u16,
                                6u16,
                                7u16,
                                8u16,
                                9u16,
                                10u16,
                                16u16,
                                17u16,
                                18u16,
                                19u16,
                                20u16,
                                21u16,
                                22u16,
                                65535u16,
                                
                            ];
        let skip = RCode::Reserved as u16;
        // Fuzz all 65536 values possible for QTYPE
        'rng: for val_u in range(0, 65536u) {
            if (val_u as u16) == skip {
                continue 'rng;
            }
            let val: u16 = val_u as u16;
            'defs: for &defval in defined_rcodes.iter() {
                // Do some checks on defined QTYPEs
                if defval == val {
                    // Make sure it doesn't translate to reserved
                    assert!(RCode::Reserved != RCode::from_u16(val));

                    // Make sure converstion from-to-from u16
                    // has the same result.
                    let from_u16 = RCode::from_u16(val);
                    let to_u16 = from_u16 as u16;
                    assert!(from_u16 == RCode::from_u16(to_u16));
                    assert!(to_u16 == RCode::to_u16(from_u16));

                    // If we're good, we can stop checking
                    // the defined QTYPEs list and go to the
                    // next value.
                    continue 'rng;
                }
            }
            // Check everything else is reserved
            assert!(RCode::Reserved == RCode::from_u16(val));
        }
    }
}
