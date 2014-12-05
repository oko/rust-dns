#[repr(u16)]
#[deriving(PartialEq,Show)]
pub enum RRClass {
    Reserved   = 0,
    IN         = 1,
    Unassigned = 2,
    CH         = 3,
    HS         = 4,
    NONE       = 254,
    ANY        = 255,
    
}

impl RRClass {
    /// Convert a `u16` integer to a `RRClass` variant. Undefined values are
    /// mapped to `RRClass::Reserved`.
    pub fn from_u16(val: u16) -> RRClass {
        match val {
            0   => RRClass::Reserved,
            1   => RRClass::IN,
            2   => RRClass::Unassigned,
            3   => RRClass::CH,
            4   => RRClass::HS,
            254 => RRClass::NONE,
            255 => RRClass::ANY,
            
            _ => RRClass::Reserved,
        }
    }
    pub fn to_u16(rrclass: RRClass) -> u16 {
        rrclass as u16
    }
    pub fn from_str(val: &str) -> RRClass {
        match val {
            "Reserved"   => RRClass::Reserved,
            "IN"         => RRClass::IN,
            "Unassigned" => RRClass::Unassigned,
            "CH"         => RRClass::CH,
            "HS"         => RRClass::HS,
            "NONE"       => RRClass::NONE,
            "ANY"        => RRClass::ANY,
            
            _ => RRClass::Reserved,
        }
    }
    
}

#[cfg(test)]
mod test_rrclass {
    use super::RRClass;
    
    /// Quick and dirty u16 match checking.
    #[test]
    fn test_rrclass_value() {
        
        let qt = RRClass::Reserved;
        match qt as u16 {
            0 =>    assert!(true),
            _ =>    assert!(false),
        };
    }

    /// Test that defined `QTYPE`s have corresponding variants, and check
    /// that defined `QTYPE` variants translate to/from their u16 values.
    /// Also checks that undefined `QTYPE`s are mapped to `Reserved`.
    #[test]
    fn test_rrclass_identity() {
        let defined_rrclasss = [
                                0u16,
                                1u16,
                                2u16,
                                3u16,
                                4u16,
                                254u16,
                                255u16,
                                
                            ];
        let skip = RRClass::Reserved as u16;
        // Fuzz all 65536 values possible for QTYPE
        'rng: for val_u in range(0, 65536u) {
            if (val_u as u16) == skip {
                continue 'rng;
            }
            let val: u16 = val_u as u16;
            'defs: for &defval in defined_rrclasss.iter() {
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