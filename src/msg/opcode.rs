#[repr(u8)]
#[deriving(PartialEq,Show)]
pub enum OpCode {
    Query      = 0,
    IQuery     = 1,
    Status     = 2,
    Unassigned = 3,
    Notify     = 4,
    Update     = 5,
    
}

impl OpCode {
    /// Convert a `u8` integer to a `OpCode` variant. Undefined values are
    /// mapped to `OpCode::Unassigned`.
    pub fn from_u8(val: u8) -> OpCode {
        match val {
            0 => OpCode::Query,
            1 => OpCode::IQuery,
            2 => OpCode::Status,
            3 => OpCode::Unassigned,
            4 => OpCode::Notify,
            5 => OpCode::Update,
            
            _ => OpCode::Unassigned,
        }
    }
    pub fn to_u8(opcode: OpCode) -> u8 {
        opcode as u8
    }
    pub fn from_str(val: &str) -> OpCode {
        match val {
            "Query"      => OpCode::Query,
            "IQuery"     => OpCode::IQuery,
            "Status"     => OpCode::Status,
            "Unassigned" => OpCode::Unassigned,
            "Notify"     => OpCode::Notify,
            "Update"     => OpCode::Update,
            
            _ => OpCode::Unassigned,
        }
    }
    
}

#[cfg(test)]
mod test_opcode {
    use super::OpCode;
    
    /// Quick and dirty u8 match checking.
    #[test]
    fn test_opcode_value() {
        
        let qt = OpCode::Query;
        match qt as u8 {
            0 =>    assert!(true),
            _ =>    assert!(false),
        };
    }

    /// Test that defined `QTYPE`s have corresponding variants, and check
    /// that defined `QTYPE` variants translate to/from their u8 values.
    /// Also checks that undefined `QTYPE`s are mapped to `Unassigned`.
    #[test]
    fn test_opcode_identity() {
        let defined_opcodes = [
                                0u8,
                                1u8,
                                2u8,
                                3u8,
                                4u8,
                                5u8,
                                
                            ];
        let skip = OpCode::Unassigned as u8;
        // Fuzz all 65536 values possible for QTYPE
        'rng: for val_u in range(0, 256u) {
            if (val_u as u8) == skip {
                continue 'rng;
            }
            let val: u8 = val_u as u8;
            'defs: for &defval in defined_opcodes.iter() {
                // Do some checks on defined QTYPEs
                if defval == val {
                    // Make sure it doesn't translate to reserved
                    assert!(OpCode::Unassigned != OpCode::from_u8(val));

                    // Make sure converstion from-to-from u8
                    // has the same result.
                    let from_u8 = OpCode::from_u8(val);
                    let to_u8 = from_u8 as u8;
                    assert!(from_u8 == OpCode::from_u8(to_u8));
                    assert!(to_u8 == OpCode::to_u8(from_u8));

                    // If we're good, we can stop checking
                    // the defined QTYPEs list and go to the
                    // next value.
                    continue 'rng;
                }
            }
            // Check everything else is reserved
            assert!(OpCode::Unassigned == OpCode::from_u8(val));
        }
    }
}
