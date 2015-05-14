pub use super::IdentifierError;

#[repr(u16)]
#[derive(PartialEq,Debug,Clone)]
pub enum EDNS0OptionCode {
    LLQ = 1,
    UL = 2,
    NSID = 3,
    DAU = 5,
    DHU = 6,
    N3U = 7,
    EdnsClientSubnet = 8,
    EDNS = 9,

}

impl EDNS0OptionCode {
    pub fn from_u16(value: u16) ->  Result<EDNS0OptionCode, IdentifierError> {
        match value {
            1 => Ok(EDNS0OptionCode::LLQ),
            2 => Ok(EDNS0OptionCode::UL),
            3 => Ok(EDNS0OptionCode::NSID),
            5 => Ok(EDNS0OptionCode::DAU),
            6 => Ok(EDNS0OptionCode::DHU),
            7 => Ok(EDNS0OptionCode::N3U),
            8 => Ok(EDNS0OptionCode::EdnsClientSubnet),
            9 => Ok(EDNS0OptionCode::EDNS),

            0 => Err(IdentifierError::ReservedIdentifierError(0 as i64)),
            4 => Err(IdentifierError::ReservedIdentifierError(4 as i64)),
            x @ 65001...65534 => Err(IdentifierError::ReservedIdentifierError(x as i64)),
            65535 => Err(IdentifierError::ReservedIdentifierError(65535 as i64)),

            x @ 10...65000 => Err(IdentifierError::UnassignedIdentifierError(x as i64)),

            x @ _ => Err(IdentifierError::UnknownIdentifierError(x as i64)),
        }
    }
}

#[cfg(test)]
mod test_edns0optioncode {
    use super::EDNS0OptionCode;
    use super::IdentifierError;
    #[test]
    fn test_variant_identity() {
        assert_eq!(EDNS0OptionCode::LLQ, EDNS0OptionCode::from_u16(1).ok().unwrap());
        assert_eq!(EDNS0OptionCode::UL, EDNS0OptionCode::from_u16(2).ok().unwrap());
        assert_eq!(EDNS0OptionCode::NSID, EDNS0OptionCode::from_u16(3).ok().unwrap());
        assert_eq!(EDNS0OptionCode::DAU, EDNS0OptionCode::from_u16(5).ok().unwrap());
        assert_eq!(EDNS0OptionCode::DHU, EDNS0OptionCode::from_u16(6).ok().unwrap());
        assert_eq!(EDNS0OptionCode::N3U, EDNS0OptionCode::from_u16(7).ok().unwrap());
        assert_eq!(EDNS0OptionCode::EdnsClientSubnet, EDNS0OptionCode::from_u16(8).ok().unwrap());
        assert_eq!(EDNS0OptionCode::EDNS, EDNS0OptionCode::from_u16(9).ok().unwrap());

    }

    #[test]
    fn test_range_reserved_identity() {
        assert_eq!(IdentifierError::ReservedIdentifierError(0), EDNS0OptionCode::from_u16(0).err().unwrap());
        assert_eq!(IdentifierError::ReservedIdentifierError(4), EDNS0OptionCode::from_u16(4).err().unwrap());
        for i in 65001..(65534u64+1) {
            assert_eq!(IdentifierError::ReservedIdentifierError(i as i64), EDNS0OptionCode::from_u16(i as u16).err().unwrap());
        }
        assert_eq!(IdentifierError::ReservedIdentifierError(65535), EDNS0OptionCode::from_u16(65535).err().unwrap());

    }
    #[test]
    fn test_range_unassigned_identity() {
        for i in 10..(65000u64+1) {
            assert_eq!(IdentifierError::UnassignedIdentifierError(i as i64), EDNS0OptionCode::from_u16(i as u16).err().unwrap());
        }

    }

}
