pub use super::IdentifierError;

#[repr(u16)]
#[deriving(PartialEq,Show,Clone)]
pub enum RCode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp = 4,
    Refused = 5,
    YXDomain = 6,
    YXRRSet = 7,
    NXRRSet = 8,
    NotAuth = 9,
    NotZone = 10,
    BADVERS = 16,
    BADKEY = 17,
    BADTIME = 18,
    BADMODE = 19,
    BADNAME = 20,
    BADALG = 21,
    BADTRUNC = 22,
    
}

impl RCode {
    pub fn from_u16(value: u16) ->  Result<RCode, IdentifierError> {
        match value {
            0 => Ok(RCode::NoError),
            1 => Ok(RCode::FormErr),
            2 => Ok(RCode::ServFail),
            3 => Ok(RCode::NXDomain),
            4 => Ok(RCode::NotImp),
            5 => Ok(RCode::Refused),
            6 => Ok(RCode::YXDomain),
            7 => Ok(RCode::YXRRSet),
            8 => Ok(RCode::NXRRSet),
            9 => Ok(RCode::NotAuth),
            10 => Ok(RCode::NotZone),
            16 => Ok(RCode::BADVERS),
            17 => Ok(RCode::BADKEY),
            18 => Ok(RCode::BADTIME),
            19 => Ok(RCode::BADMODE),
            20 => Ok(RCode::BADNAME),
            21 => Ok(RCode::BADALG),
            22 => Ok(RCode::BADTRUNC),
            
            x @ 3841...4095 => Err(IdentifierError::PrivateUseIdentifierError(x as i64)),
            
            65535 => Err(IdentifierError::ReservedIdentifierError(65535 as i64)),
            
            x @ 11...15 => Err(IdentifierError::UnassignedIdentifierError(x as i64)),
            x @ 23...3840 => Err(IdentifierError::UnassignedIdentifierError(x as i64)),
            x @ 4096...65534 => Err(IdentifierError::UnassignedIdentifierError(x as i64)),
            
            x @ _ => Err(IdentifierError::UnknownIdentifierError(x as i64)),
        }
    }
}

#[cfg(test)]
mod test_rcode {
    use super::RCode;
    use super::IdentifierError;
    #[test]
    fn test_variant_identity() {
        assert_eq!(RCode::NoError, RCode::from_u16(0).ok().unwrap());
        assert_eq!(RCode::FormErr, RCode::from_u16(1).ok().unwrap());
        assert_eq!(RCode::ServFail, RCode::from_u16(2).ok().unwrap());
        assert_eq!(RCode::NXDomain, RCode::from_u16(3).ok().unwrap());
        assert_eq!(RCode::NotImp, RCode::from_u16(4).ok().unwrap());
        assert_eq!(RCode::Refused, RCode::from_u16(5).ok().unwrap());
        assert_eq!(RCode::YXDomain, RCode::from_u16(6).ok().unwrap());
        assert_eq!(RCode::YXRRSet, RCode::from_u16(7).ok().unwrap());
        assert_eq!(RCode::NXRRSet, RCode::from_u16(8).ok().unwrap());
        assert_eq!(RCode::NotAuth, RCode::from_u16(9).ok().unwrap());
        assert_eq!(RCode::NotZone, RCode::from_u16(10).ok().unwrap());
        assert_eq!(RCode::BADVERS, RCode::from_u16(16).ok().unwrap());
        assert_eq!(RCode::BADKEY, RCode::from_u16(17).ok().unwrap());
        assert_eq!(RCode::BADTIME, RCode::from_u16(18).ok().unwrap());
        assert_eq!(RCode::BADMODE, RCode::from_u16(19).ok().unwrap());
        assert_eq!(RCode::BADNAME, RCode::from_u16(20).ok().unwrap());
        assert_eq!(RCode::BADALG, RCode::from_u16(21).ok().unwrap());
        assert_eq!(RCode::BADTRUNC, RCode::from_u16(22).ok().unwrap());
        
    }

    #[test]
    fn test_range_privateuse_identity() {
        for i in range(3841, 4095u64+1) {
            assert_eq!(IdentifierError::PrivateUseIdentifierError(i as i64), RCode::from_u16(i as u16).err().unwrap());
        }
        
    }
    #[test]
    fn test_range_reserved_identity() {
        assert_eq!(IdentifierError::ReservedIdentifierError(65535), RCode::from_u16(65535).err().unwrap());
        
    }
    #[test]
    fn test_range_unassigned_identity() {
        for i in range(11, 15u64+1) {
            assert_eq!(IdentifierError::UnassignedIdentifierError(i as i64), RCode::from_u16(i as u16).err().unwrap());
        }
        for i in range(23, 3840u64+1) {
            assert_eq!(IdentifierError::UnassignedIdentifierError(i as i64), RCode::from_u16(i as u16).err().unwrap());
        }
        for i in range(4096, 65534u64+1) {
            assert_eq!(IdentifierError::UnassignedIdentifierError(i as i64), RCode::from_u16(i as u16).err().unwrap());
        }
        
    }
    
}