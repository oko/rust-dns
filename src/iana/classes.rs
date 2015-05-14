pub use super::IdentifierError;

#[repr(u16)]
#[derive(PartialEq,Debug,Clone)]
pub enum Class {
    IN = 1,
    CH = 3,
    HS = 4,
    NONE = 254,
    ANY = 255,

}

impl Class {
    pub fn from_u16(value: u16) ->  Result<Class, IdentifierError> {
        match value {
            1 => Ok(Class::IN),
            3 => Ok(Class::CH),
            4 => Ok(Class::HS),
            254 => Ok(Class::NONE),
            255 => Ok(Class::ANY),

            x @ 65280...65534 => Err(IdentifierError::PrivateUseIdentifierError(x as i64)),

            0 => Err(IdentifierError::ReservedIdentifierError(0 as i64)),
            65535 => Err(IdentifierError::ReservedIdentifierError(65535 as i64)),

            2 => Err(IdentifierError::UnassignedIdentifierError(2 as i64)),
            x @ 5...253 => Err(IdentifierError::UnassignedIdentifierError(x as i64)),
            x @ 256...65279 => Err(IdentifierError::UnassignedIdentifierError(x as i64)),

            x @ _ => Err(IdentifierError::UnknownIdentifierError(x as i64)),
        }
    }
}

#[cfg(test)]
mod test_class {
    use super::Class;
    use super::IdentifierError;
    #[test]
    fn test_variant_identity() {
        assert_eq!(Class::IN, Class::from_u16(1).ok().unwrap());
        assert_eq!(Class::CH, Class::from_u16(3).ok().unwrap());
        assert_eq!(Class::HS, Class::from_u16(4).ok().unwrap());
        assert_eq!(Class::NONE, Class::from_u16(254).ok().unwrap());
        assert_eq!(Class::ANY, Class::from_u16(255).ok().unwrap());

    }

    #[test]
    fn test_range_privateuse_identity() {
        for i in 65280..(65534u64+1) {
            assert_eq!(IdentifierError::PrivateUseIdentifierError(i as i64), Class::from_u16(i as u16).err().unwrap());
        }

    }
    #[test]
    fn test_range_reserved_identity() {
        assert_eq!(IdentifierError::ReservedIdentifierError(0), Class::from_u16(0).err().unwrap());
        assert_eq!(IdentifierError::ReservedIdentifierError(65535), Class::from_u16(65535).err().unwrap());

    }
    #[test]
    fn test_range_unassigned_identity() {
        assert_eq!(IdentifierError::UnassignedIdentifierError(2), Class::from_u16(2).err().unwrap());
        for i in 5..(253u64+1) {
            assert_eq!(IdentifierError::UnassignedIdentifierError(i as i64), Class::from_u16(i as u16).err().unwrap());
        }
        for i in 256..(65279u64+1) {
            assert_eq!(IdentifierError::UnassignedIdentifierError(i as i64), Class::from_u16(i as u16).err().unwrap());
        }

    }

}
