pub use super::IdentifierError;

#[repr(u8)]
#[deriving(PartialEq,Show)]
pub enum OpCode {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
    
}

impl OpCode {
    pub fn from_u8(value: u8) ->  Result<OpCode, IdentifierError> {
        match value {
            0 => Ok(OpCode::Query),
            1 => Ok(OpCode::IQuery),
            2 => Ok(OpCode::Status),
            4 => Ok(OpCode::Notify),
            5 => Ok(OpCode::Update),
            
            3 => Err(IdentifierError::UnassignedIdentifierError(3 as i64)),
            x @ 6...15 => Err(IdentifierError::UnassignedIdentifierError(x as i64)),
            
            x @ _ => Err(IdentifierError::UnknownIdentifierError(x as i64)),
        }
    }
}

#[cfg(test)]
mod test_opcode {
    use super::OpCode;
    use super::IdentifierError;
    #[test]
    fn test_variant_identity() {
        assert_eq!(OpCode::Query, OpCode::from_u8(0).ok().unwrap());
        assert_eq!(OpCode::IQuery, OpCode::from_u8(1).ok().unwrap());
        assert_eq!(OpCode::Status, OpCode::from_u8(2).ok().unwrap());
        assert_eq!(OpCode::Notify, OpCode::from_u8(4).ok().unwrap());
        assert_eq!(OpCode::Update, OpCode::from_u8(5).ok().unwrap());
        
    }

    #[test]
    fn test_range_unassigned_identity() {
        assert_eq!(IdentifierError::UnassignedIdentifierError(3), OpCode::from_u8(3).err().unwrap());
        for i in range(6, 15u64+1) {
            assert_eq!(IdentifierError::UnassignedIdentifierError(i as i64), OpCode::from_u8(i as u8).err().unwrap());
        }
        
    }
    
}