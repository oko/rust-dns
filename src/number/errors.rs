use std::error;

#[deriving(PartialEq,Show,Copy,Clone)]
pub enum IdentifierError {
	ReservedIdentifierError(i64),
	UnassignedIdentifierError(i64),
	PrivateUseIdentifierError(i64),
	UnknownIdentifierError(i64)
}

impl error::Error for IdentifierError {
    fn description(&self) -> &str {
        match *self {
            IdentifierError::ReservedIdentifierError(_) => "Received a reserved identifier",
            IdentifierError::UnassignedIdentifierError(_) => "Received an unassigned identifier",
            IdentifierError::PrivateUseIdentifierError(_) => "Received a private-use identifier",
            IdentifierError::UnknownIdentifierError(_) => "Received an unknown identifier",
        }
    }

    fn detail(&self) -> Option<String> {
        match *self {
            IdentifierError::ReservedIdentifierError(x) => Some(format!("Received a reserved identifier: {}", x)),
            IdentifierError::UnassignedIdentifierError(x) => Some(format!("Received an unassigned identifier: {}", x)),
            IdentifierError::PrivateUseIdentifierError(x) => Some(format!("Received a private-use identifier: {}", x)),
            IdentifierError::UnknownIdentifierError(x) => Some(format!("Received an unknown identifier: {}", x)),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            _ => None,
        }
    }
}