use std::error;
use std::fmt;

#[derive(PartialEq,Debug,Copy,Clone)]
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

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            _ => None,
        }
    }
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            IdentifierError::ReservedIdentifierError(x) => write!(f, "reserved IANA identifier {}", x),
            IdentifierError::UnassignedIdentifierError(x) => write!(f, "unassigned IANA identifier {}", x),
            IdentifierError::PrivateUseIdentifierError(x) => write!(f, "private use IANA identifier {}", x),
            IdentifierError::UnknownIdentifierError(x) => write!(f, "unknown IANA identifier {}", x),
        }
    }
}
