use std::error;
use super::IdentifierError;

#[deriving(PartialEq,Show,Copy,Clone)]
pub enum ReadError {
    InvalidIdentifierError(super::IdentifierError),
    IndexOutOfRangeError(uint, uint),
    InvalidUTF8StringError,
}

impl error::Error for ReadError {
    fn description(&self) -> &str {
        match *self {
            ReadError::InvalidIdentifierError(x) => "Read an invalid identifier",
            ReadError::IndexOutOfRangeError(_, _) => "Index out of range",
            ReadError::InvalidUTF8StringError => "Invalid UTF-8 string",
        }
    }

    fn detail(&self) -> Option<String> {
        match *self {
            ReadError::InvalidIdentifierError(x) => Some(format!("Read an invalid identifier: {}", x)),
            ReadError::IndexOutOfRangeError(x, y) => Some(format!("Index out of range: {} > {}", x, y)),
            ReadError::InvalidUTF8StringError => Some(format!("Invalid UTF-8 string")),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            ReadError::InvalidIdentifierError(ref err) => Some(err as &error::Error),
            _ => None,
        }
    }
}

impl error::FromError<IdentifierError> for ReadError {
    fn from_error(err: IdentifierError) -> ReadError {
        ReadError::InvalidIdentifierError(err)
    }
}