use std::fmt;
use std::convert;
use std::error;
use super::IdentifierError;

#[derive(PartialEq,Copy,Clone,Debug)]
pub enum ReadError {
    InvalidIdentifierError(super::IdentifierError),
    IndexOutOfRangeError(usize, usize),
    LabelTooLongError(usize),
    LabelZeroLengthError,
}

impl error::Error for ReadError {
    fn description(&self) -> &str {
        match *self {
            ReadError::InvalidIdentifierError(_) => "Read an invalid identifier",
            ReadError::IndexOutOfRangeError(_, _) => "Index out of range",
            ReadError::LabelTooLongError(_) => "Label was too long",
            ReadError::LabelZeroLengthError => "Label has zero length",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            ReadError::InvalidIdentifierError(ref err) => Some(err as &error::Error),
            _ => None,
        }
    }
}

impl convert::From<IdentifierError> for ReadError {
    fn from(err: IdentifierError) -> ReadError {
        ReadError::InvalidIdentifierError(err)
    }
}

 impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ReadError::InvalidIdentifierError(x) => write!(f, "Read an invalid identifier: {}", x),
            ReadError::IndexOutOfRangeError(x, y) => write!(f, "Index out of range: {} > {}", x, y),
            ReadError::LabelTooLongError(x) => write!(f, "Label was too long: {} > 63", x),
            ReadError::LabelZeroLengthError => write!(f, "Label has zero length"),
        }
    }
}
