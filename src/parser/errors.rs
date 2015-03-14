use std::fmt;
use std::error;
use super::IdentifierError;

#[derive(PartialEq,Copy,Clone)]
pub enum ReadError {
    InvalidIdentifierError(super::IdentifierError),
    IndexOutOfRangeError(usize, usize),
    LabelTooLongError(usize),
    LabelZeroLengthError,
    LabelInputFormatError,
}

impl error::Error for ReadError {
    fn description(&self) -> &str {
        match *self {
            ReadError::InvalidIdentifierError(x) => "Read an invalid identifier",
            ReadError::IndexOutOfRangeError(_, _) => "Index out of range",
            ReadError::LabelTooLongError(x) => "Label too long",
            ReadError::LabelZeroLengthError => "Label has zero length",
            ReadError::LabelInputFormatError => "Label input format invalid",
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

 impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ReadError::InvalidIdentifierError(x) => write!(f, "Read an invalid identifier: {}", x),
            ReadError::IndexOutOfRangeError(x, y) => write!(f, "Index out of range: {} > {}", x, y),
            ReadError::LabelTooLongError(x) => write!(f, "Label was too long: {} > 63", x),
            ReadError::LabelZeroLengthError => write!(f, "Label has zero length"),
            ReadError::LabelInputFormatError => write!(f, "Label input format invalid"),
        }
    }
}
