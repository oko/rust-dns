use std::error;
use super::IdentifierError;

#[deriving(PartialEq,Show,Copy,Clone)]
pub enum ReadError {
    InvalidIdentifierError(super::IdentifierError),
    IndexOutOfRangeError(uint, uint),
    LabelTooLongError(uint),
    LabelZeroLengthError,
}

impl error::Error for ReadError {
    fn description(&self) -> &str {
        match *self {
            ReadError::InvalidIdentifierError(x) => "Read an invalid identifier",
            ReadError::IndexOutOfRangeError(_, _) => "Index out of range",
            ReadError::LabelTooLongError(x) => "Label too long",
            ReadError::LabelZeroLengthError => "Label has zero length"
        }
    }

    fn detail(&self) -> Option<String> {
        match *self {
            ReadError::InvalidIdentifierError(x) => Some(format!("Read an invalid identifier: {}", x)),
            ReadError::IndexOutOfRangeError(x, y) => Some(format!("Index out of range: {} > {}", x, y)),
            ReadError::LabelTooLongError(x) => Some(format!("Label was too long: {} > 63", x)),
            ReadError::LabelZeroLengthError => Some(format!("Label has zero length")),

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