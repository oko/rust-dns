pub use super::iana::types::Type;
pub use super::iana::classes::Class;
pub use super::iana::rcodes::RCode;
pub use super::iana::opcodes::OpCode;
pub use super::iana::errors::IdentifierError;

pub use super::parser::message::{Message,Question,ResourceRecord,Name,Label};
pub use super::parser::message::{read_dns_message,read_dns_question,read_dns_resource_record,read_dns_name};
pub use super::parser::util::{_read_be_u16,_read_be_i32};

mod errors;
mod message;
mod util;
mod tests;
