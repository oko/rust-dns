pub use self::errors::IdentifierError;

pub use self::classes::Class;
pub use self::opcodes::OpCode;
pub use self::rcodes::RCode;
pub use self::types::Type;
pub use self::edns0codes::EDNS0OptionCode;

use std::io;

pub mod errors;

pub mod classes;
pub mod opcodes;
pub mod rcodes;
pub mod types;
pub mod edns0codes;

pub trait DNSNumberReader {
    fn read_dns_type(&mut self) -> io::IoResult<Type>;
    fn read_dns_class(&mut self) -> io::IoResult<Class>;
}
impl<'a> DNSNumberReader for io::BufReader<'a> {
    fn read_dns_type(&mut self) -> io::IoResult<Type> {
        let t = Type::from_u16(try!(self.read_be_u16()));
        match t {
            Ok(a) => Ok(a),
            Err(a) => {
                println!("Type error: {} @ {}", a, self.tell());
                Err(io::standard_error(io::InvalidInput))
            },
        }
    }
    fn read_dns_class(&mut self) -> io::IoResult<Class> {
        let c = Class::from_u16(try!(self.read_be_u16()));
        match c {
            Ok(a) => Ok(a),
            Err(a) => {
                Err(io::standard_error(io::InvalidInput))
            },
        }
    }
}