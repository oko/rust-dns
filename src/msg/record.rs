pub use super::{Type,Class,Name,DNSNameReader,DNSNumberReader};

use std::io;

#[deriving(PartialEq,Show,Clone)]
pub struct Question {
    pub qname: Name,
    pub qtype: Type,
    pub qclass: Class,
}

impl Question {
    pub fn new() -> Question{
        Question {
            qname: Name::new(),
            qtype: Type::A,
            qclass: Class::IN,
        }
    }
}

pub trait DNSQuestionReader {
    fn read_dns_question(&mut self) -> io::IoResult<Question>;
}
impl<'a> DNSQuestionReader for io::BufReader<'a> {
    fn read_dns_question(&mut self) -> io::IoResult<Question> {
        let mut question = Question {
            qname: try!(self.read_dns_name()),
            qtype: try!(self.read_dns_type()),
            qclass: try!(self.read_dns_class()),
        };
        Ok(question)
    }
}
pub enum ResourceRecordError {
    DataFormatError,
    DataSizeError,
}

#[deriving(PartialEq,Show,Clone)]
pub struct ResourceRecord {
    pub rname: Name,
    pub rtype: Type,
    pub rclass: Class,
    pub rttl: i32,
    pub rdlen: u16,
    pub rdata: Vec<u8>,
}
impl ResourceRecord {
    pub fn new() -> ResourceRecord {
        ResourceRecord {
            rname: Name::new(),
            rtype: Type::A,
            rclass: Class::IN,
            rttl: 300,
            rdlen: 4,
            rdata: vec!(192u8,168,0,1),
        }
    }
    pub fn get_record<T: ResourceRecordDataType>(&self) -> Result<T, ResourceRecordError> {
        Ok(try!(ResourceRecordDataType::from_u8(self.rdata.as_slice(), None::<T>)))
    }
    pub fn get_rname(&self) -> Name {
        self.rname.clone()
    }
}

pub trait DNSResourceRecordReader {
    fn read_dns_resource_record(&mut self) -> io::IoResult<ResourceRecord>;
}
impl<'a> DNSResourceRecordReader for io::BufReader<'a> {
    fn read_dns_resource_record(&mut self) -> io::IoResult<ResourceRecord> {
        let mut record = ResourceRecord {
            rname: try!(self.read_dns_name()),
            rtype: try!(self.read_dns_type()),
            rclass: try!(self.read_dns_class()),
            rttl: try!(self.read_be_i32()),
            rdlen: try!(self.read_be_u16()),
            rdata: Vec::new(),
        };
        match record.rtype {
            Type::CNAME |
             Type::MB |
             Type::MD |
             Type::MG |
             Type::MR |
             Type::NS |
             Type::PTR
             => {
                let n = try!(self.read_dns_name());
                try!(n.push_bytes(&mut record.rdata));
            },
            _ => {
                try!(self.push(record.rdlen as uint, &mut record.rdata));
            },
        }
        
        Ok(record)
    }

}



pub trait ResourceRecordDataType {
    fn from_u8(&[u8], Option<Self>) -> Result<Self, ResourceRecordError>;
    fn to_u8_vec(&self) -> Vec<u8>;
}

#[deriving(PartialEq,Show,Clone)]
pub struct A {
    address: [u8, ..4],
}
impl ResourceRecordDataType for A {
    fn from_u8(data: &[u8], _ignore: Option<A>) -> Result<A, ResourceRecordError> {
        if data.len() == 4 {
            Ok(A { address: [data[0], data[1], data[2], data[3]] })
        } else {
            Err(ResourceRecordError::DataSizeError)
        }
    }
    fn to_u8_vec(&self) -> Vec<u8> {
        vec!(self.address[0], self.address[1], self.address[2], self.address[3])
    }
}


#[cfg(test)]
mod test_resource_record {
    // TODO: write unit tests for DNSResourceRecordReader & co.
}