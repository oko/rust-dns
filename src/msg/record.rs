pub use super::{Type,Class,Name};

#[deriving(PartialEq,Show)]
pub struct Question {
    qname: Name,
    qtype: Type,
    qclass: Class,
}

trait ResourceRecordData {
    fn from_u8(&[u8], Option<Self>) -> Result<Self, ResourceRecordError>;
    fn to_u8_vec(&self) -> Vec<u8>;
}

#[deriving(PartialEq,Show)]
pub struct A {
    address: [u8, ..4],
}
impl ResourceRecordData for A {
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

pub enum ResourceRecordError {
    DataFormatError,
    DataSizeError,
}

#[deriving(PartialEq,Show)]
pub struct ResourceRecord {
    rname: Name,
    rtype: Type,
    rclass: Class,
    rttl: i32,
    rdlen: u16,
    rdata: Vec<u8>,
}
impl ResourceRecord {
    pub fn get_record<T: ResourceRecordData>(&self) -> Result<T, ResourceRecordError> {
        Ok(try!(ResourceRecordData::from_u8(self.rdata.as_slice(), None::<T>)))
    }
}

#[cfg(test)]
mod test_resource_record {
    use super::{ResourceRecord,ResourceRecordData,A,Type,Class,Name};

    #[test]
    fn test_get_record() {
        let rr = ResourceRecord {
            rname: Name::new(),
            rtype: Type::A,
            rclass: Class::IN,
            rttl: 300,
            rdlen: 4,
            rdata: vec!(192u8,168,0,1),
        };
        let a: A = rr.get_record().ok().unwrap();
        assert_eq!(rr.rdata, a.to_u8_vec());
    }
}