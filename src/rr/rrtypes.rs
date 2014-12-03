use super::{RRType, RRClass, TTL};
use std::fmt;

pub struct RR {
    pub name: Vec<String>,
    pub rrtype: RRType,
    pub rrclass: RRClass,
    pub ttl: TTL,
    pub rdata: Vec<u8>,
}

trait RData {
    fn to_rdata(&self) -> Vec<u8>;
    fn from_rdata(&[u8], _ignored: Option<Self>) -> Result<Self, &'static str>;
}

/// DNS A record
#[deriving(PartialEq,Eq)]
pub struct A {
    /// Address as an array of `u8` bytes
    pub address: [u8, ..4],
}
impl A {
    /// Create a new A record from a `u32` representation
    fn from_u32(ival: u32) -> A {
        A {
            address: [(ival >> 24) as u8, (ival >> 16) as u8, (ival >> 8) as u8, (ival & 0xFF) as u8],
        }
    }
    /// Create a new A record from four octets
    fn new(a: u8, b: u8, c: u8, d: u8) -> A {
        A {
            address: [a, b, c, d],
        }
    }
}
impl fmt::Show for A {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}.{}.{}.{}", self.address[0], self.address[1], self.address[2], self.address[3])
    }
}
impl RData for A {
    fn to_rdata(&self) -> Vec<u8>{
        let mut rdata: Vec<u8> = Vec::new();
        for &byte in self.address.iter() {
            rdata.push(byte);
        }
        rdata
    }
    fn from_rdata(rdata: &[u8], _ignored: Option<A>) -> Result<A, &'static str> {
        let rlen = rdata.len();
        if rlen == 4 {
            Ok(A { address: [rdata[0], rdata[1], rdata[2], rdata[3]] })
        } else if rlen < 4 {
            Err("rdata too small for A record")
        } else {
            Err("rdata too large for A record")
        }
    }
}

/// DNS AAAA record
#[deriving(PartialEq,Eq)]
pub struct AAAA {
    pub address: [u16, ..8],
}
impl AAAA {
    /// Create a new AAAA record from an array of 8 `u16` bytes
    fn new(iarr: [u16, ..8]) -> AAAA {
        AAAA {
            address: iarr,
        }
    }

    /// Generate an [RFC5952](http://tools.ietf.org/html/rfc5952)-compliant
    /// representation of a AAAA record's IPv6 address.
    fn rfc5952(&self) -> String {
        let mut occurrences: Vec<(int, uint)> = Vec::new();
        let mut start = -1i;
        let mut size = 0u;
        let mut i = 0u;
        let mut last = -1i;
        while i < 8 {
            let part = self.address[i] as int;

            if part == 0 {
                if part != last {
                    start = i as int;
                }
                size += 1;
            } else {
                if last == 0 {
                    occurrences.push( (start, size) );
                    start = -1;
                    size = 0;
                }
            }
            last = part;
            i += 1;
        }
        if start != -1 {
            occurrences.push( (start, size) );
        }
        let mut largest: (int, uint) = (0, 0);
        for &occurrence in occurrences.iter() {
            let (start, len) = occurrence;
            let (_, lsize) = largest;
            if len > lsize {
                largest = (start, len);
            }
        }
        let (start, len) = largest;

        // Basic formatting if no zero fields exist or largest group
        // is only one field.
        if (start == 0 && len == 0) || len < 2 {
            format!("{}", self)
        } else {
            i = 0;
            let mut output = String::with_capacity(8*4+7);
            let mut double_colon = false;
            while i < 8 {
                if i < start as uint || i >= (start as uint) + len {
                    if i + 1 < 8 {
                        output.push_str(format!("{:x}:", self.address[i]).as_slice());
                    } else {
                        output.push_str(format!("{:x}", self.address[i]).as_slice());
                    }
                } else {
                    if !double_colon {
                        output.push_str(":");
                        double_colon = true;
                    }
                }
                i += 1;
            }
            output
        }
    }
}
impl fmt::Show for AAAA {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            self.address[0], self.address[1], self.address[2], self.address[3],
            self.address[4], self.address[5], self.address[6], self.address[7])
    }
}
impl RData for AAAA {
    fn to_rdata(&self) -> Vec<u8>{
        let mut rdata: Vec<u8> = Vec::new();
        for &dbyte in self.address.iter() {
            rdata.push((dbyte >> 8) as u8);
            rdata.push(dbyte as u8);
        }
        rdata
    }
    fn from_rdata(rdata: &[u8], _ignored: Option<AAAA>) -> Result<AAAA, &'static str> {
        let rlen = rdata.len();
        if rlen == 16 {
            let mut data = [0u16, ..8];
            for i in range(0, 8u) {
                data[i] = ((rdata[2*i] as u16) << 8) + (rdata[(2*i)+1] as u16);
            }
            Ok(AAAA { address: data, })
        } else if rlen < 16 {
            Err("rdata too small for AAAA record")
        } else {
            Err("rdata too large for AAAA record")
        }
    }
}

#[cfg(test)]
mod test_a {
    use super::{A, RData};

    #[test]
    fn test_rr_a_create() {
        let rec = A { address: [192, 168, 0, 1] };
        assert!(rec.address[0] == 192);
        assert!(rec.address[1] == 168);
        assert!(rec.address[2] == 0);
        assert!(rec.address[3] == 1);
    }
    #[test]
    fn test_rr_a_new() {
        let rec = A::new(192, 168, 0, 1);
        assert!(rec.address[0] == 192);
        assert!(rec.address[1] == 168);
        assert!(rec.address[2] == 0);
        assert!(rec.address[3] == 1);
    }

    #[test]
    fn test_rr_a_show() {
        let rec = A::from_u32(3232235521);
        assert!(format!("{}", rec).as_slice() == "192.168.0.1");
    }

    #[test]
    fn test_rr_a_to_rdata() {
        let rec = A::new(192, 168, 0, 1);
        let output = rec.to_rdata();
        let compare = vec!(192u8, 168, 0, 1);

        assert_eq!(output.len(), 4);
        assert_eq!(output.len(), compare.len());

        for i in range(0, compare.len()) {
            assert_eq!(output[i], compare[i]);
        }
    }

    #[test]
    fn test_rr_a_from_rdata() {
        let rec = A::new(192, 168, 0, 1);
        let output = rec.to_rdata();
        let compare = vec!(192u8, 168, 0, 1);

        let rec_new = RData::from_rdata(compare.as_slice(), None::<A>).ok().unwrap();
        assert_eq!(rec_new, rec);
    }
}

#[cfg(test)]
mod test_aaaa {
    use super::{AAAA, RData};
    #[test]
    fn test_rr_aaaa_create() {
        let rec = AAAA { address: [0x2001, 0x0db8, 0xac10, 0xfe01, 0x0, 0x0, 0x0, 0x0] };
        assert!(rec.address[0] == 0x2001);
        assert!(rec.address[1] == 0x0db8);
        assert!(rec.address[2] == 0xac10);
        assert!(rec.address[3] == 0xfe01);
        assert!(rec.address[4] == 0x0);
        assert!(rec.address[5] == 0x0);
        assert!(rec.address[6] == 0x0);
        assert!(rec.address[7] == 0x0);
    }

    #[test]
    fn test_rr_aaaa_new() {
        let rec = AAAA::new([0x2001, 0x0db8, 0xac10, 0xfe01, 0x0, 0x1, 0x2, 0x3]);
        assert!(rec.address[0] == 0x2001);
        assert!(rec.address[1] == 0x0db8);
        assert!(rec.address[2] == 0xac10);
        assert!(rec.address[3] == 0xfe01);
        assert!(rec.address[4] == 0x0);
        assert!(rec.address[5] == 0x1);
        assert!(rec.address[6] == 0x2);
        assert!(rec.address[7] == 0x3);
    }

    #[test]
    fn test_rr_aaaa_show() {
        let rec = AAAA::new([0x2001, 0x0db8, 0xac10, 0xfe01, 0x0, 0x0, 0x0, 0x0]);
        assert!(format!("{}", rec).as_slice() == "2001:db8:ac10:fe01:0:0:0:0");
    }

    #[test]
    fn test_rr_aaaa_rfc5952() {
        let rec = AAAA::new([0x2001, 0x0db8, 0xfe01, 0x0, 0x0, 0x0, 0x0, 0xac10]);
        assert!(rec.rfc5952().as_slice() == "2001:db8:fe01::ac10");
        let rec = AAAA::new([0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1]);
        assert!(rec.rfc5952().as_slice() == "1:0:0:1::1");
        let rec = AAAA::new([0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x1]);
        assert!(rec.rfc5952().as_slice() == "1::1:0:0:1");
        let rec = AAAA::new([0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1]);
        assert!(rec.rfc5952().as_slice() == "1::1");
        let rec = AAAA::new([0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]);
        assert!(rec.rfc5952().as_slice() == "1::");
        let rec = AAAA::new([0x1, 0x0, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1]);
        assert!(rec.rfc5952().as_slice() == "1:0:1:1:1:1:1:1");
        let rec = AAAA::new([0x1, 0x0, 0x1, 0x1, 0x1, 0x0, 0x0, 0x1]);
        assert!(rec.rfc5952().as_slice() == "1:0:1:1:1::1");
    }

    #[test]
    fn test_rr_aaaa_to_rdata() {
        let rec = AAAA::new([0xabcd, 0xabcd, 0xabcd, 0xabcd, 0xabcd, 0xabcd, 0xabcd, 0xabcd]);
        let output = rec.to_rdata();
        let compare = vec!(0xabu8, 0xcdu8, 0xabu8, 0xcdu8, 0xabu8, 0xcdu8, 0xabu8, 0xcdu8, 0xabu8, 0xcdu8, 0xabu8, 0xcdu8, 0xabu8, 0xcdu8, 0xabu8, 0xcdu8);

        assert_eq!(output.len(), compare.len());

        for i in range(0, compare.len()) {
            assert_eq!(output[i], compare[i]);
        }

        let rec = AAAA::new([0x0123, 0x4567, 0x89ab, 0xcdef, 0x0123, 0x4567, 0x89ab, 0xcdef]);
        let output = rec.to_rdata();
        let compare = vec!(0x01u8, 0x23u8, 0x45u8, 0x67u8, 0x89u8, 0xabu8, 0xcdu8, 0xefu8, 0x01u8, 0x23u8, 0x45u8, 0x67u8, 0x89u8, 0xabu8, 0xcdu8, 0xefu8);

        assert_eq!(output.len(), 16);
        assert_eq!(output.len(), compare.len());

        for i in range(0, compare.len()) {
            assert_eq!(output[i], compare[i]);
        }
    }

    #[test]
    fn test_rr_aaaa_from_rdata() {

        let rec = AAAA::new([0x0123, 0x4567, 0x89ab, 0xcdef, 0x0123, 0x4567, 0x89ab, 0xcdef]);
        let output = rec.to_rdata();
        let compare = vec!(0x01u8, 0x23u8, 0x45u8, 0x67u8, 0x89u8, 0xabu8, 0xcdu8, 0xefu8, 0x01u8, 0x23u8, 0x45u8, 0x67u8, 0x89u8, 0xabu8, 0xcdu8, 0xefu8);

        let rec_new = RData::from_rdata(compare.as_slice(), None::<AAAA>).ok().unwrap();
        assert_eq!(rec_new, rec);
    }
}