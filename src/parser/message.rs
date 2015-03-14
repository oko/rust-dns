use super::Type;
use super::Class;
use super::RCode;
use super::OpCode;
use super::errors;

use std::fmt;
use std::cmp;
use std::cmp::Ordering;

pub struct Message<'n> {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question<'n>>,
    pub answers: Vec<ResourceRecord<'n>>,
    pub nameservers: Vec<ResourceRecord<'n>>,
    pub additionals: Vec<ResourceRecord<'n>>,
}

#[derive(PartialEq,Debug,Clone)]
pub struct Question<'n> {
    pub qname: Name<'n>,
    pub qtype: Type,
    pub qclass: Class,
}

#[derive(PartialEq,Debug,Clone)]
pub struct ResourceRecord<'n> {
    pub rname: Name<'n>,
    pub rtype: Type,
    pub rclass: Class,
    pub rttl: i32,
    pub rdlen: u16,
    pub rdata: usize,
    pub context: &'n [u8],
}

/// A DNS domain name.
///
/// Domain names consist of a sequence of labels, each between 1 and 63
/// octets in length, which have a total length of less than 255 octets.
/// Due to wire format limitations and the implicit terminating root
/// label, the effective upper limit on name length is less than 255
/// octets.
#[derive(PartialEq,Eq,Hash,Debug,Clone)]
pub struct Name<'n> {
    labels: Vec<Label<'n>>,
}
impl<'n> Name<'n> {
    #[inline]
    pub fn to_string(&self) -> String {
        format!("{:?}", self)
    }

    /// Parse a DNS name from the RDATA section of a DNS resource record.
    /// The `context` field in the `ResourceRecord` struct exists so that
    /// this function can properly follow pointers.
//    pub fn from_rdata<'r>(rr: &'r ResourceRecord) -> Result<Name<'r>, errors::ReadError> {
//        let mut i = rr.rdata;
//        read_dns_name(rr.context, &mut i)
//    }
    fn from_str(s: &'n str) -> Result<Name, errors::ReadError> {
        let mut n = Name { labels: Vec::new() };
        for x in s.split('.') {
            if x.len() == 0 { continue; }
            n.labels.push(try!(Label::from_slice(x.as_bytes())));
        }
        Ok(n)
    }
}
impl<'n> fmt::Display for Name<'n> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.labels.len() > 0 {
            for l in self.labels.iter() {
                try!(write!(f, "{}.", l));
            }
            write!(f, "")
        } else {
            write!(f, ".")
        }
    }
}
impl<'n> cmp::PartialOrd for Name<'n> {
    fn partial_cmp(&self, other: &Name<'n>) -> Option<Ordering> {
        let sl = self.labels.len();
        let ol = other.labels.len();
        let mut case = Ordering::Equal;
        let max_depth = cmp::min(sl, ol);
        for i in range(1, max_depth + 1) {
            if self.labels[sl - i] == other.labels[ol - i] {
                if self.labels[sl - i] < other.labels[ol - i] {
                    case = Ordering::Less;
                } else if self.labels[sl - i] > other.labels[ol - i] {
                    case = Ordering::Greater;
                } else {
                    continue;
                }
            } else if self.labels[sl - i] < other.labels[ol - i] {
                return Some(Ordering::Less);
            } else if self.labels[sl - i] > other.labels[ol - i] {
                return Some(Ordering::Greater);
            }
        }
        if sl > ol {
            Some(Ordering::Greater)
        } else if sl < ol {
            Some(Ordering::Less)
        } else {
            Some(case)
        }
    }
}

/// A DNS domain name label.
///
/// A label may consist of between 1 and 63 octets of any value `0x00`
/// to `0xFF`
#[derive(Eq,Hash,Debug,Clone)]
pub struct Label<'l> {
    label: &'l [u8],
}

impl<'l> Label<'l> {
    fn from_slice(slice: &'l [u8]) -> Result<Label, errors::ReadError> {
        if slice.len() > 63 { return Err(errors::ReadError::LabelTooLongError(slice.len())); }
        if slice.len() == 0 { return Err(errors::ReadError::LabelZeroLengthError); }
        Ok(Label { label: slice, })
    }
}
impl<'l> fmt::Display for Label<'l> {

    /// Formats a label, escaping non-printing characters and "." as per
    /// [RFC4343§2.1](https://tools.ietf.org/html/rfc4343#section-2.1)
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for c in self.label.iter() {
            match *c {
                // Non-printing character ranges are shown as \XXX
                // where XXX is the char's zero-padded decimal repr
                x @ 0x00...0x20 | x @ 0x7F...0xFF | x @ 0x2E => {
                    try!(write!(f, "\\{:03}", x));
                },
                // Printing character ranges are shown as is
                x @ 0x21...0x2D | x @ 0x2F...0x7E => {
                    try!(write!(f, "{}", x as char));
                },
                _ => {
                    return Err(fmt::Error);
                },
            }
        }
        write!(f, "")
    }
}
impl<'l> cmp::PartialEq for Label<'l> {

    /// Domain names are compared for equality case-insensitively for
    /// alphabetic characters (`0x41...0x5A`, `0x61...0x71`).
    fn eq(&self, other: &Label) -> bool {
        let sl = self.label.len();
        let ol = other.label.len();
        if sl != ol { return false; }
        for i in range(0, cmp::min(sl, ol)) {
            match self.label[i] {
                x @ 0x41...0x5A => {
                    // Compare uppercase letters case-insensitively
                    if x == other.label[i] || (x + 32) == other.label[i] { continue; } else { return false; }
                },
                x @ 0x61...0x7A => {
                    // Compare lowercase letters case-insensitively
                    if x == other.label[i] || (x - 32) == other.label[i] { continue; } else { return false; }
                },
                x @ _ => {
                    // Direct equality for non-alphabetic characters
                    if x == other.label[i] { continue; } else { return false; }
                }
            }
        }
        true
    }
}
impl<'l> cmp::PartialOrd for Label<'l> {

    /// Domain names are compared for ordering based on the ordinal
    /// values of characters (i.e., 'A' is hex `0x41`, and 'a' is hex `0x61`,
    /// so 'A' orders before 'a')
    fn partial_cmp(&self, other: &Label) -> Option<Ordering> {
        let sl = self.label.len();
        let ol = other.label.len();
        let mut caps = Ordering::Equal;

        // Don't try to compare outside bounds if one label is shorter
        for i in range(0, cmp::min(sl, ol)) {
            let sli = self.label[i];
            let oli = other.label[i];
            // Strip casing from [a-z] characters for comparison
            let sll = if 0x61 <= sli && sli <= 0x7A { sli - 32 } else { sli };
            let oll = if 0x61 <= oli && oli <= 0x7A { oli - 32 } else { oli };

            if sll < oll {
                return Some(Ordering::Less);
            } else if sll > oll {
                return Some(Ordering::Greater);
            } else {
                if caps == Ordering::Equal {
                    if sli < oli {
                        caps = Ordering::Less;
                    } else if sli > oli {
                        caps = Ordering::Greater;
                    }
                }
            }
        }
        if sl > ol { Some(Ordering::Greater) }
        else if sl < ol { Some(Ordering::Less) }
        else { Some(caps) }
    }
}
