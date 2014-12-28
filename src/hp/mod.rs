pub use super::number::types::Type;
pub use super::number::classes::Class;
pub use super::number::rcodes::RCode;
pub use super::number::opcodes::OpCode;
pub use super::number::errors::IdentifierError;

use std::fmt;
use std::cmp;
use std::str;

use self::util::{_read_be_u16,_read_be_i32};

mod util;
mod err;

#[deriving(PartialEq,Show,Clone)]
pub struct Message<'n> {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question<'n>>,
    pub answers: Vec<ResourceRecord<'n>>,
    pub nameservers: Vec<ResourceRecord<'n>>,
    pub additionals: Vec<ResourceRecord<'n>>,
}

#[deriving(PartialEq,Show,Clone)]
pub struct Question<'n> {
    pub qname: Name<'n>,
    pub qtype: Type,
    pub qclass: Class,
}

#[deriving(PartialEq,Show,Clone)]
pub struct ResourceRecord<'n> {
    pub rname: Name<'n>,
    pub rtype: Type,
    pub rclass: Class,
    pub rttl: i32,
    pub rdlen: u16,
    pub rdata: uint,
    pub context: &'n [u8],
}

/// A DNS domain name.
/// 
/// Domain names consist of a sequence of labels, each between 1 and 63
/// octets in length, which have a total length of less than 255 octets.
/// Due to wire format limitations and the implicit terminating root
/// label, the effective upper limit on name length is less than 255
/// octets.
#[deriving(PartialEq,Eq,Hash,Clone)]
pub struct Name<'n> {
    labels: Vec<Label<'n>>,
}
impl<'n> Name<'n> {
    #[inline]
    pub fn to_string(&self) -> String {
        format!("{}", self)
    }

    /// Parse a DNS name from the RDATA section of a DNS resource record.
    /// The `context` field in the `ResourceRecord` struct exists so that
    /// this function can properly follow pointers.
    pub fn from_rdata<'r>(rr: &'r ResourceRecord) -> Result<Name<'r>, err::ReadError> {
        let mut i = rr.rdata;
        read_dns_name(rr.context, &mut i)
    }
    fn from_str(s: &'n str) -> Result<Name, err::ReadError> {
        let mut n = Name { labels: Vec::new() };
        for x in s.split('.') {
            if x.len() == 0 { continue; }
            n.labels.push(try!(Label::from_slice(x.as_bytes())));
        }
        Ok(n)
    }
}
impl<'n> fmt::Show for Name<'n> {
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
        println!("START CMP");
        println!("{} : {}", self, other);
        let sl = self.labels.len();
        let ol = other.labels.len();
        let mut case = Equal;
        let max_depth = cmp::min(sl, ol);
        for i in range(1, max_depth + 1) {
            println!("{} : {}", self.labels[sl - i], other.labels[ol - i]);
            if self.labels[sl - i] == other.labels[ol - i] {
                println!("label at -{} eq", i);
                if self.labels[sl - i] < other.labels[ol - i] {
                    case = Less;
                } else if self.labels[sl - i] > other.labels[ol - i] {
                    case = Greater;
                } else {
                    continue;
                }
            } else if self.labels[sl - i] < other.labels[ol - i] {
                println!("label at -{} self smaller", i);
                return Some(Less);
            } else if self.labels[sl - i] > other.labels[ol - i] {
                println!("labels at -{} self larger", i);
                return Some(Greater);
            }
        }
        if sl > ol {
            Some(Greater)
        } else if sl < ol {
            Some(Less)
        } else {
            Some(case)
        }
    }
}

/// A DNS domain name label.
///
/// A label may consist of between 1 and 63 octets of any value `0x00`
/// to `0xFF`
#[deriving(Eq,Hash,Clone)]
pub struct Label<'l> {
    label: &'l [u8],
}

impl<'l> Label<'l> {
    fn from_slice(slice: &'l [u8]) -> Result<Label, err::ReadError> {
        if slice.len() > 63 { return Err(err::ReadError::LabelTooLongError(slice.len())); }
        if slice.len() == 0 { return Err(err::ReadError::LabelZeroLengthError); }
        Ok(Label { label: slice, })
    }
}
impl<'l> fmt::Show for Label<'l> {

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
        let mut caps = Equal;

        // Don't try to compare outside bounds if one label is shorter
        for i in range(0, cmp::min(sl, ol)) {
            let sli = self.label[i];
            let oli = other.label[i];
            // Strip casing from [a-z] characters for comparison
            let sll = if 0x61 <= sli && sli <= 0x7A { sli - 32 } else { sli };
            let oll = if 0x61 <= oli && oli <= 0x7A { oli - 32 } else { oli };

            if sll < oll {
                return Some(Less);
            } else if sll > oll {
                return Some(Greater);
            } else {
                if caps == Equal {
                    if sli < oli {
                        caps = Less;
                    } else if sli > oli {
                        caps = Greater;
                    }
                }
            }
        }
        if sl > ol { Some(Greater) }
        else if sl < ol { Some(Less) }
        else { Some(caps) }
    }
}
// impl<'l> cmp::Ord for Label<'l> {

//     /// Domain names are compared for ordering based on the ordinal
//     /// values of characters (i.e., 'A' is hex `0x41`, and 'a' is hex `0x61`,
//     /// so 'A' orders before 'a')
//     fn cmp(&self, other: &Label) -> Ordering {
//         let sl = self.label.len();
//         let ol = other.label.len();

//         // Don't try to compare outside bounds if one label is shorter
//         for i in range(0, cmp::min(sl, ol)) {
//             let sli = self.label[i];
//             let oli = other.label[i];
//             // Order by value
//             match sli {
//                 x @ 0x61...0x7A => {
//                     // Compare lowercase letters case-insensitively
//                     match oli {
//                         y @ 0x41...0x5A => {
//                             if (x - 32) < y { return Less; }
//                             else { return Greater; }
//                         },
//                         y @ _ => {
//                             if x < y { return Less; }
//                             else if y > x { return Greater; }
//                             else { continue; }
//                         }
//                     }
//                 },
//                 _ => {
//                     if sli > oli { return Greater; }
//                     else if sli < oli { return Less; }
//                     else { continue; }
//                 }
//             }
//         }
//         // If 
//         if sl > ol { Greater }
//         else if sl < ol { Less }
//         else { Equal }
//     }
// }

/// Read a DNS message from a `&[u8]` buffer.
pub fn read_dns_message<'b>(buf: &'b [u8]) -> Result<Message<'b>, err::ReadError> {
    if buf.len() < 12 {
        return Err(err::ReadError::IndexOutOfRangeError(12, buf.len()));
    }
    let mut i = 0u;
    let id = _read_be_u16(buf, &mut i);
    let flags = _read_be_u16(buf, &mut i);
    let qdcount = _read_be_u16(buf, &mut i);
    let ancount = _read_be_u16(buf, &mut i);
    let nscount = _read_be_u16(buf, &mut i);
    let adcount = _read_be_u16(buf, &mut i);
    
    let mut msg = Message {
        id: id,
        flags: flags,
        questions: Vec::new(),
        answers: Vec::new(),
        nameservers: Vec::new(),
        additionals: Vec::new(),
    };


    for n in range(0, qdcount) { msg.questions.push(try!(read_dns_question(buf, &mut i))) }
    for n in range(0, ancount) { msg.answers.push(try!(read_dns_resource_record(buf, &mut i))) }
    for n in range(0, nscount) { msg.nameservers.push(try!(read_dns_resource_record(buf, &mut i))) }
    for n in range(0, adcount) { msg.additionals.push(try!(read_dns_resource_record(buf, &mut i))) }

    
    Ok(msg)
}

/// Read a single DNS question from a buffer
#[inline(always)]
fn read_dns_question<'b>(buf: &'b [u8], idx: &mut uint) -> Result<Question<'b>, err::ReadError> {
    let mut q = Question {
        qname: try!(read_dns_name(buf, idx)),
        qtype: Type::A,
        qclass: Class::IN,
    };
    // Check bounds before reading fixed-length question data
    if *idx + 4 > buf.len() {
        return Err(err::ReadError::IndexOutOfRangeError(*idx + 4, buf.len()));
    }
    q.qtype = try!(Type::from_u16(_read_be_u16(buf, idx)));
    q.qclass = try!(Class::from_u16(_read_be_u16(buf, idx)));
    Ok(q)
}

/// Read a single DNS resource record from a `&[u8]` buffer
#[inline(always)]
fn read_dns_resource_record<'b>(buf: &'b [u8], idx: &mut uint) -> Result<ResourceRecord<'b>, err::ReadError> {
    let mut r = ResourceRecord {
        rname: try!(read_dns_name(buf, idx)),
        rtype: Type::A,
        rclass: Class::IN,
        rttl: 0,
        rdlen: 0,
        rdata: *idx,
        context: buf,
    };
    // Check bounds before reading fixed-length RR data
    if *idx + 10 >= buf.len() {
        return Err(err::ReadError::IndexOutOfRangeError(*idx + 10, buf.len()));
    }
    r.rtype = try!(Type::from_u16(_read_be_u16(buf, idx)));
    r.rclass = try!(Class::from_u16(_read_be_u16(buf, idx)));
    r.rttl = _read_be_i32(buf, idx);
    r.rdlen = _read_be_u16(buf, idx);
    r.rdata = *idx;
    *idx += r.rdlen as uint;
    // Check bounds of RDLEN/RDATA against buffer size
    if *idx > buf.len() {
        return Err(err::ReadError::IndexOutOfRangeError(*idx, buf.len()));
    }
    Ok(r)
}

/// Read a single DNS name from a `&[u8]` buffer
#[inline(always)]
fn read_dns_name<'b>(buf: &'b [u8], idx: &mut uint) -> Result<Name<'b>, err::ReadError> {
    // Pre-check bounds (min 1 byte for root label)
    if *idx + 1 > buf.len() {
        return Err(err::ReadError::IndexOutOfRangeError(*idx + 1, buf.len()));
    }

    let mut labels: Vec<Label> = Vec::with_capacity(8);

    let mut follow = false;
    let mut return_to = 0u;
    let mut pcount = 0u;
    let blen = buf.len();
    // Read in labels
    loop {
        // Check bounds for next label
        if *idx + 1 > buf.len() {
            return Err(err::ReadError::IndexOutOfRangeError(*idx + 1, buf.len()));
        }
        // Get the next label's size
        let llen = buf[*idx];
        // Get offset (clear upper 2 bits of label size)
        let offset = 1 + ((llen & 0x3F) as uint);

        if llen == 0 || pcount > 255 {
            // Zero length labels are the root, so we're done

            // If we've gone through more than 255 pointers something
            // isn't right and we should bail.

            break;
        } else if (llen & 0xC0) == 0xC0 && (*idx + 1) < blen {
            // Labels with the two high order bits set (0xC0)
            // are pointers.

            // If this is the first pointer encountered, store
            // the current reader location to restore later.
            if !follow {
                return_to = *idx+2;
                follow = true;
            }
            pcount += 1;

            // Seek to the pointer location
            *idx = buf[*idx+1] as uint;
            continue;
        } else if (*idx + offset) >= blen {
            return Err(err::ReadError::IndexOutOfRangeError(*idx + offset, blen));
        } else {
            let new_label = buf[*idx+1..*idx+offset];
            *idx += offset;
            labels.push(try!(Label::from_slice(new_label)));
        }
    }

    if follow {
        // Restore the reader location to the byte after the first
        // pointer followed during the read.
        *idx = return_to;
    } else {
        // Or just push the index up by one if we aren't reading.
        *idx += 1;
    }

    Ok(Name { labels: labels })
}

#[cfg(test)]
mod tests;