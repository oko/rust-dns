use std::io;
use std::fmt;

/// An RFC1035 `<domain-name>` (sequence of labels)
/// 
#[deriving(PartialEq,Eq,Hash,Clone)]
pub struct Name {
    pub labels: Vec<String>,
}

impl Name {
    pub fn new() -> Name {
        Name { labels: Vec::new() }
    }

    pub fn to_string(&self) -> String {
        format!("{}", self.labels.connect("."))
    }

    /// Parse a byte slice containing an already-decompressed name.
    pub fn parse_decompressed(buf: &[u8]) -> io::IoResult<Name> {
        let mut labels: Vec<String> = Vec::with_capacity(10);
        let mut reader = io::BufReader::new(buf);
        loop {
            let llen = try!(reader.read_u8());
            if llen == 0 {
                break;
            } else if llen > 63 {
                return Err(io::standard_error(io::InvalidInput));
            } else {
                let str_read = String::from_utf8(try!(reader.read_exact(llen as uint)));
                match str_read {
                    Ok(s) => labels.push(s),
                    Err(_) => return Err(io::standard_error(io::InvalidInput)),
                }
            }
        }
        Ok(Name { labels: labels })
    }

    /// Generate a `Vec<u8>` containing this name in fully-expanded
    /// RFC1035 label format.
    pub fn to_bytes(&self) -> io::IoResult<Vec<u8>> {
        let mut vec: Vec<u8> = Vec::new();
        for l in self.labels.iter() {
            try!(vec.write_u8(l.len() as u8));
            try!(vec.write_str(l.as_slice()));
        }
        try!(vec.write_u8(0));
        Ok(vec)
    }

    /// Push this name in fully-expanded RFC1035 label format onto an
    /// existing `Vec<u8>`
    pub fn push_bytes(&self, vec: &mut Vec<u8>) -> io::IoResult<()> {
        for l in self.labels.iter() {
            try!(vec.write_u8(l.len() as u8));
            try!(vec.write_str(l.as_slice()));
        }
        try!(vec.write_u8(0));
        Ok(())
    }

    /// Generate a vector of Name objects containing
    pub fn gen_suffixes(&self) -> Vec<Name> {
        let mut output: Vec<Name> = Vec::new();
        let mut clone = self.clone();

        for i in range(0, output.len() - 1) {
            match clone.labels.remove(0) {
                Some(_) => {
                    output.push(clone.clone());
                    continue;
                },
                None => {
                    break;
                },
            }
        }

        output
    }

    pub fn reduce(&self) -> Option<(String, Name)> {
        let mut clone = self.clone();
        match clone.labels.remove(0) {
            Some(s) => {
                Some((s, clone))
            },
            None => None,
        }
    }
}
impl fmt::Show for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.", self.labels.connect("."))
    }
}

/// Trait for `io::Reader`s that implement DNS packet parsing.
/// Due to the way DNS name compression works readers likely
/// need to implement `io::Seek`.
pub trait DNSNameReader {
    fn read_dns_name(&mut self) -> io::IoResult<Name>;
}
impl<'a> DNSNameReader for io::BufReader<'a> {
    fn read_dns_name(&mut self) -> io::IoResult<Name> {

        let mut labels: Vec<String> = Vec::new();

        let mut follow = false;
        let mut return_to = 0u64;

        // Read in labels
        loop {
            // Get the next label's size
            let llen = try!(self.read_u8());

            if llen == 0 {
                // Zero length labels are the root, so we're done
                break;
            } else if (llen & 0xC0) == 0xC0 {
                // Labels with the two high order bits set (0xC0)
                // are pointers.
                let jump_to = try!(self.read_u8()) as i64;

                // If this is the first pointer encountered, store
                // the current reader location to restore later.
                if !follow {
                    return_to = try!(self.tell());
                    follow = true;
                }

                // Seek to the pointer location
                try!(self.seek(jump_to, io::SeekStyle::SeekSet));
                continue;
            } else {
                let str_read = String::from_utf8(try!(self.read_exact(llen as uint)));
                match str_read {
                    Ok(s) => labels.push(s),
                    Err(_) => return Err(io::standard_error(io::InvalidInput)),
                }
            }
        }

        if follow {
            // Restore the reader location to the byte after the first
            // pointer followed during the read.
            try!(self.seek(return_to as i64, io::SeekStyle::SeekSet));
        }

        Ok(Name { labels: labels })
    }
}

#[cfg(test)]
mod test_dns_name_reader {
    use std::io;
    use super::DNSNameReader;

    static NET1_RS: &'static [u8] = include_bin!("../tests/packets/net1-rs.bin");

    #[test]
    fn test_read_name() {
        let mut r = io::BufReader::new(NET1_RS);

        // Regular pointerless read (first name in packet)
        r.seek(0x0C, io::SeekStyle::SeekSet).ok();
        let l1 = r.read_dns_name().ok().unwrap();
        assert_eq!(l1.labels.len(), 1);
        assert_eq!(l1.labels[0].as_slice(), "net");
    }
    #[test]
    fn test_read_single_ptr_follow() {
        let mut r = io::BufReader::new(NET1_RS);

        // Single pointer follow (second name in packet)
        r.seek(0x21, io::SeekStyle::SeekSet).ok();
        let l2 = r.read_dns_name().ok().unwrap();
        assert_eq!(l2.labels.len(), 3);
        assert_eq!(l2.labels[0].as_slice(), "m");
        assert_eq!(l2.labels[1].as_slice(), "gtld-servers");
        assert_eq!(l2.labels[2].as_slice(), "net");
    }
    #[test]
    fn test_read_multi_ptr_follow() {
        let mut r = io::BufReader::new(NET1_RS);

        // Multi-pointer follow (nth name in packet)
        r.seek(0x5e, io::SeekStyle::SeekSet).ok();
        let l2 = r.read_dns_name().ok().unwrap();
        assert_eq!(l2.labels.len(), 3);
        assert_eq!(l2.labels[0].as_slice(), "j");
        assert_eq!(l2.labels[1].as_slice(), "gtld-servers");
        assert_eq!(l2.labels[2].as_slice(), "net");
        // Test seek restoration after multi-pointer follow
        let l1 = r.read_dns_name().ok().unwrap();
        assert_eq!(l1.labels.len(), 1);
        assert_eq!(l1.labels[0].as_slice(), "net");
    }
}