use std::io;
use std::fmt;

#[deriving(PartialEq,Clone)]
pub struct Name {
    labels: Vec<String>,
}

impl Name {
    pub fn new() -> Name {
        Name { labels: Vec::new() }
    }
}
impl fmt::Show for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(f, "{}", self.labels.connect(".")));
        write!(f, ".")
    }
}

pub trait DNSNameReader {
    fn read_dns_name(&mut self) -> io::IoResult<Name>;
}
impl<'a> DNSNameReader for io::BufReader<'a> {
    fn read_dns_name(&mut self) -> io::IoResult<Name> {

        let mut labels: Vec<String> = Vec::new();

        let mut follow = false;
        let mut return_to = 0u64;

        loop {
            let llen = try!(self.read_u8());

            if llen == 0 {
                break;
            } else if (llen & 0xC0) == 0xC0 {
                let jump_to = try!(self.read_u8()) as i64;
                if !follow {
                    return_to = try!(self.tell());
                    follow = true;
                }
                self.seek(jump_to, io::SeekStyle::SeekSet);
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
            try!(self.seek(return_to as i64, io::SeekStyle::SeekSet));
        }

        Ok(Name { labels: labels })
    }
}