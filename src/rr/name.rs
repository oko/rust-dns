pub use super::RData;

use std::io;

#[deriving(Show)]
pub struct Name {
	labels: Vec<String>,
}
impl RData for Name {
    fn to_rdata(&self) -> Vec<u8> {
    	let mut output: Vec<u8> = Vec::new();
    	for label in self.labels.iter() {
    		output.write_u8(label.len() as u8).ok();
    		output.write_str(label.as_slice()).ok();
    	}
    	output.write_u8(0);
    	output
    }
    fn from_rdata(rdata: &mut [u8], _ignored: Option<Name>) -> Result<Name, &'static str> {
    	let mut reader = io::BufReader::new(rdata);
    	let mut output: Vec<String> = Vec::new();
    	let i = 0u;
    	while i < rdata.len() {
    		let llen = reader.read_u8().unwrap() & 0x3f;
    		if llen == 0 { break; }
    		let lread = String::from_utf8(reader.read_exact(llen as uint).unwrap());
    		match lread {
    			Ok(ldata) => output.push(ldata),
    			Err(_) => return Err("failed to read label"),
    		};
    	}
    	Ok(Name { labels: output })
    }
}

#[cfg(test)]
mod test_name {
	use super::{RData,Name};
	#[test]
	fn test_name_rdata() {
		let mut compare = vec!(0x08u8, 0x66u8, 0x61u8, 0x63u8, 0x65u8, 0x62u8, 0x6fu8, 0x6fu8, 0x6bu8, 0x03u8, 0x63u8, 0x6fu8, 0x6du8, 0x00u8);
		let name = RData::from_rdata(compare.as_mut_slice(), None::<Name>).unwrap();
		for label in name.labels.iter() {
			println!("{}", label);
		}
	}
}