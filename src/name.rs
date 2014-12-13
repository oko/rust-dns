
#[deriving(PartialEq,Show)]
pub struct Name {
    labels: Vec<String>,
}

impl Name {
    pub fn new() -> Name {
        Name { labels: Vec::new() }
    }
}