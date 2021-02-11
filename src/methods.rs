use serde::Deserialize;

pub type Tag = String;

pub trait Method {
    fn tag(&self) -> &Tag;
    fn name(&self) -> &str;
    fn image_path(&self) -> &str;
    fn supports(&self, purpose: &str) -> bool;
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationMethod {
    tag: Tag,
    name: String,
    image_path: String,
    start: String,
}

impl Method for AuthenticationMethod {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn image_path(&self) -> &str {
        &self.image_path
    }

    fn supports(&self, _purpose: &str) -> bool {
        true
    }
}

#[derive(Debug, Deserialize)]
pub struct CommunicationMethod {
    tag: Tag,
    name: String,
    image_path: String,
    start: String,
    purposes: Vec<String>,
}

impl Method for CommunicationMethod {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn image_path(&self) -> &str {
        &self.image_path
    }

    fn supports(&self, purpose: &str) -> bool {
        self.purposes.contains(&purpose.to_string())
    }
}
