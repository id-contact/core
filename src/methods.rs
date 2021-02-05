use serde::Deserialize;

pub type Tag = String;

pub trait Method {
    fn tag(&self) -> &Tag;
    fn name(&self) -> &String;
    fn image_path(&self) -> &String;
    fn supports(&self, purpose: &String) -> bool;
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

    fn name(&self) -> &String {
        &self.name
    }

    fn image_path(&self) -> &String {
        &self.image_path
    }

    fn supports(&self, _purpose: &String) -> bool {
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

    fn name(&self) -> &String {
        &self.name
    }

    fn image_path(&self) -> &String {
        &self.image_path
    }

    fn supports(&self, purpose: &String) -> bool {
        self.purposes.contains(purpose)
    }
}
