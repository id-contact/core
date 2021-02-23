use serde::Deserialize;
use id_contact_proto::{StartAuthRequest, StartAuthResponse, StartCommRequest, StartCommResponse};

pub type Tag = String;

pub trait Method {
    fn tag(&self) -> &Tag;
    fn name(&self) -> &str;
    fn image_path(&self) -> &str;
    fn supports(&self, purpose: &str) -> bool;
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthenticationMethod {
    tag: Tag,
    name: String,
    image_path: String,
    start: String,
}

impl AuthenticationMethod {
    pub async fn start(&self, attributes: &Vec<String>, continuation: &str, attr_url: &Option<String>) -> Result<String, reqwest::Error> {
        let client = reqwest::Client::new();

        Ok(client
            .post(&format!("{}/start_authentication", self.start))
            .json(&StartAuthRequest{
                attributes: attributes.clone(),
                continuation: continuation.to_string(),
                attr_url: attr_url.clone(),
            })
            .send()
            .await?
            .json::<StartAuthResponse>()
            .await?
            .client_url)
    }
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

#[derive(Debug, Deserialize, Clone)]
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

impl CommunicationMethod {
    pub async fn start(&self, purpose: &Tag) -> Result<StartCommResponse, reqwest::Error> {
        let client = reqwest::Client::new();

        Ok(client
            .post(&format!("{}/start_communication", &self.start))
            .json(&StartCommRequest{purpose: purpose.clone(), attributes: None})
            .send()
            .await?
            .json::<StartCommResponse>()
            .await?)
    }
}
