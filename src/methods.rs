use serde::{Deserialize,Serialize};

pub type Tag = String;

pub trait Method {
    fn tag(&self) -> &Tag;
    fn name(&self) -> &str;
    fn image_path(&self) -> &str;
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthenticationMethod {
    tag: Tag,
    name: String,
    image_path: String,
    start: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthRequest {
    attributes: Vec<String>,
    continuation: String,
    attr_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StartAuthResponse {
    client_url: String,
}

impl AuthenticationMethod {
    pub async fn start(&self, attributes: &Vec<String>, continuation: &str, attr_url: &Option<String>) -> Result<String, reqwest::Error> {
        let client = reqwest::Client::new();

        Ok(client
            .post(&format!("{}/start_authentication", self.start))
            .json(&AuthRequest{
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
}

#[derive(Debug, Deserialize, Clone)]
pub struct CommunicationMethod {
    tag: Tag,
    name: String,
    image_path: String,
    start: String,
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
}

#[derive(Debug, Serialize)]
struct StartCommRequest {
    purpose: Tag,
}

#[derive(Debug, Deserialize)]
pub struct StartCommResponse {
    pub client_url: String,
    pub attr_url: Option<String>,
}

impl CommunicationMethod {
    pub async fn start(&self, purpose: &Tag) -> Result<StartCommResponse, reqwest::Error> {
        let client = reqwest::Client::new();

        Ok(client
            .post(&format!("{}/start_communication", &self.start))
            .json(&StartCommRequest{purpose: purpose.clone()})
            .send()
            .await?
            .json::<StartCommResponse>()
            .await?)
    }
}
