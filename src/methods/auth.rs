use super::{Method, Tag};
use id_contact_proto::{StartAuthRequest, StartAuthResponse};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct AuthenticationMethod {
    tag: Tag,
    name: String,
    image_path: String,
    start: String,
}

impl AuthenticationMethod {
    pub async fn start(
        &self,
        attributes: &Vec<String>,
        continuation: &str,
        attr_url: &Option<String>,
    ) -> Result<String, reqwest::Error> {
        let client = reqwest::Client::new();

        Ok(client
            .post(&format!("{}/start_authentication", self.start))
            .json(&StartAuthRequest {
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
