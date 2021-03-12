use id_contact_proto::{AuthResult, AuthStatus, StartAuthRequest, StartAuthResponse, StartCommRequest, StartCommResponse};
use serde::Deserialize;

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

fn default_as_false() -> bool { false }

#[derive(Debug, Deserialize, Clone)]
pub struct CommunicationMethod {
    tag: Tag,
    name: String,
    image_path: String,
    start: String,
    #[serde(default="default_as_false")]
    disable_attributes_at_start: bool,
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

impl CommunicationMethod {
    pub async fn start(&self, purpose: &Tag) -> Result<StartCommResponse, reqwest::Error> {
        let client = reqwest::Client::new();

        Ok(client
            .post(&format!("{}/start_communication", &self.start))
            .json(&StartCommRequest {
                purpose: purpose.clone(),
                auth_result: None,
            })
            .send()
            .await?
            .json::<StartCommResponse>()
            .await?)
    }

    async fn start_with_attributes_fallback(
        &self,
        purpose: &Tag,
        auth_result: &str,
    ) -> Result<StartCommResponse, reqwest::Error> {
        let comm_data = self.start(purpose).await?;

        if let Some(attr_url) = comm_data.attr_url {
            let client = reqwest::Client::new();

            client
                .post(&attr_url)
                .header("Content-Type", "application/jwt")
                .body(auth_result.to_string())
                .send()
                .await?;

            Ok(StartCommResponse {
                client_url: comm_data.client_url,
                attr_url: None
            })
        } else {
            Ok(StartCommResponse {
                client_url: if comm_data.client_url.contains('?') {
                    format!("{}&status=succes&attributes={}", comm_data.client_url, auth_result)
                } else {
                    format!("{}?status=succes&attributes={}", comm_data.client_url, auth_result)
                },
                attr_url: None,
            })
        }
    }

    pub async fn start_with_auth_result(
        &self,
        purpose: &Tag,
        auth_result: &str,
    ) -> Result<StartCommResponse, reqwest::Error> {
        if self.disable_attributes_at_start {
            return self.start_with_attributes_fallback(purpose, auth_result).await;
        }

        let client = reqwest::Client::new();

        Ok(client
            .post(&format!("{}/start_communication", &self.start))
            .json(&StartCommRequest {
                purpose: purpose.clone(),
                auth_result: Some(auth_result.to_string()),
            })
            .send()
            .await?
            .json::<StartCommResponse>()
            .await?)
    }
}
