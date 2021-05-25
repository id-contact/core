use std::time::Duration;

use super::{Method, Tag};
use id_contact_proto::{StartCommRequest, StartCommResponse};
use serde::Deserialize;

fn default_as_false() -> bool {
    false
}

#[derive(Debug, Deserialize, Clone)]
pub struct CommunicationMethod {
    tag: Tag,
    name: String,
    image_path: String,
    start: String,
    #[serde(default = "default_as_false")]
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
    // Start a communication session to be composed with an authentication session
    pub async fn start(&self, purpose: &Tag) -> Result<StartCommResponse, reqwest::Error> {
        let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?;

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

    // Falback for plugins not supporting attribute reception on startup
    async fn start_with_attributes_fallback(
        &self,
        purpose: &Tag,
        auth_result: &str,
    ) -> Result<StartCommResponse, reqwest::Error> {
        let comm_data = self.start(purpose).await?;

        if let Some(attr_url) = comm_data.attr_url {
            let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?;

            client
                .post(&attr_url)
                .header("Content-Type", "application/jwt")
                .body(auth_result.to_string())
                .send()
                .await?;

            Ok(StartCommResponse {
                client_url: comm_data.client_url,
                attr_url: None,
            })
        } else {
            Ok(StartCommResponse {
                client_url: if comm_data.client_url.contains('?') {
                    format!(
                        "{}&status=succes&attributes={}",
                        comm_data.client_url, auth_result
                    )
                } else {
                    format!(
                        "{}?status=succes&attributes={}",
                        comm_data.client_url, auth_result
                    )
                },
                attr_url: None,
            })
        }
    }

    // Start a communication session for which we already have authentication results.
    pub async fn start_with_auth_result(
        &self,
        purpose: &Tag,
        auth_result: &str,
    ) -> Result<StartCommResponse, reqwest::Error> {
        if self.disable_attributes_at_start {
            return self
                .start_with_attributes_fallback(purpose, auth_result)
                .await;
        }

        let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?;

        Ok(client
            .post(&format!("{}/start_communication", &self.start))
            .json(&StartCommRequest {
                purpose: purpose.clone(),
                auth_result: Some(auth_result.to_string()),
            })
            .send()
            .await?
            .error_for_status()?
            .json::<StartCommResponse>()
            .await?)
    }
}
