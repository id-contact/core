use std::collections::HashMap;

use crate::config::CoreConfig;

use super::{Method, Tag};
use crate::error::Error;
use id_contact_proto::{StartAuthRequest, StartAuthResponse};
use rocket::{response::Redirect, State};
use serde::Deserialize;

fn default_as_false() -> bool {
    false
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthenticationMethod {
    tag: Tag,
    name: String,
    image_path: String,
    start: String,
    #[serde(default = "default_as_false")]
    disable_attr_url: bool,
    #[serde(default = "default_as_false")]
    shim_tel_url: bool,
}

impl AuthenticationMethod {
    pub async fn start(
        &self,
        attributes: &Vec<String>,
        continuation: &str,
        attr_url: &Option<String>,
        config: &CoreConfig,
    ) -> Result<String, Error> {
        let continuation = self.parse_continuation(continuation, config);
        if let Some(attr_url) = attr_url {
            if self.disable_attr_url {
                return self
                    .start_fallback(attributes, continuation, attr_url, config)
                    .await;
            }
        }

        let client = reqwest::Client::new();

        Ok(client
            .post(&format!("{}/start_authentication", self.start))
            .json(&StartAuthRequest {
                attributes: attributes.clone(),
                continuation: continuation,
                attr_url: attr_url.clone(),
            })
            .send()
            .await?
            .error_for_status()?
            .json::<StartAuthResponse>()
            .await?
            .client_url)
    }

    // Start session using fallback shim for attribute url handling
    async fn start_fallback(
        &self,
        attributes: &Vec<String>,
        continuation: String,
        attr_url: &str,
        config: &CoreConfig,
    ) -> Result<String, Error> {
        // Prepare session state for url
        let mut state = HashMap::new();
        state.insert("attr_url".to_string(), attr_url.to_string());
        state.insert("continuation".to_string(), continuation.to_string());
        let state = config.encode_urlstate(state)?;

        // Start auth session
        let client = reqwest::Client::new();
        Ok(client
            .post(&format!("{}/start_authentication", self.start))
            .json(&StartAuthRequest {
                attributes: attributes.clone(),
                continuation: format!("{}/auth_attr_shim/{}", config.internal_url(), state),
                attr_url: None,
            })
            .send()
            .await?
            .error_for_status()?
            .json::<StartAuthResponse>()
            .await?
            .client_url)
    }

    fn parse_continuation(&self, continuation: &str, config: &CoreConfig) -> String {
        if continuation.starts_with("tel:") && self.shim_tel_url {
            format!("{}/shim/tel.html?{}", config.server_url(), urlencoding::encode(continuation))
        } else {
            continuation.to_string()
        }
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

#[get("/auth_attr_shim/<state>?<result>")]
pub async fn auth_attr_shim(
    state: String,
    result: String,
    config: State<'_, CoreConfig>,
) -> Result<Redirect, Error> {
    // Unpack session state
    let state = config.decode_urlstate(state)?;
    let attr_url = state.get("attr_url").ok_or(Error::BadRequest)?;
    let continuation = state.get("continuation").ok_or(Error::BadRequest)?;

    // Send through results
    let client = reqwest::Client::new();
    client
        .post(attr_url)
        .header("Content-Type", "application/jwt")
        .body(result)
        .send()
        .await?;

    // Redirect user
    Ok(Redirect::to(continuation.to_string()))
}
