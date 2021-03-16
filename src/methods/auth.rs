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
}

impl AuthenticationMethod {
    pub async fn start(
        &self,
        attributes: &Vec<String>,
        continuation: &str,
        attr_url: &Option<String>,
        config: &CoreConfig,
    ) -> Result<String, Error> {
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
                continuation: continuation.to_string(),
                attr_url: attr_url.clone(),
            })
            .send()
            .await?
            .json::<StartAuthResponse>()
            .await?
            .client_url)
    }

    // Start session using fallback shim for attribute url handling
    pub async fn start_fallback(
        &self,
        attributes: &Vec<String>,
        continuation: &str,
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
                continuation: format!("{}/auth_attr_shim/{}", config.server_url(), state),
                attr_url: None,
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
