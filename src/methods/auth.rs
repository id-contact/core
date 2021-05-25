use std::{collections::HashMap, time::Duration};

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

        let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?;

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
        let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?;
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
            format!(
                "{}/shim/tel.html?{}",
                config.server_url(),
                urlencoding::encode(continuation)
            )
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
    let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?;
    client
        .post(attr_url)
        .header("Content-Type", "application/jwt")
        .body(result)
        .send()
        .await?;

    // Redirect user
    Ok(Redirect::to(continuation.to_string()))
}

#[cfg(test)]
mod tests {
    use figment::providers::{Format, Toml};
    use httpmock::MockServer;
    use id_contact_proto::StartAuthRequest;
    use serde_json::json;
    use rocket::figment::Figment;

    use crate::config::CoreConfig;

    const TEST_CONFIG_VALID: &'static str = r#"
[global]
server_url = "https://core.idcontact.test.tweede.golf"
internal_url = "http://core:8000"
internal_secret = "sample_secret_1234567890178901237890"


[[global.auth_methods]]
tag = "irma"
name = "Gebruik je IRMA app"
image_path = "/static/irma.svg"
start = "http://auth-irma:8000"

[[global.auth_methods]]
tag = "digid"
name = "Gebruik DigiD"
image_path = "/static/digid.svg"
start = "http://auth-test:8000"


[[global.comm_methods]]
tag = "call"
name = "Bellen"
image_path = "/static/phone.svg"
start = "http://comm-test:8000"

[[global.comm_methods]]
tag = "chat"
name = "Chatten"
image_path = "/static/chat.svg"
start = "http://comm-matrix-bot:3000"


[[global.purposes]]
tag = "report_move"
attributes = [ "email" ]
allowed_auth = [ "*" ]
allowed_comm = [ "call", "chat" ]

[[global.purposes]]
tag = "request_permit"
attributes = [ "email" ]
allowed_auth = [ "irma", "digid" ]
allowed_comm = [ "*" ]

[[global.purposes]]
tag = "request_passport"
attributes = [ "email" ]
allowed_auth = [ "irma" ]
allowed_comm = [ "call" ]

"#;

    #[test]
    fn test_start_with_attr_url() {
        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(Toml::string(TEST_CONFIG_VALID).nested());
        
        let config = figment.extract::<CoreConfig>().unwrap();

        let server = MockServer::start();
        let start_mock = server.mock(|when, then | {
            when.path("/start_authentication")
                .method(httpmock::Method::POST)
                .json_body(json!({
                    "attributes": [
                        "email",
                    ],
                    "attr_url": "https://example.com/attr_url",
                    "continuation": "https://example.com/continuation",
                }));
            then.status(200)
                .header("Content-Type", "application/json")
                .json_body(json!({
                    "client_url": "https://example.com/client_url",
                }));
        });

        let method = super::AuthenticationMethod{
            tag: "test".into(),
            name: "test".into(),
            image_path: "none".into(),
            start: server.base_url(),
            disable_attr_url: false,
            shim_tel_url: false,
        };

        let result = tokio_test::block_on(
            method.start(
                &vec!["email".into()], 
                "https://example.com/continuation", 
                &Some("https://example.com/attr_url".into()), 
                &config)).unwrap();
        
        assert_eq!(result, "https://example.com/client_url");
        start_mock.assert();
    }

    #[test]
    fn test_start_without_attr_url() {
        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(Toml::string(TEST_CONFIG_VALID).nested());
        
        let config = figment.extract::<CoreConfig>().unwrap();

        let server = MockServer::start();
        let start_mock = server.mock(|when, then | {
            when.path("/start_authentication")
                .method(httpmock::Method::POST)
                .json_body(json!({
                    "attributes": [
                        "email",
                    ],
                    "continuation": "https://example.com/continuation",
                }));
            then.status(200)
                .header("Content-Type", "application/json")
                .json_body(json!({
                    "client_url": "https://example.com/client_url",
                }));
        });

        let method = super::AuthenticationMethod{
            tag: "test".into(),
            name: "test".into(),
            image_path: "none".into(),
            start: server.base_url(),
            disable_attr_url: false,
            shim_tel_url: false,
        };

        let result = tokio_test::block_on(
            method.start(
                &vec!["email".into()], 
                "https://example.com/continuation", 
                &None, 
                &config)).unwrap();
        
        assert_eq!(result, "https://example.com/client_url");
        start_mock.assert();
    }

    #[test]
    fn test_attr_shim_start() {
        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(Toml::string(TEST_CONFIG_VALID).nested());
        
        let config = figment.extract::<CoreConfig>().unwrap();

        let server = MockServer::start();
        let start_mock = server.mock(|when, then | {
            when.path("/start_authentication")
                .method(httpmock::Method::POST)
                .matches(|req| {
                    if let Some(body) = &req.body {
                        let body = serde_json::from_slice::<StartAuthRequest>(body);
                        if let Ok(body) = body {
                            body.attr_url == None &&
                            body.continuation != "https://example.com/continuation" &&
                            body.attributes == vec!["email"]
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                });
            then.status(200)
                .header("Content-Type", "application/json")
                .json_body(json!({
                    "client_url": "https://example.com/client_url",
                }));
        });

        let method = super::AuthenticationMethod{
            tag: "test".into(),
            name: "test".into(),
            image_path: "none".into(),
            start: server.base_url(),
            disable_attr_url: true,
            shim_tel_url: false,
        };

        let result = tokio_test::block_on(
            method.start(
                &vec!["email".into()], 
                "https://example.com/continuation", 
                &Some("https://example.com/attr_url".into()), 
                &config));
        
        start_mock.assert();
        assert_eq!(result.unwrap(), "https://example.com/client_url");
    }

    #[test]
    fn test_tel_shim_start_tel() {
        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(Toml::string(TEST_CONFIG_VALID).nested());
        
        let config = figment.extract::<CoreConfig>().unwrap();

        let server = MockServer::start();
        let start_mock = server.mock(|when, then | {
            when.path("/start_authentication")
                .method(httpmock::Method::POST)
                .matches(|req| {
                    if let Some(body) = &req.body {
                        let body = serde_json::from_slice::<StartAuthRequest>(body);
                        if let Ok(body) = body {
                            body.attr_url == Some("https://example.com/attr_url".into()) &&
                            body.continuation != "tel:0123456789" &&
                            body.attributes == vec!["email"]
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                });
            then.status(200)
                .header("Content-Type", "application/json")
                .json_body(json!({
                    "client_url": "https://example.com/client_url",
                }));
        });

        let method = super::AuthenticationMethod{
            tag: "test".into(),
            name: "test".into(),
            image_path: "none".into(),
            start: server.base_url(),
            disable_attr_url: false,
            shim_tel_url: true,
        };

        let result = tokio_test::block_on(
            method.start(
                &vec!["email".into()], 
                "tel:0123456789", 
                &Some("https://example.com/attr_url".into()), 
                &config));
        
        start_mock.assert();
        assert_eq!(result.unwrap(), "https://example.com/client_url");
    }

    #[test]
    fn test_tel_shim_nontel() {
        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(Toml::string(TEST_CONFIG_VALID).nested());
        
        let config = figment.extract::<CoreConfig>().unwrap();

        let server = MockServer::start();
        let start_mock = server.mock(|when, then | {
            when.path("/start_authentication")
                .method(httpmock::Method::POST)
                .json_body(json!({
                    "attributes": [
                        "email",
                    ],
                    "attr_url": "https://example.com/attr_url",
                    "continuation": "https://example.com/continuation",
                }));
            then.status(200)
                .header("Content-Type", "application/json")
                .json_body(json!({
                    "client_url": "https://example.com/client_url",
                }));
        });

        let method = super::AuthenticationMethod{
            tag: "test".into(),
            name: "test".into(),
            image_path: "none".into(),
            start: server.base_url(),
            disable_attr_url: false,
            shim_tel_url: true,
        };

        let result = tokio_test::block_on(
            method.start(
                &vec!["email".into()], 
                "https://example.com/continuation", 
                &Some("https://example.com/attr_url".into()), 
                &config)).unwrap();
        
        assert_eq!(result, "https://example.com/client_url");
        start_mock.assert();
    }
}
