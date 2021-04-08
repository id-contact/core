use std::collections::HashMap;

use crate::methods::{Method, Tag};
use crate::{config::CoreConfig, error::Error};
use rocket::State;
use rocket_contrib::json::Json;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct MethodProperties {
    tag: Tag,
    name: String,
    image_path: String,
}

impl MethodProperties {
    fn filter_methods_by_tags<'a, T: Method, I: Iterator<Item = &'a String>>(
        tags: I,
        methods: &HashMap<String, T>,
    ) -> Result<Vec<MethodProperties>, Error> {
        tags.map(|t| {
            let method = methods
                .get(t)
                .ok_or_else(|| Error::NoSuchMethod(t.clone()))?;
            Ok(MethodProperties {
                tag: String::from(method.tag()),
                name: String::from(method.name()),
                image_path: String::from(method.image_path()),
            })
        })
        .collect()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionOptions {
    auth_methods: Vec<MethodProperties>,
    comm_methods: Vec<MethodProperties>,
}

#[get("/session_options/<purpose>")]
pub fn session_options(
    purpose: String,
    config: State<CoreConfig>,
) -> Result<Json<SessionOptions>, Error> {
    let purpose = config
        .purposes
        .get(&purpose)
        .ok_or_else(|| Error::NoSuchPurpose(purpose.clone()))?;
    let auth_methods = MethodProperties::filter_methods_by_tags(
        purpose.allowed_auth.iter(),
        &config.auth_methods,
    )?;
    let comm_methods = MethodProperties::filter_methods_by_tags(
        purpose.allowed_comm.iter(),
        &config.comm_methods,
    )?;

    Ok(Json(SessionOptions {
        auth_methods,
        comm_methods,
    }))
}

#[cfg(test)]
mod tests {
    use rocket::{http::Status, local::blocking::Client};

    use super::SessionOptions;
    use crate::config::CoreConfig;
    use crate::rocket;

    const TEST_CONFIG_VALID: &'static str = r#"
server_url: https://core.idcontact.test.tweede.golf
internal_url: http://core:8000
internal_secret: sample_secret_1234567890178901237890

auth_methods:
  - tag: irma
    name: Gebruik je IRMA app
    image_path: /static/irma.svg
    start: http://auth-irma:8000
  - tag: digid
    name: Gebruik DigiD
    image_path: /static/digid.svg
    start: http://auth-test:8000

comm_methods:
  - tag: call
    name: Bellen
    image_path: /static/phone.svg
    start: http://comm-test:8000
  - tag: chat
    name: Chatten
    image_path: /static/chat.svg
    start: http://comm-matrix-bot:3000

purposes:
  - tag: report_move
    attributes:
      - email
    allowed_auth:
      - "*"
    allowed_comm:
      - call
      - chat
  - tag: request_permit
    attributes:
      - email
    allowed_auth:
      - irma
      - digid
    allowed_comm:
      - "*"
  - tag: request_passport
    attributes:
      - email
    allowed_auth:
      - irma
    allowed_comm:
      - call

"#;
    #[test]
    fn test_options() {
        let config = CoreConfig::from_str(TEST_CONFIG_VALID);

        let client = Client::tracked(rocket(config)).unwrap();

        let response = client.get("/session_options/report_move").dispatch();
        assert_eq!(response.status(), Status::Ok);
        let response =
            serde_json::from_slice::<SessionOptions>(&response.into_bytes().unwrap()).unwrap();
        assert!(response.auth_methods.iter().any(|m| m.tag == "irma"));
        assert!(response.auth_methods.iter().any(|m| m.tag == "digid"));
        assert_eq!(response.auth_methods.len(), 2);
        assert!(response.comm_methods.iter().any(|m| m.tag == "call"));
        assert!(response.comm_methods.iter().any(|m| m.tag == "chat"));
        assert_eq!(response.comm_methods.len(), 2);

        let response = client.get("/session_options/request_passport").dispatch();
        assert_eq!(response.status(), Status::Ok);
        let response =
            serde_json::from_slice::<SessionOptions>(&response.into_bytes().unwrap()).unwrap();
        assert!(response.auth_methods.iter().any(|m| m.tag == "irma"));
        assert_eq!(response.auth_methods.len(), 1);
        assert!(response.comm_methods.iter().any(|m| m.tag == "call"));
        assert_eq!(response.comm_methods.len(), 1);

        let response = client.get("/session_options/does_not_exist").dispatch();
        assert_ne!(response.status(), Status::Ok);
    }
}
