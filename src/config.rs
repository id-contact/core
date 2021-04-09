use crate::error::Error;
use crate::methods::{AuthenticationMethod, CommunicationMethod, Method, Tag};
use josekit::{
    jws::{
        alg::hmac::{HmacJwsAlgorithm::Hs256, HmacJwsSigner, HmacJwsVerifier},
        JwsHeader,
    },
    jwt::{self, JwtPayload, JwtPayloadValidator},
};
use serde::Deserialize;
use std::{collections::HashMap, fs};

#[derive(Debug, Deserialize, Clone)]
pub struct Purpose {
    pub tag: String,
    pub attributes: Vec<String>,
    pub allowed_auth: Vec<String>,
    pub allowed_comm: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawCoreConfig {
    auth_methods: Vec<AuthenticationMethod>,
    comm_methods: Vec<CommunicationMethod>,
    purposes: Vec<Purpose>,
    internal_secret: String,
    server_url: String,
    internal_url: String,
    sentry_dsn: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(from = "RawCoreConfig")]
pub struct CoreConfig {
    pub auth_methods: HashMap<String, AuthenticationMethod>,
    pub comm_methods: HashMap<String, CommunicationMethod>,
    pub purposes: HashMap<String, Purpose>,
    internal_signer: HmacJwsSigner,
    internal_verifier: HmacJwsVerifier,
    server_url: String,
    internal_url: String,
    sentry_dsn: Option<String>,
}

fn contains_wildcard(target: &[String]) -> bool {
    for val in target {
        if val == "*" {
            return true;
        }
    }
    false
}

fn validate_methods<T>(target: &[String], options: &HashMap<String, T>) -> bool {
    for val in target {
        if options.get(val).is_none() {
            return false;
        }
    }
    true
}

impl From<RawCoreConfig> for CoreConfig {
    fn from(config: RawCoreConfig) -> Self {
        let mut config = CoreConfig {
            auth_methods: config
                .auth_methods
                .iter()
                .map(|m| (m.tag().clone(), m.clone()))
                .collect(),
            comm_methods: config
                .comm_methods
                .iter()
                .map(|m| (m.tag().clone(), m.clone()))
                .collect(),
            purposes: config
                .purposes
                .iter()
                .map(|m| (m.tag.clone(), m.clone()))
                .collect(),
            internal_signer: Hs256
                .signer_from_bytes(config.internal_secret.as_bytes())
                .unwrap_or_else(|e| {
                    panic!("Could not generate signer from internal secret: {}", e)
                }),
            internal_verifier: Hs256
                .verifier_from_bytes(config.internal_secret.as_bytes())
                .unwrap_or_else(|e| {
                    panic!("Could not generate verifier from internal secret: {}", e)
                }),
            internal_url: config.internal_url,
            server_url: config.server_url,
            sentry_dsn: config.sentry_dsn,
        };

        // Handle wildcards in purpose auth and comm method lists
        for purpose in config.purposes.values_mut() {
            if contains_wildcard(&purpose.allowed_auth) {
                purpose.allowed_auth = config.auth_methods.keys().map(|x| x.to_string()).collect();
            }
            if contains_wildcard(&purpose.allowed_comm) {
                purpose.allowed_comm = config.comm_methods.keys().map(|x| x.to_string()).collect();
            }
        }

        // check all mentioned auth and comm methods exist
        for purpose in config.purposes.values() {
            if !validate_methods(&purpose.allowed_auth, &config.auth_methods) {
                panic!("Invalid auth method in purpose {}", purpose.tag);
            }
            if !validate_methods(&purpose.allowed_comm, &config.comm_methods) {
                panic!("Invalid comm method in purpose {}", purpose.tag);
            }
        }

        config
    }
}

impl CoreConfig {
    pub fn from_file(filename: &str) -> CoreConfig {
        let contents = fs::read_to_string(filename)
            .unwrap_or_else(|_| panic!("Could not read the config file {}", filename));

        CoreConfig::from_str(&contents)
    }

    pub fn from_str(contents: &str) -> CoreConfig {
        let config: CoreConfig = serde_yaml::from_str(&contents)
            .unwrap_or_else(|e| panic!("Error parsing the config file: {:?}", e));

        config
    }

    pub fn purpose(&self, purpose: &Tag) -> Result<&Purpose, Error> {
        Ok(self
            .purposes
            .get(purpose)
            .ok_or_else(|| Error::NoSuchPurpose(purpose.to_string()))?)
    }

    pub fn comm_method(
        &self,
        purpose: &Purpose,
        comm_method: &Tag,
    ) -> Result<&CommunicationMethod, Error> {
        if !purpose.allowed_comm.contains(comm_method) {
            return Err(Error::NoSuchMethod(comm_method.to_string()));
        }
        Ok(self
            .comm_methods
            .get(comm_method)
            .ok_or_else(|| Error::NoSuchMethod(comm_method.to_string()))?)
    }

    pub fn auth_method(
        &self,
        purpose: &Purpose,
        auth_method: &Tag,
    ) -> Result<&AuthenticationMethod, Error> {
        if !purpose.allowed_auth.contains(auth_method) {
            return Err(Error::NoSuchMethod(auth_method.to_string()));
        }
        Ok(self
            .auth_methods
            .get(auth_method)
            .ok_or_else(|| Error::NoSuchMethod(auth_method.to_string()))?)
    }

    pub fn encode_urlstate(&self, state: HashMap<String, String>) -> Result<String, Error> {
        let mut payload = JwtPayload::new();

        payload.set_issued_at(&std::time::SystemTime::now());
        payload.set_expires_at(
            &(std::time::SystemTime::now() + std::time::Duration::from_secs(30 * 60)),
        );
        for (k, v) in state.iter() {
            payload.set_claim(k, Some(serde_json::to_value(v)?))?;
        }

        Ok(jwt::encode_with_signer(
            &payload,
            &JwsHeader::new(),
            &self.internal_signer,
        )?)
    }

    pub fn decode_urlstate(&self, urlstate: String) -> Result<HashMap<String, String>, Error> {
        let (payload, _) = jwt::decode_with_verifier(urlstate, &self.internal_verifier)?;

        let mut validator = JwtPayloadValidator::new();
        validator.set_base_time(std::time::SystemTime::now());
        validator.validate(&payload)?;

        let mut result = HashMap::new();
        for (k, v) in payload.claims_set().iter() {
            if k == "exp" || k == "iat" {
                continue;
            }
            result.insert(k.to_string(), serde_json::from_value::<String>(v.clone())?);
        }

        Ok(result)
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    pub fn internal_url(&self) -> &str {
        &self.internal_url
    }

    pub fn sentry_dsn(&self) -> Option<&str> {
        self.sentry_dsn.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::CoreConfig;
    use crate::methods::Method;

    // Test data
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
    const TEST_CONFIG_INVALID_METHOD_COMM: &'static str = r#"
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
      - does_not_exist
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
      - "*"
    allowed_comm:
      - call

"#;
    const TEST_CONFIG_INVALID_METHOD_AUTH: &'static str = r#"
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
      - does_not_exist
    allowed_comm:
      - "*"
  - tag: request_passport
    attributes:
      - email
    allowed_auth:
      - "*"
    allowed_comm:
      - call

"#;

    #[test]
    fn test_wildcard_expansion() {
        let config = CoreConfig::from_str(TEST_CONFIG_VALID);

        let mut test_auth = config.purposes["report_move"].allowed_auth.clone();
        test_auth.sort();
        assert_eq!(test_auth, vec!["digid", "irma"]);

        let mut test_auth = config.purposes["request_permit"].allowed_auth.clone();
        test_auth.sort();
        assert_eq!(test_auth, vec!["digid", "irma"]);

        let mut test_auth = config.purposes["request_passport"].allowed_auth.clone();
        test_auth.sort();
        assert_eq!(test_auth, vec!["irma"]);

        let mut test_comm = config.purposes["report_move"].allowed_comm.clone();
        test_comm.sort();
        assert_eq!(test_comm, vec!["call", "chat"]);

        let mut test_comm = config.purposes["request_permit"].allowed_comm.clone();
        test_comm.sort();
        assert_eq!(test_comm, vec!["call", "chat"]);

        let mut test_comm = config.purposes["request_passport"].allowed_comm.clone();
        test_comm.sort();
        assert_eq!(test_comm, vec!["call"]);
    }

    #[test]
    fn test_sample_config() {
        let _config = CoreConfig::from_file(&format!("{}/config.yml", env!("CARGO_MANIFEST_DIR")));
    }

    #[test]
    #[should_panic]
    fn test_invalid_auth() {
        let _config = CoreConfig::from_str(TEST_CONFIG_INVALID_METHOD_AUTH);
    }

    #[test]
    #[should_panic]
    fn test_invalid_comm() {
        let _config = CoreConfig::from_str(TEST_CONFIG_INVALID_METHOD_COMM);
    }

    #[test]
    fn test_get_purpose() {
        let config = CoreConfig::from_str(TEST_CONFIG_VALID);
        assert_eq!(
            config.purpose(&"report_move".to_string()).unwrap().tag,
            "report_move"
        );
        assert!(config.purpose(&"does_not_exist".to_string()).is_err());
    }

    #[test]
    fn test_get_comm_method() {
        let config = CoreConfig::from_str(TEST_CONFIG_VALID);

        let purpose_report_move = config.purpose(&"report_move".to_string()).unwrap();
        let purpose_request_passport = config.purpose(&"request_passport".to_string()).unwrap();

        assert_eq!(
            config
                .comm_method(purpose_report_move, &"call".to_string())
                .unwrap()
                .tag(),
            "call"
        );
        assert_eq!(
            config
                .comm_method(purpose_report_move, &"chat".to_string())
                .unwrap()
                .tag(),
            "chat"
        );
        assert!(config
            .comm_method(purpose_report_move, &"does-not-exist".to_string())
            .is_err());

        assert_eq!(
            config
                .comm_method(purpose_request_passport, &"call".to_string())
                .unwrap()
                .tag(),
            "call"
        );
        assert!(config
            .comm_method(purpose_request_passport, &"chat".to_string())
            .is_err());
    }

    #[test]
    fn test_get_auth_method() {
        let config = CoreConfig::from_str(TEST_CONFIG_VALID);

        let purpose_report_move = config.purpose(&"report_move".to_string()).unwrap();
        let purpose_request_passport = config.purpose(&"request_passport".to_string()).unwrap();

        assert_eq!(
            config
                .auth_method(purpose_report_move, &"digid".to_string())
                .unwrap()
                .tag(),
            "digid"
        );
        assert_eq!(
            config
                .auth_method(purpose_report_move, &"irma".to_string())
                .unwrap()
                .tag(),
            "irma"
        );
        assert!(config
            .auth_method(purpose_report_move, &"does-not-exist".to_string())
            .is_err());

        assert_eq!(
            config
                .auth_method(purpose_request_passport, &"irma".to_string())
                .unwrap()
                .tag(),
            "irma"
        );
        assert!(config
            .auth_method(purpose_request_passport, &"digid".to_string())
            .is_err());
    }

    #[test]
    fn test_urlstate() {
        let config = CoreConfig::from_str(TEST_CONFIG_VALID);

        let mut test_map = HashMap::new();

        test_map.insert("key_1".to_string(), "value_1".to_string());
        test_map.insert("key_2".to_string(), "value_2".to_string());

        let encoded = config.encode_urlstate(test_map.clone()).unwrap();
        assert_eq!(config.decode_urlstate(encoded).unwrap(), test_map);

        const EXPIRED_JWT: &'static str = "eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MTYwNjAzODEsImV4cCI6MTYxNjA2MjE4MSwia2V5XzEiOiJ2YWx1ZV8xIiwia2V5XzIiOiJ2YWx1ZV8yIn0.S8YcM93jDJswxGxvmIE763KhabUqODUFX1qr7NFBh30";
        assert!(config.decode_urlstate(EXPIRED_JWT.to_string()).is_err());

        const INVALID_JWT: &'static str = "eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MTYwNjAzODEsImV4cCI6MTYxNjA2MjE4MSwia2V5XzEiOiJ2YWx1ZV8xIiwia2V5XzIiOiJ2YWx1ZV8yIn0.F8YcM93jDJswxGxvmIE763KhabUqODUFX1qr7NFBh30";
        assert!(config.decode_urlstate(INVALID_JWT.to_string()).is_err());
    }
}
