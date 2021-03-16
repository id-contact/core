use crate::error::Error;
use crate::methods::{AuthenticationMethod, CommunicationMethod, Method, Tag};
use josekit::{
    jws::{
        alg::hmac::{HmacJwsAlgorithm::Hs256, HmacJwsSigner, HmacJwsVerifier},
        JwsHeader,
    },
    jwt::{self, JwtPayload},
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
            server_url: config.server_url,
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

        let config: CoreConfig = serde_yaml::from_str(&contents)
            .unwrap_or_else(|e| panic!("Error parsing the config file {}: {:?}", filename, e));

        config
    }
}

impl CoreConfig {
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

        let mut result = HashMap::new();
        for (k, v) in payload.claims_set().iter() {
            result.insert(k.to_string(), serde_json::from_value::<String>(v.clone())?);
        }

        Ok(result)
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }
}
