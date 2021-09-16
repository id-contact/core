use crate::error::Error;
use crate::methods::{AuthenticationMethod, CommunicationMethod, Method};
use crate::start::StartRequestAuthOnly;
use id_contact_jwt::SignKeyConfig;
use josekit::jws::JwsVerifier;
use josekit::jwt::decode_with_verifier_selector;
use josekit::{
    jws::{
        alg::hmac::{HmacJwsAlgorithm::Hs256, HmacJwsSigner, HmacJwsVerifier},
        JwsHeader, JwsSigner,
    },
    jwt::{self, JwtPayload, JwtPayloadValidator},
};
use serde::Deserialize;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::Debug;

#[derive(Debug, Deserialize, Clone)]
pub struct Purpose {
    pub tag: String,
    pub attributes: Vec<String>,
    pub allowed_auth: Vec<String>,
    pub allowed_comm: Vec<String>,
}

#[derive(Deserialize)]
#[serde(from = "String")]
struct TokenSecret(String);

impl Debug for TokenSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSecret").finish()
    }
}

impl From<String> for TokenSecret {
    fn from(value: String) -> Self {
        TokenSecret(value)
    }
}

#[derive(Debug, Deserialize)]
struct RawCoreConfig {
    auth_methods: Vec<AuthenticationMethod>,
    comm_methods: Vec<CommunicationMethod>,
    purposes: Vec<Purpose>,
    authonly_request_keys: HashMap<String, SignKeyConfig>,
    internal_secret: TokenSecret,
    server_url: String,
    internal_url: String,
    ui_tel_url: String,
    ui_signing_privkey: SignKeyConfig,
    sentry_dsn: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(from = "RawCoreConfig")]
pub struct CoreConfig {
    pub auth_methods: HashMap<String, AuthenticationMethod>,
    pub comm_methods: HashMap<String, CommunicationMethod>,
    pub purposes: HashMap<String, Purpose>,
    authonly_request_keys: HashMap<String, Box<dyn JwsVerifier>>,
    internal_signer: HmacJwsSigner,
    internal_verifier: HmacJwsVerifier,
    server_url: String,
    internal_url: String,
    ui_tel_url: String,
    ui_signer: Box<dyn JwsSigner>,
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
                .into_iter()
                .map(|m| (m.tag().clone(), m))
                .collect(),
            comm_methods: config
                .comm_methods
                .into_iter()
                .map(|m| (m.tag().clone(), m))
                .collect(),
            purposes: config
                .purposes
                .into_iter()
                .map(|m| (m.tag.clone(), m))
                .collect(),
            authonly_request_keys: config
                .authonly_request_keys
                .into_iter()
                .map(|(requestor, key)| {
                    let key = Box::<dyn JwsVerifier>::try_from(key).unwrap_or_else(|_| {
                        log::error!("Could not parse requestor key for requestor {}", requestor);
                        panic!("Invalid requestor key")
                    });
                    (requestor, key)
                })
                .collect(),
            internal_signer: Hs256
                .signer_from_bytes(config.internal_secret.0.as_bytes())
                .unwrap_or_else(|e| {
                    log::error!("Could not generate signer from internal secret: {}", e);
                    panic!("Could not generate signer from internal secret: {}", e)
                }),
            internal_verifier: Hs256
                .verifier_from_bytes(config.internal_secret.0.as_bytes())
                .unwrap_or_else(|e| {
                    log::error!("Could not generate verifier from internal secret: {}", e);
                    panic!("Could not generate verifier from internal secret: {}", e)
                }),
            ui_signer: Box::<dyn JwsSigner>::try_from(config.ui_signing_privkey).unwrap_or_else(
                |e| {
                    log::error!("Could not generate signer from core private key: {}", e);
                    panic!("Could not generate signer from core private key: {}", e)
                },
            ),
            internal_url: config.internal_url,
            server_url: config.server_url,
            ui_tel_url: config.ui_tel_url,
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
                log::error!("Invalid auth method in purpose {}", purpose.tag);
                panic!("Invalid auth method in purpose {}", purpose.tag);
            }
            if !validate_methods(&purpose.allowed_comm, &config.comm_methods) {
                log::error!("Invalid comm method in purpose {}", purpose.tag);
                panic!("Invalid comm method in purpose {}", purpose.tag);
            }
        }

        config
    }
}

impl CoreConfig {
    pub fn purpose(&self, purpose: &str) -> Result<&Purpose, Error> {
        self.purposes
            .get(purpose)
            .ok_or_else(|| Error::NoSuchPurpose(purpose.to_string()))
    }

    pub fn comm_method(
        &self,
        purpose: &Purpose,
        comm_method: &str,
    ) -> Result<&CommunicationMethod, Error> {
        if !purpose.allowed_comm.iter().any(|c| c == comm_method) {
            return Err(Error::NoSuchMethod(comm_method.to_string()));
        }
        self.comm_methods
            .get(comm_method)
            .ok_or_else(|| Error::NoSuchMethod(comm_method.to_string()))
    }

    pub fn auth_method(
        &self,
        purpose: &Purpose,
        auth_method: &str,
    ) -> Result<&AuthenticationMethod, Error> {
        if !purpose.allowed_auth.iter().any(|c| c == auth_method) {
            return Err(Error::NoSuchMethod(auth_method.to_string()));
        }
        self.auth_methods
            .get(auth_method)
            .ok_or_else(|| Error::NoSuchMethod(auth_method.to_string()))
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

    pub fn decode_authonly_request(
        &self,
        request_jwt: &str,
    ) -> Result<StartRequestAuthOnly, Error> {
        let decoded = decode_with_verifier_selector(request_jwt, |header| {
            Ok(header
                .key_id()
                .map(|kid| self.authonly_request_keys.get(kid))
                .flatten()
                .map(|key| key.as_ref()))
        })?
        .0;
        let mut validator = JwtPayloadValidator::new();
        validator.set_base_time(std::time::SystemTime::now());
        validator.validate(&decoded)?;
        let request = decoded.claim("request").ok_or(Error::BadRequest)?;
        Ok(serde_json::from_value::<StartRequestAuthOnly>(
            request.clone(),
        )?)
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    pub fn ui_tel_url(&self) -> &str {
        &self.ui_tel_url
    }

    pub fn _internal_url(&self) -> &str {
        &self.internal_url
    }

    pub fn sentry_dsn(&self) -> Option<&str> {
        self.sentry_dsn.as_deref()
    }

    pub fn ui_signer(&self) -> &dyn JwsSigner {
        self.ui_signer.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use figment::providers::{Format, Toml};
    use rocket::figment::Figment;

    use super::CoreConfig;
    use crate::{config::TokenSecret, methods::Method};

    // Test data
    const TEST_CONFIG_VALID: &'static str = r#"
[global]
server_url = "https://core.idcontact.test.tweede.golf"
internal_url = "http://core:8000"
internal_secret = "sample_secret_1234567890178901237890"
ui_tel_url = "https://poc.idcontact.test.tweede.golf/tel/"

[global.ui_signing_privkey]
type = "RSA"
key = """
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDn/BGtPZPgYa+5
BhxaMuv+UV7nWxNXYUt3cYBoyIc3xD9VP9cSE/+RnrTjaXUGPZWlnbIzG/b3gkrA
EIg1zfjxUth34N+QycnjJf0tkcrZaR7q0JYEH2ZiAaMzAI11dzNuX3rHX8d69pOi
u+T3WvMK/PDq9XTyO2msDI3lpgxTgjT9xUnCLTduH+yStoAHXXSZBKqLVBT/bPoe
S5/v7/H9sALG+JYLI8J3/CRc2kWFNxGV8V7IpzLSnAXHU4sIMnWpjuhT7PXBzKl4
4d6JRLGuJIeVZpPbiR74nvwYZWacJl278xG66fmG+BqJbGeEgGYTEljq9G4yXCRt
Go5+3lBNAgMBAAECggEARY9EsaCMLbS83wrhB37LWneFsHOTqhjHaypCaajvOp6C
qwo4b/hFIqHm9WWSrGtc6ssNOtwAwphz14Fdhlybb6j6tX9dKeoHui+S6c4Ud/pY
ReqDgPr1VR/OkqVwxS8X4dmJVCz5AHrdK+eRMUY5KCtOBfXRuixsdCVTiu+uNH99
QC3kID1mmOF3B0chOK4WPN4cCsQpfOvoJfPBcJOtyxUSLlQdJH+04s3gVA24nCJj
66+AnVkjgkyQ3q0Jugh1vo0ikrUW8uSLmg40sT5eYDN9jP6r5Gc8yDqsmYNVbLhU
pY8XR4gtzbtAXK8R2ISKNhOSuTv4SWFXVZiDIBkuIQKBgQD3qnZYyhGzAiSM7T/R
WS9KrQlzpRV5qSnEp2sPG/YF+SGAdgOaWOEUa3vbkCuLCTkoJhdTp67BZvv/657Q
2eK2khsYRs02Oq+4rYvdcAv/wS2vkMbg6CUp1w2/pwBvwFTXegr00k6IabXNcXBy
kAjMsZqVDSdQByrf80AlFyEsOQKBgQDvyoUDhLReeDNkbkPHL/EHD69Hgsc77Hm6
MEiLdNljTJLRUl+DuD3yKX1xVBaCLp9fMJ/mCrxtkldhW+i6JBHRQ7vdf11zNsRf
2Cud3Q97RMHTacCHhEQDGnYkOQNTRhk8L31N0XBKfUu0phSmVyTnu2lLWmYJ8hyO
yOEB19JstQKBgQC3oVw+WRTmdSBEnWREBKxb4hCv/ib+Hb8qYDew7DpuE1oTtWzW
dC/uxAMBuNOQMzZ93kBNdnbMT19pUXpfwC2o0IvmZBijrL+9Xm/lr7410zXchqvu
9jEX5Kv8/gYE1cYSPhsBiy1PV5HE0edeCg18N/M1sJsFa0sO4X0eAxhFgQKBgQC7
iQDkUooaBBn1ZsM9agIwSpUD8YTOGdDNy+tAnf9SSNXePXUT+CkCVm6UDnaYE8xy
zv2PFUBu1W/fZdkqkwEYT8gCoBS/AcstRkw+Z2AvQQPxyxhXJBto7e4NwEUYgI9F
4cI29SDEMR/fRbCKs0basVjVJPr+tkqdZP+MyHT6rQKBgQCT1YjY4F45Qn0Vl+sZ
HqwVHvPMwVsexcRTdC0evaX/09s0xscSACvFJh5Dm9gnuMHElBcpZFATIvFcbV5Y
MbJ/NNQiD63NEcL9VXwT96sMx2tnduOq4sYzu84kwPQ4ohxmPt/7xHU3L8SGqoec
Bs6neR/sZuHzNm8y/xtxj2ZAEw==
-----END PRIVATE KEY-----
"""

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
    const TEST_CONFIG_INVALID_METHOD_COMM: &'static str = r#"
[global]
server_url = "https://core.idcontact.test.tweede.golf"
internal_url = "http://core:8000"
internal_secret = "sample_secret_1234567890178901237890"
ui_tel_url = "https://poc.idcontact.test.tweede.golf/tel/"

[global.ui_signing_privkey]
type = "RSA"
key = """
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDn/BGtPZPgYa+5
BhxaMuv+UV7nWxNXYUt3cYBoyIc3xD9VP9cSE/+RnrTjaXUGPZWlnbIzG/b3gkrA
EIg1zfjxUth34N+QycnjJf0tkcrZaR7q0JYEH2ZiAaMzAI11dzNuX3rHX8d69pOi
u+T3WvMK/PDq9XTyO2msDI3lpgxTgjT9xUnCLTduH+yStoAHXXSZBKqLVBT/bPoe
S5/v7/H9sALG+JYLI8J3/CRc2kWFNxGV8V7IpzLSnAXHU4sIMnWpjuhT7PXBzKl4
4d6JRLGuJIeVZpPbiR74nvwYZWacJl278xG66fmG+BqJbGeEgGYTEljq9G4yXCRt
Go5+3lBNAgMBAAECggEARY9EsaCMLbS83wrhB37LWneFsHOTqhjHaypCaajvOp6C
qwo4b/hFIqHm9WWSrGtc6ssNOtwAwphz14Fdhlybb6j6tX9dKeoHui+S6c4Ud/pY
ReqDgPr1VR/OkqVwxS8X4dmJVCz5AHrdK+eRMUY5KCtOBfXRuixsdCVTiu+uNH99
QC3kID1mmOF3B0chOK4WPN4cCsQpfOvoJfPBcJOtyxUSLlQdJH+04s3gVA24nCJj
66+AnVkjgkyQ3q0Jugh1vo0ikrUW8uSLmg40sT5eYDN9jP6r5Gc8yDqsmYNVbLhU
pY8XR4gtzbtAXK8R2ISKNhOSuTv4SWFXVZiDIBkuIQKBgQD3qnZYyhGzAiSM7T/R
WS9KrQlzpRV5qSnEp2sPG/YF+SGAdgOaWOEUa3vbkCuLCTkoJhdTp67BZvv/657Q
2eK2khsYRs02Oq+4rYvdcAv/wS2vkMbg6CUp1w2/pwBvwFTXegr00k6IabXNcXBy
kAjMsZqVDSdQByrf80AlFyEsOQKBgQDvyoUDhLReeDNkbkPHL/EHD69Hgsc77Hm6
MEiLdNljTJLRUl+DuD3yKX1xVBaCLp9fMJ/mCrxtkldhW+i6JBHRQ7vdf11zNsRf
2Cud3Q97RMHTacCHhEQDGnYkOQNTRhk8L31N0XBKfUu0phSmVyTnu2lLWmYJ8hyO
yOEB19JstQKBgQC3oVw+WRTmdSBEnWREBKxb4hCv/ib+Hb8qYDew7DpuE1oTtWzW
dC/uxAMBuNOQMzZ93kBNdnbMT19pUXpfwC2o0IvmZBijrL+9Xm/lr7410zXchqvu
9jEX5Kv8/gYE1cYSPhsBiy1PV5HE0edeCg18N/M1sJsFa0sO4X0eAxhFgQKBgQC7
iQDkUooaBBn1ZsM9agIwSpUD8YTOGdDNy+tAnf9SSNXePXUT+CkCVm6UDnaYE8xy
zv2PFUBu1W/fZdkqkwEYT8gCoBS/AcstRkw+Z2AvQQPxyxhXJBto7e4NwEUYgI9F
4cI29SDEMR/fRbCKs0basVjVJPr+tkqdZP+MyHT6rQKBgQCT1YjY4F45Qn0Vl+sZ
HqwVHvPMwVsexcRTdC0evaX/09s0xscSACvFJh5Dm9gnuMHElBcpZFATIvFcbV5Y
MbJ/NNQiD63NEcL9VXwT96sMx2tnduOq4sYzu84kwPQ4ohxmPt/7xHU3L8SGqoec
Bs6neR/sZuHzNm8y/xtxj2ZAEw==
-----END PRIVATE KEY-----
"""

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
allowed_comm = [ "call", "chat", "does_not_exist" ]

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
    const TEST_CONFIG_INVALID_METHOD_AUTH: &'static str = r#"
[global]
server_url = "https://core.idcontact.test.tweede.golf"
internal_url = "http://core:8000"
internal_secret = "sample_secret_1234567890178901237890"
ui_tel_url = "https://poc.idcontact.test.tweede.golf/tel/"

[global.ui_signing_privkey]
type = "RSA"
key = """
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDn/BGtPZPgYa+5
BhxaMuv+UV7nWxNXYUt3cYBoyIc3xD9VP9cSE/+RnrTjaXUGPZWlnbIzG/b3gkrA
EIg1zfjxUth34N+QycnjJf0tkcrZaR7q0JYEH2ZiAaMzAI11dzNuX3rHX8d69pOi
u+T3WvMK/PDq9XTyO2msDI3lpgxTgjT9xUnCLTduH+yStoAHXXSZBKqLVBT/bPoe
S5/v7/H9sALG+JYLI8J3/CRc2kWFNxGV8V7IpzLSnAXHU4sIMnWpjuhT7PXBzKl4
4d6JRLGuJIeVZpPbiR74nvwYZWacJl278xG66fmG+BqJbGeEgGYTEljq9G4yXCRt
Go5+3lBNAgMBAAECggEARY9EsaCMLbS83wrhB37LWneFsHOTqhjHaypCaajvOp6C
qwo4b/hFIqHm9WWSrGtc6ssNOtwAwphz14Fdhlybb6j6tX9dKeoHui+S6c4Ud/pY
ReqDgPr1VR/OkqVwxS8X4dmJVCz5AHrdK+eRMUY5KCtOBfXRuixsdCVTiu+uNH99
QC3kID1mmOF3B0chOK4WPN4cCsQpfOvoJfPBcJOtyxUSLlQdJH+04s3gVA24nCJj
66+AnVkjgkyQ3q0Jugh1vo0ikrUW8uSLmg40sT5eYDN9jP6r5Gc8yDqsmYNVbLhU
pY8XR4gtzbtAXK8R2ISKNhOSuTv4SWFXVZiDIBkuIQKBgQD3qnZYyhGzAiSM7T/R
WS9KrQlzpRV5qSnEp2sPG/YF+SGAdgOaWOEUa3vbkCuLCTkoJhdTp67BZvv/657Q
2eK2khsYRs02Oq+4rYvdcAv/wS2vkMbg6CUp1w2/pwBvwFTXegr00k6IabXNcXBy
kAjMsZqVDSdQByrf80AlFyEsOQKBgQDvyoUDhLReeDNkbkPHL/EHD69Hgsc77Hm6
MEiLdNljTJLRUl+DuD3yKX1xVBaCLp9fMJ/mCrxtkldhW+i6JBHRQ7vdf11zNsRf
2Cud3Q97RMHTacCHhEQDGnYkOQNTRhk8L31N0XBKfUu0phSmVyTnu2lLWmYJ8hyO
yOEB19JstQKBgQC3oVw+WRTmdSBEnWREBKxb4hCv/ib+Hb8qYDew7DpuE1oTtWzW
dC/uxAMBuNOQMzZ93kBNdnbMT19pUXpfwC2o0IvmZBijrL+9Xm/lr7410zXchqvu
9jEX5Kv8/gYE1cYSPhsBiy1PV5HE0edeCg18N/M1sJsFa0sO4X0eAxhFgQKBgQC7
iQDkUooaBBn1ZsM9agIwSpUD8YTOGdDNy+tAnf9SSNXePXUT+CkCVm6UDnaYE8xy
zv2PFUBu1W/fZdkqkwEYT8gCoBS/AcstRkw+Z2AvQQPxyxhXJBto7e4NwEUYgI9F
4cI29SDEMR/fRbCKs0basVjVJPr+tkqdZP+MyHT6rQKBgQCT1YjY4F45Qn0Vl+sZ
HqwVHvPMwVsexcRTdC0evaX/09s0xscSACvFJh5Dm9gnuMHElBcpZFATIvFcbV5Y
MbJ/NNQiD63NEcL9VXwT96sMx2tnduOq4sYzu84kwPQ4ohxmPt/7xHU3L8SGqoec
Bs6neR/sZuHzNm8y/xtxj2ZAEw==
-----END PRIVATE KEY-----
"""

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
allowed_auth = [ "irma", "digid", "does_not_exist" ]
allowed_comm = [ "*" ]

[[global.purposes]]
tag = "request_passport"
attributes = [ "email" ]
allowed_auth = [ "irma" ]
allowed_comm = [ "call" ]

"#;
    fn config_from_str(config: &str) -> CoreConfig {
        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(Toml::string(config).nested());

        figment.extract::<CoreConfig>().unwrap()
    }

    #[test]
    fn test_wildcard_expansion() {
        let config = config_from_str(TEST_CONFIG_VALID);

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
    #[should_panic]
    fn test_invalid_auth() {
        let _config = config_from_str(TEST_CONFIG_INVALID_METHOD_AUTH);
    }

    #[test]
    #[should_panic]
    fn test_invalid_comm() {
        let _config = config_from_str(TEST_CONFIG_INVALID_METHOD_COMM);
    }

    #[test]
    fn test_get_purpose() {
        let config = config_from_str(TEST_CONFIG_VALID);
        assert_eq!(
            config.purpose(&"report_move".to_string()).unwrap().tag,
            "report_move"
        );
        assert!(config.purpose(&"does_not_exist".to_string()).is_err());
    }

    #[test]
    fn test_get_comm_method() {
        let config = config_from_str(TEST_CONFIG_VALID);

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
    fn test_log_hiding() {
        let test_token = TokenSecret::from("test".to_string());
        assert_eq!(format!("{:?}", test_token), "TokenSecret");

        let config = config_from_str(TEST_CONFIG_VALID);
        assert_eq!(format!("{:?}", config.internal_signer), "HmacJwsSigner { algorithm: Hs256, private_key: PKey { algorithm: \"HMAC\" }, key_id: None }");
        assert_eq!(format!("{:?}", config.internal_verifier), "HmacJwsVerifier { algorithm: Hs256, private_key: PKey { algorithm: \"HMAC\" }, key_id: None }");
    }

    #[test]
    fn test_get_auth_method() {
        let config = config_from_str(TEST_CONFIG_VALID);

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
        let config = config_from_str(TEST_CONFIG_VALID);

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
