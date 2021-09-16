use std::{collections::HashMap, time::Duration};

use crate::config::CoreConfig;
use josekit::{
    jws::JwsHeader,
    jwt::{self, JwtPayload},
};

use super::{Method, Tag};
use crate::error::Error;
use id_contact_proto::{StartAuthRequest, StartAuthResponse};
use rocket::{response::Redirect, State};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct AuthenticationMethod {
    tag: Tag,
    name: String,
    image_path: String,
    start: String,
    #[serde(default = "bool::default")]
    disable_attr_url: bool,
    #[serde(default = "bool::default")]
    shim_tel_url: bool,
}

impl AuthenticationMethod {
    pub async fn start(
        &self,
        attributes: &[String],
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

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;

        Ok(client
            .post(&format!("{}/start_authentication", self.start))
            .json(&StartAuthRequest {
                attributes: attributes.to_vec(),
                continuation,
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
        attributes: &[String],
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
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;
        Ok(client
            .post(&format!("{}/start_authentication", self.start))
            .json(&StartAuthRequest {
                attributes: attributes.to_vec(),
                continuation: format!("{}/auth_attr_shim/{}", config.server_url(), state),
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
            let token = sign_continuation(continuation, config);
            format!("{}{}", config.ui_tel_url(), &token)
        } else {
            continuation.to_string()
        }
    }
}

fn sign_continuation(continuation: &str, config: &CoreConfig) -> String {
    let mut payload = JwtPayload::new();
    payload.set_issued_at(&std::time::SystemTime::now());

    // expires_at is set to the expiry time of a DTMF code
    payload
        .set_expires_at(&(std::time::SystemTime::now() + std::time::Duration::from_secs(60 * 60)));
    payload
        .set_claim(
            "continuation",
            Some(serde_json::to_value(continuation).unwrap()),
        )
        .unwrap();
    jwt::encode_with_signer(&payload, &JwsHeader::new(), config.ui_signer()).unwrap()
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
    config: &State<CoreConfig>,
) -> Result<Redirect, Error> {
    // Unpack session state
    let state = config.decode_urlstate(state)?;
    let attr_url = state.get("attr_url").ok_or(Error::BadRequest)?;
    let continuation = state.get("continuation").ok_or(Error::BadRequest)?;

    // Send through results
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
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
    use rocket::{figment::Figment, local::blocking::Client};
    use serde_json::json;

    use crate::{config::CoreConfig, setup_routes};

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

[global.authonly_request_keys.test]
type = "RSA"
key = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5/wRrT2T4GGvuQYcWjLr
/lFe51sTV2FLd3GAaMiHN8Q/VT/XEhP/kZ6042l1Bj2VpZ2yMxv294JKwBCINc34
8VLYd+DfkMnJ4yX9LZHK2Wke6tCWBB9mYgGjMwCNdXczbl96x1/HevaTorvk91rz
Cvzw6vV08jtprAyN5aYMU4I0/cVJwi03bh/skraAB110mQSqi1QU/2z6Hkuf7+/x
/bACxviWCyPCd/wkXNpFhTcRlfFeyKcy0pwFx1OLCDJ1qY7oU+z1wcypeOHeiUSx
riSHlWaT24ke+J78GGVmnCZdu/MRuun5hvgaiWxnhIBmExJY6vRuMlwkbRqOft5Q
TQIDAQAB
-----END PUBLIC KEY-----
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

    #[test]
    fn test_start_with_attr_url() {
        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(Toml::string(TEST_CONFIG_VALID).nested());

        let config = figment.extract::<CoreConfig>().unwrap();

        let server = MockServer::start();
        let start_mock = server.mock(|when, then| {
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

        let method = super::AuthenticationMethod {
            tag: "test".into(),
            name: "test".into(),
            image_path: "none".into(),
            start: server.base_url(),
            disable_attr_url: false,
            shim_tel_url: false,
        };

        let result = tokio_test::block_on(method.start(
            &vec!["email".into()],
            "https://example.com/continuation",
            &Some("https://example.com/attr_url".into()),
            &config,
        ));

        start_mock.assert();
        assert_eq!(result.unwrap(), "https://example.com/client_url");
    }

    #[test]
    fn test_start_without_attr_url() {
        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(Toml::string(TEST_CONFIG_VALID).nested());

        let config = figment.extract::<CoreConfig>().unwrap();

        let server = MockServer::start();
        let start_mock = server.mock(|when, then| {
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

        let method = super::AuthenticationMethod {
            tag: "test".into(),
            name: "test".into(),
            image_path: "none".into(),
            start: server.base_url(),
            disable_attr_url: false,
            shim_tel_url: false,
        };

        let result = tokio_test::block_on(method.start(
            &vec!["email".into()],
            "https://example.com/continuation",
            &None,
            &config,
        ));

        start_mock.assert();
        assert_eq!(result.unwrap(), "https://example.com/client_url");
    }

    #[test]
    fn test_attr_shim_start() {
        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(Toml::string(TEST_CONFIG_VALID).nested());

        let config = figment.extract::<CoreConfig>().unwrap();

        let server = MockServer::start();
        let start_mock = server.mock(|when, then| {
            when.path("/start_authentication")
                .method(httpmock::Method::POST)
                .matches(|req| {
                    if let Some(body) = &req.body {
                        let body = serde_json::from_slice::<StartAuthRequest>(body);
                        if let Ok(body) = body {
                            body.attr_url == None
                                && body.continuation != "https://example.com/continuation"
                                && body.attributes == vec!["email"]
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

        let method = super::AuthenticationMethod {
            tag: "test".into(),
            name: "test".into(),
            image_path: "none".into(),
            start: server.base_url(),
            disable_attr_url: true,
            shim_tel_url: false,
        };

        let result = tokio_test::block_on(method.start(
            &vec!["email".into()],
            "https://example.com/continuation",
            &Some("https://example.com/attr_url".into()),
            &config,
        ));

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
        let start_mock = server.mock(|when, then| {
            when.path("/start_authentication")
                .method(httpmock::Method::POST)
                .matches(|req| {
                    if let Some(body) = &req.body {
                        let body = serde_json::from_slice::<StartAuthRequest>(body);
                        if let Ok(body) = body {
                            body.attr_url == Some("https://example.com/attr_url".into())
                                && body.continuation != "tel:0123456789"
                                && body.attributes == vec!["email"]
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

        let method = super::AuthenticationMethod {
            tag: "test".into(),
            name: "test".into(),
            image_path: "none".into(),
            start: server.base_url(),
            disable_attr_url: false,
            shim_tel_url: true,
        };

        let result = tokio_test::block_on(method.start(
            &vec!["email".into()],
            "tel:0123456789",
            &Some("https://example.com/attr_url".into()),
            &config,
        ));

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
        let start_mock = server.mock(|when, then| {
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

        let method = super::AuthenticationMethod {
            tag: "test".into(),
            name: "test".into(),
            image_path: "none".into(),
            start: server.base_url(),
            disable_attr_url: false,
            shim_tel_url: true,
        };

        let result = tokio_test::block_on(method.start(
            &vec!["email".into()],
            "https://example.com/continuation",
            &Some("https://example.com/attr_url".into()),
            &config,
        ));

        start_mock.assert();
        assert_eq!(result.unwrap(), "https://example.com/client_url");
    }

    #[test]
    fn test_attr_url_shim_end_to_end() {
        let server = httpmock::MockServer::start();

        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(
                Toml::string(&format!(
                    r#"
[global]
server_url = ""
internal_url = "https://example.com/should_not_be_used"
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

[global.authonly_request_keys.test]
type = "RSA"
key = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5/wRrT2T4GGvuQYcWjLr
/lFe51sTV2FLd3GAaMiHN8Q/VT/XEhP/kZ6042l1Bj2VpZ2yMxv294JKwBCINc34
8VLYd+DfkMnJ4yX9LZHK2Wke6tCWBB9mYgGjMwCNdXczbl96x1/HevaTorvk91rz
Cvzw6vV08jtprAyN5aYMU4I0/cVJwi03bh/skraAB110mQSqi1QU/2z6Hkuf7+/x
/bACxviWCyPCd/wkXNpFhTcRlfFeyKcy0pwFx1OLCDJ1qY7oU+z1wcypeOHeiUSx
riSHlWaT24ke+J78GGVmnCZdu/MRuun5hvgaiWxnhIBmExJY6vRuMlwkbRqOft5Q
TQIDAQAB
-----END PUBLIC KEY-----
"""

[[global.auth_methods]]
tag = "test"
name = "test"
image_path = "none"
disable_attr_url = true
start = "{}"

[[global.comm_methods]]
tag = "test"
name = "test"
image_path = "none"
start = "{}"

[[global.purposes]]
tag = "test"
attributes = [ "email" ]
allowed_auth = [ "test" ]
allowed_comm = [ "test" ]
"#,
                    server.base_url(),
                    server.base_url()
                ))
                .nested(),
            );

        let config = figment.extract::<CoreConfig>().unwrap();
        let client = Client::tracked(setup_routes(rocket::custom(figment))).unwrap();

        static mut ESCAPE_HATCH: Option<String> = None;
        let start_mock = server.mock(|when, then| {
            when.path("/start_authentication")
                .method(httpmock::Method::POST)
                .matches(|req| {
                    if let Some(body) = &req.body {
                        let body = serde_json::from_slice::<StartAuthRequest>(body);
                        if let Ok(body) = body {
                            unsafe {
                                ESCAPE_HATCH = Some(body.continuation.clone());
                            }
                            body.attr_url == None
                                && body.continuation != "https://example.com/continuation"
                                && body.attributes == vec!["email"]
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
        let attr_mock = server.mock(|when, then| {
            when.path("/attr_url")
                .method(httpmock::Method::POST)
                .header("Content-Type", "application/jwt")
                .body("test");
            then.status(200);
        });

        // Do start request
        let result = tokio_test::block_on(config.auth_methods["test"].start(
            &vec!["email".into()],
            "https://example.com/continuation",
            &Some(format!("{}/attr_url", server.base_url())),
            &config,
        ));

        start_mock.assert();
        let result = result.unwrap();
        assert_eq!(result, "https://example.com/client_url");

        // Test authentication finish path
        let auth_finish = unsafe { ESCAPE_HATCH.clone().unwrap() };
        let response = client
            .get(format!("{}?result=test", auth_finish))
            .dispatch();
        attr_mock.assert();
        assert_eq!(response.status(), rocket::http::Status::SeeOther);
        assert_eq!(
            response.headers().get_one("Location"),
            Some("https://example.com/continuation".into())
        );
    }
}
