use std::collections::HashMap;

use crate::methods::{Method, Tag};
use crate::{config::CoreConfig, error::Error};
use rocket::{serde::json::Json, State};
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

type AllSessionOptions = HashMap<String, SessionOptions>;

#[get("/session_options")]
pub fn all_session_options(config: &State<CoreConfig>) -> Result<Json<AllSessionOptions>, Error> {
    let mut all_options: AllSessionOptions = HashMap::new();

    for (name, purpose) in &config.purposes {
        let auth_methods = MethodProperties::filter_methods_by_tags(
            purpose.allowed_auth.iter(),
            &config.auth_methods,
        )?;
        let comm_methods = MethodProperties::filter_methods_by_tags(
            purpose.allowed_comm.iter(),
            &config.comm_methods,
        )?;

        all_options.insert(
            name.to_string(),
            SessionOptions {
                auth_methods,
                comm_methods,
            },
        );
    }

    Ok(Json(all_options))
}

#[get("/session_options/<purpose>")]
pub fn session_options(
    purpose: String,
    config: &State<CoreConfig>,
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
    use crate::setup_routes;
    use figment::providers::{Format, Toml};
    use rocket::figment::Figment;

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
    #[test]
    fn test_options() {
        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(Toml::string(TEST_CONFIG_VALID).nested());

        let client = Client::tracked(setup_routes(rocket::custom(figment))).unwrap();

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
