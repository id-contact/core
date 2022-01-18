use crate::error::Error;
use crate::{config::CoreConfig, methods::Tag};
use rocket::serde::json::Json;
use rocket::{
    form::Form,
    http::Status,
    response::{Redirect, Responder},
    Request, Response, State,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, FromForm)]
pub struct StartRequestFull {
    purpose: String,
    auth_method: Tag,
    comm_method: Tag,
}

#[derive(Debug, Deserialize)]
pub struct StartRequestCommOnly {
    purpose: String,
    auth_result: String,
    comm_method: Tag,
}

#[derive(Debug, Deserialize)]
pub struct StartRequestAuthOnly {
    purpose: String,
    auth_method: Tag,
    comm_url: String,
    attr_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientUrlResponse {
    client_url: String,
}

impl<'r> Responder<'r, 'static> for ClientUrlResponse {
    fn respond_to(self, req: &'r Request<'_>) -> Result<Response<'static>, Status> {
        if req.headers().get_one("Accept") == Some("application/json") {
            return Some(Json(ClientUrlResponse {
                client_url: self.client_url,
            }))
            .respond_to(req);
        }

        Some(Redirect::to(self.client_url)).respond_to(req)
    }
}

#[post("/start", format = "application/jwt", data = "<choices>")]
pub async fn session_start_jwt(
    choices: String,
    config: &State<CoreConfig>,
) -> Result<ClientUrlResponse, Error> {
    if let Ok(start_request) = config.decode_authonly_request(&choices) {
        session_start_auth_only(start_request, config).await
    } else {
        Err(Error::BadRequest)
    }
}

#[post("/start", format = "application/json", data = "<choices>")]
pub async fn session_start(
    choices: String,
    config: &State<CoreConfig>,
) -> Result<ClientUrlResponse, Error> {
    // Workaround for issue where matching routes based on json body structure does not works as expected
    if let Ok(start_request) = serde_json::from_str::<StartRequestFull>(&choices) {
        session_start_full(start_request, config).await
    } else if let Ok(c) = serde_json::from_str::<StartRequestCommOnly>(&choices) {
        start_session_comm_only(c, config).await
    } else {
        Err(Error::BadRequest)
    }
}

#[post("/start", format = "application/x-www-form-urlencoded", data = "<choices>")]
pub async fn session_start_get(
    choices: Form<StartRequestFull>,
    config: &State<CoreConfig>,
) -> Result<ClientUrlResponse, Error> {
    session_start_full(choices.into_inner(), config).await
}

async fn session_start_full(
    choices: StartRequestFull,
    config: &State<CoreConfig>,
) -> Result<ClientUrlResponse, Error> {
    // Fetch purpose and methods
    let purpose = config.purpose(&choices.purpose)?;
    let auth_method = config.auth_method(purpose, &choices.auth_method)?;
    let comm_method = config.comm_method(purpose, &choices.comm_method)?;

    // Setup session
    let comm_data = comm_method.start(&purpose.tag).await?;
    let client_url = auth_method
        .start(
            &purpose.attributes,
            &comm_data.client_url,
            &comm_data.attr_url,
            config,
        )
        .await?;

    Ok(ClientUrlResponse { client_url })
}

async fn session_start_auth_only(
    choices: StartRequestAuthOnly,
    config: &State<CoreConfig>,
) -> Result<ClientUrlResponse, Error> {
    // Fetch purpose and methods
    let purpose = config.purpose(&choices.purpose)?;
    let auth_method = config.auth_method(purpose, &choices.auth_method)?;

    // Setup session
    let client_url = auth_method
        .start(
            &purpose.attributes,
            &choices.comm_url,
            &choices.attr_url,
            config,
        )
        .await?;

    Ok(ClientUrlResponse { client_url })
}

async fn start_session_comm_only(
    choices: StartRequestCommOnly,
    config: &State<CoreConfig>,
) -> Result<ClientUrlResponse, Error> {
    // Fetch purpose and methods
    let purpose = config.purpose(&choices.purpose)?;
    let comm_method = config.comm_method(purpose, &choices.comm_method)?;

    // Setup session
    let comm_data = comm_method
        .start_with_auth_result(&choices.purpose, &choices.auth_result)
        .await?;

    Ok(ClientUrlResponse {
        client_url: comm_data.client_url,
    })
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use figment::{
        providers::{Format, Toml},
        Figment,
    };
    use id_contact_comm_common::jwt::sign_start_auth_request;
    use id_contact_jwt::SignKeyConfig;
    use id_contact_proto::StartRequestAuthOnly;
    use josekit::jws::JwsSigner;
    use rocket::{
        http::{Accept, ContentType},
        local::blocking::Client,
    };
    use serde_json::json;

    use crate::{setup_routes, start::ClientUrlResponse};

    #[test]
    fn test_start_full() {
        let server = httpmock::MockServer::start();

        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(
                Toml::string(&format!(
                    r#"
[global]
server_url = ""
internal_url = ""
internal_secret = "sample_secret_1234567890178901237890"
ui_tel_url = ""

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
        let client = Client::tracked(setup_routes(rocket::custom(figment))).unwrap();

        let auth_mock = server.mock(|when, then| {
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
        let comm_mock = server.mock(|when, then| {
            when.path("/start_communication")
                .method(httpmock::Method::POST)
                .json_body(json!({
                    "purpose": "test",
                }));
            then.status(200)
                .header("Content-Type", "application/json")
                .json_body(json!({
                    "client_url": "https://example.com/continuation",
                    "attr_url": "https://example.com/attr_url",
                }));
        });

        let request = client
            .post("/start")
            .header(ContentType::JSON)
            .header(Accept::JSON)
            .body(r#"{"purpose":"test","auth_method":"test","comm_method":"test"}"#);
        let response = request.dispatch();
        auth_mock.assert();
        comm_mock.assert();
        assert_eq!(response.status(), rocket::http::Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::JSON));
        let body =
            serde_json::from_slice::<ClientUrlResponse>(&response.into_bytes().unwrap()).unwrap();
        assert_eq!(body.client_url, "https://example.com/client_url");
    }

    #[test]
    fn test_start_authonly_with_attrurl_unsigned_fails() {
        let server = httpmock::MockServer::start();

        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(
                Toml::string(&format!(
                    r#"
[global]
server_url = ""
internal_url = ""
internal_secret = "sample_secret_1234567890178901237890"
ui_tel_url = ""

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
        let client = Client::tracked(setup_routes(rocket::custom(figment))).unwrap();

        let request = client
            .post("/start")
            .header(ContentType::JSON)
            .header(Accept::JSON)
            .body(r#"{"purpose":"test","auth_method":"test","comm_url":"https://example.com/continuation","attr_url":"https://example.com/attr_url"}"#);
        let response = request.dispatch();
        assert_ne!(response.status(), rocket::http::Status::Ok);
    }

    #[test]
    fn test_start_authonly_with_attrurl_wrongsigned_fails() {
        let server = httpmock::MockServer::start();

        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(
                Toml::string(&format!(
                    r#"
[global]
server_url = ""
internal_url = ""
internal_secret = "sample_secret_1234567890178901237890"
ui_tel_url = ""

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
        let client = Client::tracked(setup_routes(rocket::custom(figment))).unwrap();

        let key = r#"{"type":"RSA","key":"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAz9FbZ9TtafmJB2h1ds0uIWD8PmZuK581/4DWPqoN0bgwoMWk\nIlcbl9lUF3LR2mds644Bv0Zx9buXanhYXPjrv0jtHhccb3tmkkHh6O5BrzEwH9Rh\n5YyLJ/YPqu0z5ExfNvpRNILriX1oMqdcrYxpvLMSw9i9Z43Jp3ahCNTMeVyi/xoI\n5SNiaaXV+12CMw32JeACBJB2dM7xqgh4tWp4gEQjTVKeRdgxOy7x5mgi7YIYhqGH\nMXBuzXhMuFPDe4GP3DwN77JhcjrJk5DX+H2u6DpWhpfshqWgyLT7FqCSgKK4Y/Ir\nmVTFBsKclE75EgFidwbT/tmEb59ng0RQG5GZcQIDAQABAoIBAEcg8fcc4tGVzffS\nIfoyiep0xoEZD/YwPQwhbbLvA2HXeBVe8CmsxM35XZXU/8yP/7Cz3xc3pkOkHFQd\nsqjHrfC/piDZaisiAl5m3EqcWbD71evfBk7KBsr7pisrmso19ZTcojSl5rYdTS+h\nJtBjscEbTX3ozhMGbZG6wa1DIGUc2JtTkvB42omY91XaimkFVaxLocjSjJGTBi5f\nDHxb7Tiw+dI/lnmAy93PkvzUG79/9FGKHorDMCEseIEiZkndiBoY5skH0mGOSY/k\nDxb6j0TUOHa1ndvlrFUciVw/Kjvv4hOGSJEUwRJ/l+7qr6pejQXfx/FEjC8K+vB0\nMSduxAECgYEA9cP4zIbB+kq3XdwVXicbDICjwVpKMjQORdm9mlAXbrsjRAfhf5Ap\nZgcdud7SJ/Y5shTwHwUK9qQktWkGNCH+7lXxxGy1LjcQx8QoqvfkPzJNCLlnRDJT\nSFhTudFIcgnHJoE1yYK5uSHcq25tQvNDA3GWjFggMcpPSLU4kDXZGUECgYEA2HjW\nLq8pmR9EpdrxiaMF0NOuj+MvqjOtoEJn+/7ycfkZlb9h+nYwvzCyCeIYAsyxmAP9\nBu0vH3rjBONrSREWO5cChmNhUdjnY6w22ZjrFJ7voPecRgZ4Es/lGfTSNCxJB5eo\nlLj+kGqaSw1Qdzwsum7H4ALjTidfALdAygwuxDECgYEAx2doGNpFzQSOXrNRCwGD\nqtM9CoZtqOofooEWm3vcZ1WjOXGDfvLDBCtF7SdjMFVRXrIqWaDH0nI/7oj2JZpn\ns408CnmBT6wSC2OW85EKOlRfuHJl3SlP9WTlGeE6fHx+fzlbINLWSeW1m8qPEEE7\n4DFrSxe9l2hkh8OxzyBBs4ECgYB1F9fzZLiBpVJCzM2+f7pTnU1dc6yCynVurL0G\nqH+IexAF2oIrMudnY/XKNsx6JzMhYXbq2j2VL6nBKSsNWPrHvQWWoAcyeLuhRLRe\nu8LdYqOIVKfpkPI+asooYi+aHSJbwwNjfzXj9GYFluwhsyEWr3naiHVf/xf6kSWw\npSpe4QKBgQDV0obbmvlG9o8FPa9JuuMuWPaedAQEe3KqlO8Ykg7N0PZRxS/o06EQ\nOP1g0YBX09oKwveCi8hEg9rzUsaVYYUMX+yo24RBu5ZINeM7Yl+WaB8U58fRk+Ol\nzuDnKwkeKVCxvMF8bckWB3vN6WJJ9CzukLmSi3JWUKNaojoXh3ZY2w==\n-----END RSA PRIVATE KEY-----"}"#;

        let signer =
            Box::<dyn JwsSigner>::try_from(serde_json::from_str::<SignKeyConfig>(key).unwrap())
                .unwrap();

        let request = sign_start_auth_request(
            StartRequestAuthOnly {
                purpose: "test".into(),
                auth_method: "test".into(),
                comm_url: "https://example.com/continuation".into(),
                attr_url: Some("https://example.com/attr_url".into()),
            },
            "test",
            signer.as_ref(),
        )
        .unwrap();

        let request = client
            .post("/start")
            .header(ContentType::new("application", "jwt"))
            .header(Accept::JSON)
            .body(request);
        let response = request.dispatch();
        assert_ne!(response.status(), rocket::http::Status::Ok);
    }

    #[test]
    fn test_start_authonly_with_attrurl() {
        let server = httpmock::MockServer::start();

        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(
                Toml::string(&format!(
                    r#"
[global]
server_url = ""
internal_url = ""
internal_secret = "sample_secret_1234567890178901237890"
ui_tel_url = ""

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
        let client = Client::tracked(setup_routes(rocket::custom(figment))).unwrap();

        let auth_mock = server.mock(|when, then| {
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

        let key = r#"{"type":"RSA","key":"-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDn/BGtPZPgYa+5\nBhxaMuv+UV7nWxNXYUt3cYBoyIc3xD9VP9cSE/+RnrTjaXUGPZWlnbIzG/b3gkrA\nEIg1zfjxUth34N+QycnjJf0tkcrZaR7q0JYEH2ZiAaMzAI11dzNuX3rHX8d69pOi\nu+T3WvMK/PDq9XTyO2msDI3lpgxTgjT9xUnCLTduH+yStoAHXXSZBKqLVBT/bPoe\nS5/v7/H9sALG+JYLI8J3/CRc2kWFNxGV8V7IpzLSnAXHU4sIMnWpjuhT7PXBzKl4\n4d6JRLGuJIeVZpPbiR74nvwYZWacJl278xG66fmG+BqJbGeEgGYTEljq9G4yXCRt\nGo5+3lBNAgMBAAECggEARY9EsaCMLbS83wrhB37LWneFsHOTqhjHaypCaajvOp6C\nqwo4b/hFIqHm9WWSrGtc6ssNOtwAwphz14Fdhlybb6j6tX9dKeoHui+S6c4Ud/pY\nReqDgPr1VR/OkqVwxS8X4dmJVCz5AHrdK+eRMUY5KCtOBfXRuixsdCVTiu+uNH99\nQC3kID1mmOF3B0chOK4WPN4cCsQpfOvoJfPBcJOtyxUSLlQdJH+04s3gVA24nCJj\n66+AnVkjgkyQ3q0Jugh1vo0ikrUW8uSLmg40sT5eYDN9jP6r5Gc8yDqsmYNVbLhU\npY8XR4gtzbtAXK8R2ISKNhOSuTv4SWFXVZiDIBkuIQKBgQD3qnZYyhGzAiSM7T/R\nWS9KrQlzpRV5qSnEp2sPG/YF+SGAdgOaWOEUa3vbkCuLCTkoJhdTp67BZvv/657Q\n2eK2khsYRs02Oq+4rYvdcAv/wS2vkMbg6CUp1w2/pwBvwFTXegr00k6IabXNcXBy\nkAjMsZqVDSdQByrf80AlFyEsOQKBgQDvyoUDhLReeDNkbkPHL/EHD69Hgsc77Hm6\nMEiLdNljTJLRUl+DuD3yKX1xVBaCLp9fMJ/mCrxtkldhW+i6JBHRQ7vdf11zNsRf\n2Cud3Q97RMHTacCHhEQDGnYkOQNTRhk8L31N0XBKfUu0phSmVyTnu2lLWmYJ8hyO\nyOEB19JstQKBgQC3oVw+WRTmdSBEnWREBKxb4hCv/ib+Hb8qYDew7DpuE1oTtWzW\ndC/uxAMBuNOQMzZ93kBNdnbMT19pUXpfwC2o0IvmZBijrL+9Xm/lr7410zXchqvu\n9jEX5Kv8/gYE1cYSPhsBiy1PV5HE0edeCg18N/M1sJsFa0sO4X0eAxhFgQKBgQC7\niQDkUooaBBn1ZsM9agIwSpUD8YTOGdDNy+tAnf9SSNXePXUT+CkCVm6UDnaYE8xy\nzv2PFUBu1W/fZdkqkwEYT8gCoBS/AcstRkw+Z2AvQQPxyxhXJBto7e4NwEUYgI9F\n4cI29SDEMR/fRbCKs0basVjVJPr+tkqdZP+MyHT6rQKBgQCT1YjY4F45Qn0Vl+sZ\nHqwVHvPMwVsexcRTdC0evaX/09s0xscSACvFJh5Dm9gnuMHElBcpZFATIvFcbV5Y\nMbJ/NNQiD63NEcL9VXwT96sMx2tnduOq4sYzu84kwPQ4ohxmPt/7xHU3L8SGqoec\nBs6neR/sZuHzNm8y/xtxj2ZAEw==\n-----END PRIVATE KEY-----"}"#;

        let signer =
            Box::<dyn JwsSigner>::try_from(serde_json::from_str::<SignKeyConfig>(key).unwrap())
                .unwrap();

        let request = sign_start_auth_request(
            StartRequestAuthOnly {
                purpose: "test".into(),
                auth_method: "test".into(),
                comm_url: "https://example.com/continuation".into(),
                attr_url: Some("https://example.com/attr_url".into()),
            },
            "test",
            signer.as_ref(),
        )
        .unwrap();

        let request = client
            .post("/start")
            .header(ContentType::new("application", "jwt"))
            .header(Accept::JSON)
            .body(request);
        let response = request.dispatch();
        auth_mock.assert();
        assert_eq!(response.status(), rocket::http::Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::JSON));
        let body =
            serde_json::from_slice::<ClientUrlResponse>(&response.into_bytes().unwrap()).unwrap();
        assert_eq!(body.client_url, "https://example.com/client_url");
    }

    #[test]
    fn test_start_authonly_without_attrurl() {
        let server = httpmock::MockServer::start();

        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(
                Toml::string(&format!(
                    r#"
[global]
server_url = ""
internal_url = ""
internal_secret = "sample_secret_1234567890178901237890"
ui_tel_url = ""

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
        let client = Client::tracked(setup_routes(rocket::custom(figment))).unwrap();

        let auth_mock = server.mock(|when, then| {
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

        let key = r#"{"type":"RSA","key":"-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDn/BGtPZPgYa+5\nBhxaMuv+UV7nWxNXYUt3cYBoyIc3xD9VP9cSE/+RnrTjaXUGPZWlnbIzG/b3gkrA\nEIg1zfjxUth34N+QycnjJf0tkcrZaR7q0JYEH2ZiAaMzAI11dzNuX3rHX8d69pOi\nu+T3WvMK/PDq9XTyO2msDI3lpgxTgjT9xUnCLTduH+yStoAHXXSZBKqLVBT/bPoe\nS5/v7/H9sALG+JYLI8J3/CRc2kWFNxGV8V7IpzLSnAXHU4sIMnWpjuhT7PXBzKl4\n4d6JRLGuJIeVZpPbiR74nvwYZWacJl278xG66fmG+BqJbGeEgGYTEljq9G4yXCRt\nGo5+3lBNAgMBAAECggEARY9EsaCMLbS83wrhB37LWneFsHOTqhjHaypCaajvOp6C\nqwo4b/hFIqHm9WWSrGtc6ssNOtwAwphz14Fdhlybb6j6tX9dKeoHui+S6c4Ud/pY\nReqDgPr1VR/OkqVwxS8X4dmJVCz5AHrdK+eRMUY5KCtOBfXRuixsdCVTiu+uNH99\nQC3kID1mmOF3B0chOK4WPN4cCsQpfOvoJfPBcJOtyxUSLlQdJH+04s3gVA24nCJj\n66+AnVkjgkyQ3q0Jugh1vo0ikrUW8uSLmg40sT5eYDN9jP6r5Gc8yDqsmYNVbLhU\npY8XR4gtzbtAXK8R2ISKNhOSuTv4SWFXVZiDIBkuIQKBgQD3qnZYyhGzAiSM7T/R\nWS9KrQlzpRV5qSnEp2sPG/YF+SGAdgOaWOEUa3vbkCuLCTkoJhdTp67BZvv/657Q\n2eK2khsYRs02Oq+4rYvdcAv/wS2vkMbg6CUp1w2/pwBvwFTXegr00k6IabXNcXBy\nkAjMsZqVDSdQByrf80AlFyEsOQKBgQDvyoUDhLReeDNkbkPHL/EHD69Hgsc77Hm6\nMEiLdNljTJLRUl+DuD3yKX1xVBaCLp9fMJ/mCrxtkldhW+i6JBHRQ7vdf11zNsRf\n2Cud3Q97RMHTacCHhEQDGnYkOQNTRhk8L31N0XBKfUu0phSmVyTnu2lLWmYJ8hyO\nyOEB19JstQKBgQC3oVw+WRTmdSBEnWREBKxb4hCv/ib+Hb8qYDew7DpuE1oTtWzW\ndC/uxAMBuNOQMzZ93kBNdnbMT19pUXpfwC2o0IvmZBijrL+9Xm/lr7410zXchqvu\n9jEX5Kv8/gYE1cYSPhsBiy1PV5HE0edeCg18N/M1sJsFa0sO4X0eAxhFgQKBgQC7\niQDkUooaBBn1ZsM9agIwSpUD8YTOGdDNy+tAnf9SSNXePXUT+CkCVm6UDnaYE8xy\nzv2PFUBu1W/fZdkqkwEYT8gCoBS/AcstRkw+Z2AvQQPxyxhXJBto7e4NwEUYgI9F\n4cI29SDEMR/fRbCKs0basVjVJPr+tkqdZP+MyHT6rQKBgQCT1YjY4F45Qn0Vl+sZ\nHqwVHvPMwVsexcRTdC0evaX/09s0xscSACvFJh5Dm9gnuMHElBcpZFATIvFcbV5Y\nMbJ/NNQiD63NEcL9VXwT96sMx2tnduOq4sYzu84kwPQ4ohxmPt/7xHU3L8SGqoec\nBs6neR/sZuHzNm8y/xtxj2ZAEw==\n-----END PRIVATE KEY-----"}"#;

        let signer =
            Box::<dyn JwsSigner>::try_from(serde_json::from_str::<SignKeyConfig>(key).unwrap())
                .unwrap();

        let request = sign_start_auth_request(
            StartRequestAuthOnly {
                purpose: "test".into(),
                auth_method: "test".into(),
                comm_url: "https://example.com/continuation".into(),
                attr_url: None,
            },
            "test",
            signer.as_ref(),
        )
        .unwrap();

        let request = client
            .post("/start")
            .header(ContentType::new("application", "jwt"))
            .header(Accept::JSON)
            .body(request);
        let response = request.dispatch();
        auth_mock.assert();
        assert_eq!(response.status(), rocket::http::Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::JSON));
        let body =
            serde_json::from_slice::<ClientUrlResponse>(&response.into_bytes().unwrap()).unwrap();
        assert_eq!(body.client_url, "https://example.com/client_url");
    }

    #[test]
    fn test_start_comm_only() {
        let server = httpmock::MockServer::start();

        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(
                Toml::string(&format!(
                    r#"
[global]
server_url = ""
internal_url = ""
internal_secret = "sample_secret_1234567890178901237890"
ui_tel_url = ""

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
        let client = Client::tracked(setup_routes(rocket::custom(figment))).unwrap();

        let comm_mock = server.mock(|when, then| {
            when.path("/start_communication")
                .method(httpmock::Method::POST)
                .json_body(json!({
                    "purpose": "test",
                    "auth_result": "test",
                }));
            then.status(200)
                .header("Content-Type", "application/json")
                .json_body(json!({
                    "client_url": "https://example.com/continuation",
                }));
        });

        let request = client
            .post("/start")
            .header(ContentType::JSON)
            .header(Accept::JSON)
            .body(r#"{"purpose":"test","comm_method":"test","auth_result":"test"}"#);
        let response = request.dispatch();
        comm_mock.assert();
        assert_eq!(response.status(), rocket::http::Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::JSON));
        let body =
            serde_json::from_slice::<ClientUrlResponse>(&response.into_bytes().unwrap()).unwrap();
        assert_eq!(body.client_url, "https://example.com/continuation");
    }

    #[test]
    fn test_start_invalid_auth() {
        let server = httpmock::MockServer::start();

        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(
                Toml::string(&format!(
                    r#"
[global]
server_url = ""
internal_url = ""
internal_secret = "sample_secret_1234567890178901237890"
ui_tel_url = ""

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
        let client = Client::tracked(setup_routes(rocket::custom(figment))).unwrap();

        let auth_mock = server.mock(|when, then| {
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
        let comm_mock = server.mock(|when, then| {
            when.path("/start_communication")
                .method(httpmock::Method::POST)
                .json_body(json!({
                    "purpose": "test",
                }));
            then.status(200)
                .header("Content-Type", "application/json")
                .json_body(json!({
                    "client_url": "https://example.com/continuation",
                    "attr_url": "https://example.com/attr_url",
                }));
        });

        let request = client
            .post("/start")
            .header(ContentType::JSON)
            .body(r#"{"purpose":"test","auth_method":"invalid","comm_method":"test"}"#);
        let response = request.dispatch();
        auth_mock.assert_hits(0);
        comm_mock.assert_hits(0);
        assert_ne!(response.status(), rocket::http::Status::Ok);
    }

    #[test]
    fn test_start_missing_auth() {
        let server = httpmock::MockServer::start();

        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(
                Toml::string(&format!(
                    r#"
[global]
server_url = ""
internal_url = ""
internal_secret = "sample_secret_1234567890178901237890"
ui_tel_url = ""

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
        let client = Client::tracked(setup_routes(rocket::custom(figment))).unwrap();

        let auth_mock = server.mock(|when, then| {
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
        let comm_mock = server.mock(|when, then| {
            when.path("/start_communication")
                .method(httpmock::Method::POST)
                .json_body(json!({
                    "purpose": "test",
                }));
            then.status(200)
                .header("Content-Type", "application/json")
                .json_body(json!({
                    "client_url": "https://example.com/continuation",
                    "attr_url": "https://example.com/attr_url",
                }));
        });

        let request = client
            .post("/start")
            .header(ContentType::JSON)
            .body(r#"{"purpose":"test","comm_method":"test"}"#);
        let response = request.dispatch();
        auth_mock.assert_hits(0);
        comm_mock.assert_hits(0);
        assert_ne!(response.status(), rocket::http::Status::Ok);
    }

    #[test]
    fn test_start_invalid_comm() {
        let server = httpmock::MockServer::start();

        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(
                Toml::string(&format!(
                    r#"
[global]
server_url = ""
internal_url = ""
internal_secret = "sample_secret_1234567890178901237890"
ui_tel_url = ""

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
        let client = Client::tracked(setup_routes(rocket::custom(figment))).unwrap();

        let auth_mock = server.mock(|when, then| {
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
        let comm_mock = server.mock(|when, then| {
            when.path("/start_communication")
                .method(httpmock::Method::POST)
                .json_body(json!({
                    "purpose": "test",
                }));
            then.status(200)
                .header("Content-Type", "application/json")
                .json_body(json!({
                    "client_url": "https://example.com/continuation",
                    "attr_url": "https://example.com/attr_url",
                }));
        });

        let request = client
            .post("/start")
            .header(ContentType::JSON)
            .body(r#"{"purpose":"test","auth_method":"test","comm_method":"invalid"}"#);
        let response = request.dispatch();
        auth_mock.assert_hits(0);
        comm_mock.assert_hits(0);
        assert_ne!(response.status(), rocket::http::Status::Ok);
    }

    #[test]
    fn test_start_missing_comm() {
        let server = httpmock::MockServer::start();

        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(
                Toml::string(&format!(
                    r#"
[global]
server_url = ""
internal_url = ""
internal_secret = "sample_secret_1234567890178901237890"
ui_tel_url = ""

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
        let client = Client::tracked(setup_routes(rocket::custom(figment))).unwrap();

        let auth_mock = server.mock(|when, then| {
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
        let comm_mock = server.mock(|when, then| {
            when.path("/start_communication")
                .method(httpmock::Method::POST)
                .json_body(json!({
                    "purpose": "test",
                }));
            then.status(200)
                .header("Content-Type", "application/json")
                .json_body(json!({
                    "client_url": "https://example.com/continuation",
                    "attr_url": "https://example.com/attr_url",
                }));
        });

        let request = client
            .post("/start")
            .header(ContentType::JSON)
            .body(r#"{"purpose":"test","auth_method":"test"}"#);
        let response = request.dispatch();
        auth_mock.assert_hits(0);
        comm_mock.assert_hits(0);
        assert_ne!(response.status(), rocket::http::Status::Ok);
    }

    #[test]
    fn test_start_invalid_purpose() {
        let server = httpmock::MockServer::start();

        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(
                Toml::string(&format!(
                    r#"
[global]
server_url = ""
internal_url = ""
internal_secret = "sample_secret_1234567890178901237890"
ui_tel_url = ""

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
        let client = Client::tracked(setup_routes(rocket::custom(figment))).unwrap();

        let auth_mock = server.mock(|when, then| {
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
        let comm_mock = server.mock(|when, then| {
            when.path("/start_communication")
                .method(httpmock::Method::POST)
                .json_body(json!({
                    "purpose": "test",
                }));
            then.status(200)
                .header("Content-Type", "application/json")
                .json_body(json!({
                    "client_url": "https://example.com/continuation",
                    "attr_url": "https://example.com/attr_url",
                }));
        });

        let request = client
            .post("/start")
            .header(ContentType::JSON)
            .body(r#"{"purpose":"invalid","auth_method":"test","comm_method":"test"}"#);
        let response = request.dispatch();
        auth_mock.assert_hits(0);
        comm_mock.assert_hits(0);
        assert_ne!(response.status(), rocket::http::Status::Ok);
    }

    #[test]
    fn test_start_missing_purpose() {
        let server = httpmock::MockServer::start();

        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(
                Toml::string(&format!(
                    r#"
[global]
server_url = ""
internal_url = ""
internal_secret = "sample_secret_1234567890178901237890"
ui_tel_url = ""

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
        let client = Client::tracked(setup_routes(rocket::custom(figment))).unwrap();

        let auth_mock = server.mock(|when, then| {
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
        let comm_mock = server.mock(|when, then| {
            when.path("/start_communication")
                .method(httpmock::Method::POST)
                .json_body(json!({
                    "purpose": "test",
                }));
            then.status(200)
                .header("Content-Type", "application/json")
                .json_body(json!({
                    "client_url": "https://example.com/continuation",
                    "attr_url": "https://example.com/attr_url",
                }));
        });

        let request = client
            .post("/start")
            .header(ContentType::JSON)
            .body(r#"{"auth_method":"test","comm_method":"test"}"#);
        let response = request.dispatch();
        auth_mock.assert_hits(0);
        comm_mock.assert_hits(0);
        assert_ne!(response.status(), rocket::http::Status::Ok);
    }

    #[test]
    fn test_start_invalid_json() {
        let server = httpmock::MockServer::start();

        let figment = Figment::from(rocket::Config::default())
            .select(rocket::Config::DEFAULT_PROFILE)
            .merge(
                Toml::string(&format!(
                    r#"
[global]
server_url = ""
internal_url = ""
internal_secret = "sample_secret_1234567890178901237890"
ui_tel_url = ""

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
        let client = Client::tracked(setup_routes(rocket::custom(figment))).unwrap();

        let auth_mock = server.mock(|when, then| {
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
        let comm_mock = server.mock(|when, then| {
            when.path("/start_communication")
                .method(httpmock::Method::POST)
                .json_body(json!({
                    "purpose": "test",
                }));
            then.status(200)
                .header("Content-Type", "application/json")
                .json_body(json!({
                    "client_url": "https://example.com/continuation",
                    "attr_url": "https://example.com/attr_url",
                }));
        });

        let request = client
            .post("/start")
            .header(ContentType::JSON)
            .body(r#"{sdlkfjb jks"#);
        let response = request.dispatch();
        auth_mock.assert_hits(0);
        comm_mock.assert_hits(0);
        assert_ne!(response.status(), rocket::http::Status::Ok);
    }
}
