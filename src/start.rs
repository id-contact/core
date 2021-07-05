use crate::error::Error;
use crate::{config::CoreConfig, methods::Tag};
use rocket::{State, response::{Redirect, Responder}, Request, Response, http::Status};
use rocket_contrib::json::Json;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
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
                client_url: self.client_url
            })).respond_to(req)
        }

        return Some(Redirect::to(self.client_url)).respond_to(req);
    }
}

#[post("/start", format = "application/json", data = "<choices>")]
pub async fn session_start(
    choices: String,
    config: State<'_, CoreConfig>,
) -> Result<ClientUrlResponse, Error> {
    // Workaround for issue where matching routes based on json body structure does not works as expected
    if let Ok(start_request) = serde_json::from_str::<StartRequestFull>(&choices) {
        session_start_full(start_request, config).await
    } else if let Ok(start_request) = serde_json::from_str::<StartRequestAuthOnly>(&choices) {
        session_start_auth_only(start_request, config).await
    } else if let Ok(c) = serde_json::from_str::<StartRequestCommOnly>(&choices) {
        start_session_comm_only(c, config).await
    } else {
        Err(Error::BadRequest)
    }
}

async fn session_start_full(
    choices: StartRequestFull,
    config: State<'_, CoreConfig>,
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
            &config,
        )
        .await?;

     Ok(ClientUrlResponse { client_url })
}

async fn session_start_auth_only(
    choices: StartRequestAuthOnly,
    config: State<'_, CoreConfig>,
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
            &config,
        )
        .await?;

    Ok(ClientUrlResponse { client_url })
}

async fn start_session_comm_only(
    choices: StartRequestCommOnly,
    config: State<'_, CoreConfig>,
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
    use figment::{
        providers::{Format, Toml},
        Figment,
    };
    use rocket::{http::{ContentType, Accept}, local::blocking::Client};
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

        let request = client
            .post("/start")
            .header(ContentType::JSON)
            .header(Accept::JSON)
            .body(r#"{"purpose":"test","auth_method":"test","comm_url":"https://example.com/continuation","attr_url":"https://example.com/attr_url"}"#);
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

        let request = client
            .post("/start")
            .header(ContentType::JSON)
            .header(Accept::JSON)
            .body(r#"{"purpose":"test","auth_method":"test","comm_url":"https://example.com/continuation"}"#);
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
