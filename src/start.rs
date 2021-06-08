use crate::error::Error;
use crate::{config::CoreConfig, methods::Tag};
use rocket::State;
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

#[post("/start", format = "application/json", data = "<choices>")]
pub async fn session_start(
    choices: String,
    config: State<'_, CoreConfig>,
) -> Result<Json<ClientUrlResponse>, Error> {
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
) -> Result<Json<ClientUrlResponse>, Error> {
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

    Ok(Json(ClientUrlResponse { client_url }))
}

async fn session_start_auth_only(
    choices: StartRequestAuthOnly,
    config: State<'_, CoreConfig>,
) -> Result<Json<ClientUrlResponse>, Error> {
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

    Ok(Json(ClientUrlResponse { client_url }))
}

async fn start_session_comm_only(
    choices: StartRequestCommOnly,
    config: State<'_, CoreConfig>,
) -> Result<Json<ClientUrlResponse>, Error> {
    // Fetch purpose and methods
    let purpose = config.purpose(&choices.purpose)?;
    let comm_method = config.comm_method(purpose, &choices.comm_method)?;

    // Setup session
    let comm_data = comm_method
        .start_with_auth_result(&choices.purpose, &choices.auth_result)
        .await?;

    Ok(Json(ClientUrlResponse {
        client_url: comm_data.client_url,
    }))
}

#[cfg(test)]
mod tests {
    use figment::{
        providers::{Format, Toml},
        Figment,
    };
    use rocket::{http::ContentType, local::blocking::Client};
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
