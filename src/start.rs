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

#[derive(Debug, Serialize)]
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
