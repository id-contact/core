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

#[post("/start", format = "json", data = "<choices>", rank = 1)]
pub async fn session_start_full(
    choices: Json<StartRequestFull>,
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

#[post("/start", format = "json", data = "<choices>", rank = 2)]
pub async fn session_start_auth_only(
    choices: Json<StartRequestAuthOnly>,
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

#[post("/start", format = "json", data = "<choices>", rank = 3)]
pub async fn start_session_comm_only(
    choices: Json<StartRequestCommOnly>,
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
