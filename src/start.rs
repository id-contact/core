use crate::{config::CoreConfig, methods::Tag};
use rocket::State;
use rocket_contrib::json::Json;
use serde::{Deserialize, Serialize};
use std::{error::Error as StdError, fmt::Display};

#[derive(Debug, Deserialize)]
pub struct StartRequestFull {
    purpose: String,
    auth_method: Tag,
    comm_method: Tag,
}

#[derive(Debug, Deserialize)]
pub struct StartRequestCommOnly {
    purpose: String,
    attributes: String,
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

#[derive(Debug)]
pub enum Error {
    NoSuchMethod(String),
    NoSuchPurpose(String),
    Reqwest(reqwest::Error),
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Error {
        Error::Reqwest(e)
    }
}

impl<'r, 'o: 'r> rocket::response::Responder<'r, 'o> for Error {
    fn respond_to(self, request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        match self {
            Error::NoSuchMethod(m) => {
                let bad_request = rocket::response::status::BadRequest::<()>(None);
                println!("Unknown method {}", m);
                bad_request.respond_to(request)
            }
            Error::NoSuchPurpose(m) => {
                let bad_request = rocket::response::status::BadRequest::<()>(None);
                println!("Unknown purpose {}", m);
                bad_request.respond_to(request)
            }
            _ => {
                let debug_error = rocket::response::Debug::from(self);
                debug_error.respond_to(request)
            }
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NoSuchMethod(m) => f.write_fmt(format_args!("No such method: {}", m)),
            Error::NoSuchPurpose(m) => f.write_fmt(format_args!("No such purpose: {}", m)),
            Error::Reqwest(e) => e.fmt(f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Reqwest(e) => Some(e),
            _ => None,
        }
    }
}

#[post("/start", format = "json", data = "<choices>", rank=1)]
pub async fn session_start_full(
    choices: Json<StartRequestFull>,
    config: State<'_, CoreConfig>,
) -> Result<Json<ClientUrlResponse>, Error> {
    // Check presence of purpose
    let purpose = config
        .purposes
        .get(&choices.purpose)
        .ok_or_else(|| Error::NoSuchPurpose(choices.purpose.clone()))?;

    // Check and fetch auth method
    if !purpose.allowed_auth.contains(&choices.auth_method) {
        return Err(Error::NoSuchMethod(choices.auth_method.clone()));
    }
    let auth_method = config
        .auth_methods
        .get(&choices.auth_method)
        .ok_or_else(|| Error::NoSuchMethod(choices.auth_method.clone()))?;

    // Check and fetch comm method
    if !purpose.allowed_comm.contains(&choices.comm_method) {
        return Err(Error::NoSuchMethod(choices.comm_method.clone()));
    }
    let comm_method = config
        .comm_methods
        .get(&choices.comm_method)
        .ok_or_else(|| Error::NoSuchMethod(choices.comm_method.clone()))?;

    let comm_data = comm_method.start(&purpose.tag).await?;
    let client_url = auth_method
        .start(
            &purpose.attributes,
            &comm_data.client_url,
            &comm_data.attr_url,
        )
        .await?;

    Ok(Json(ClientUrlResponse { client_url }))
}

#[post("/start", format = "json", data = "<choices>", rank=2)]
pub async fn session_start_auth_only(
    choices: Json<StartRequestAuthOnly>,
    config: State<'_, CoreConfig>,
) -> Result<Json<ClientUrlResponse>, Error> {
    // Check presence of purpose
    let purpose = config
        .purposes
        .get(&choices.purpose)
        .ok_or_else(|| Error::NoSuchPurpose(choices.purpose.clone()))?;

    // Check and fetch auth method
    if !purpose.allowed_auth.contains(&choices.auth_method) {
        return Err(Error::NoSuchMethod(choices.auth_method.clone()));
    }
    let auth_method = config
        .auth_methods
        .get(&choices.auth_method)
        .ok_or_else(|| Error::NoSuchMethod(choices.auth_method.clone()))?;

    let client_url = auth_method
        .start(&purpose.attributes, &choices.comm_url, &choices.attr_url)
        .await?;

    Ok(Json(ClientUrlResponse { client_url }))
}

#[post("/start", format = "json", data = "<choices>", rank=3)]
pub async fn start_session_comm_only(
    choices: Json<StartRequestCommOnly>,
    config: State<'_, CoreConfig>,
) -> Result<Json<ClientUrlResponse>, Error> {
    // Check presence of purpose
    let purpose = config
        .purposes
        .get(&choices.purpose)
        .ok_or_else(|| Error::NoSuchPurpose(choices.purpose.clone()))?;

    // Check and fetch comm method
    if !purpose.allowed_comm.contains(&choices.comm_method) {
        return Err(Error::NoSuchMethod(choices.comm_method.clone()));
    }
    let comm_method = config
        .comm_methods
        .get(&choices.comm_method)
        .ok_or_else(|| Error::NoSuchMethod(choices.comm_method.clone()))?;

    let comm_data = comm_method
        .start_with_attributes(&choices.purpose, &choices.attributes)
        .await?;

    Ok(Json(ClientUrlResponse {
        client_url: comm_data.client_url,
    }))
}
