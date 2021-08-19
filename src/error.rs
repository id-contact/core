use std::{error::Error as StdError, fmt::Display};

#[derive(Debug)]
pub enum Error {
    NoSuchMethod(String),
    NoSuchPurpose(String),
    Reqwest(reqwest::Error),
    BadRequest,
    Jwt(josekit::JoseError),
    Json(serde_json::Error),
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Error {
        Error::Reqwest(e)
    }
}

impl From<josekit::JoseError> for Error {
    fn from(e: josekit::JoseError) -> Error {
        Error::Jwt(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::Json(e)
    }
}

impl<'r, 'o: 'r> rocket::response::Responder<'r, 'o> for Error {
    fn respond_to(self, request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        match self {
            Error::NoSuchMethod(m) => {
                let bad_request = rocket::response::status::BadRequest::<()>(None);
                log::error!("Unknown method {}", m);
                bad_request.respond_to(request)
            }
            Error::NoSuchPurpose(m) => {
                let bad_request = rocket::response::status::BadRequest::<()>(None);
                log::error!("Unknown purpose {}", m);
                bad_request.respond_to(request)
            }
            Error::BadRequest => {
                let bad_request = rocket::response::status::BadRequest::<()>(None);
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
            Error::Jwt(e) => e.fmt(f),
            Error::Json(e) => e.fmt(f),
            Error::BadRequest => f.write_str("Bad request"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Reqwest(e) => Some(e),
            Error::Jwt(e) => Some(e),
            Error::Json(e) => Some(e),
            _ => None,
        }
    }
}
