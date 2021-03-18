use std::collections::HashMap;

use crate::methods::{Method, Tag};
use crate::{config::CoreConfig, error::Error};
use rocket::State;
use rocket_contrib::json::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
pub struct SessionOptions {
    auth_methods: Vec<MethodProperties>,
    comm_methods: Vec<MethodProperties>,
}

#[get("/session_options/<purpose>")]
pub fn session_options(
    purpose: String,
    config: State<CoreConfig>,
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
