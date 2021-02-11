use crate::methods::Tag;
use rocket_contrib::json::Json;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct MethodChoices {
    purpose: String,
    auth_method: Tag,
    comm_method: Tag,
}

#[derive(Debug, Serialize)]
pub struct ClientUrlResponse {
    client_url: String,
}

#[post("/start", format = "json", data = "<choices>")]
pub fn session_start(choices: Json<MethodChoices>) -> Json<ClientUrlResponse> {
    println!("Choices: {:?}", choices);

    Json(ClientUrlResponse {
        client_url: "https://youtu.be/dQw4w9WgXcQ".to_string(),
    })
}
