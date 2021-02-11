use crate::config::CoreConfig;
use crate::methods::{Method, Tag};
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
    fn filter_methods_by_purpose<T: Method>(
        methods: &[T],
        purpose: &str,
    ) -> Vec<MethodProperties> {
        methods
            .iter()
            .filter(|&method| method.supports(purpose))
            .map(|method| MethodProperties {
                tag: String::from(method.tag()),
                name: String::from(method.name()),
                image_path: String::from(method.image_path()),
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
pub fn session_options(purpose: String, config: State<CoreConfig>) -> Json<SessionOptions> {
    let auth_methods = MethodProperties::filter_methods_by_purpose(&config.auth_methods, &purpose);
    let comm_methods = MethodProperties::filter_methods_by_purpose(&config.comm_methods, &purpose);

    Json(SessionOptions {
        auth_methods,
        comm_methods,
    })
}
