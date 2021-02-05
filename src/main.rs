#[macro_use]
extern crate rocket;

use rocket_contrib::json::Json;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use rocket::State;

type Tag = String;

trait Method {
    fn tag(&self) -> &Tag;
    fn name(&self) -> &String;
    fn image_path(&self) -> &String;
    fn supports(&self, purpose: &String) -> bool;
}

#[derive(Debug, Deserialize)]
struct AuthenticationMethod {
    tag: Tag,
    name: String,
    image_path: String,
    start: String,
}

impl Method for AuthenticationMethod {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn name(&self) -> &String {
        &self.name
    }

    fn image_path(&self) -> &String {
        &self.image_path
    }

    fn supports(&self, _purpose: &String) -> bool {
        true
    }
}

#[derive(Debug, Deserialize)]
struct CommunicationMethod {
    tag: Tag,
    name: String,
    image_path: String,
    start: String,
    purposes: Vec<String>,
}

impl Method for CommunicationMethod {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn name(&self) -> &String {
        &self.name
    }

    fn image_path(&self) -> &String {
        &self.image_path
    }

    fn supports(&self, purpose: &String) -> bool {
        self.purposes.contains(purpose)
    }
}

#[derive(Debug, Deserialize)]
struct CoreConfig {
    auth_methods: Vec<AuthenticationMethod>,
    comm_methods: Vec<CommunicationMethod>,
}

impl CoreConfig {
    fn from_file(filename: &str) -> CoreConfig {
        let contents = fs::read_to_string(filename)
            .expect(&format!("Could not read the config file {}", filename));

        let config: CoreConfig = serde_yaml::from_str(&contents)
            .expect(&format!("Error parsing the config file {}", filename));

        config
    }
}

#[derive(Debug, Serialize)]
struct MethodProperties {
    tag: Tag,
    name: String,
    image_path: String,
}

impl MethodProperties {
    fn filter_methods_by_purpose<T: Method>(methods: &Vec<T>, purpose: &String) -> Vec<MethodProperties> {
        methods
            .iter()
            .filter(|&method| method.supports(purpose))
            .map(|method| {
                MethodProperties {
                    tag: String::from(method.tag()),
                    name: String::from(method.name()),
                    image_path: String::from(method.image_path()),
                }
            })
            .collect()
    }
}

#[derive(Debug, Serialize)]
struct SessionOptions {
    auth_methods: Vec<MethodProperties>,
    comm_methods: Vec<MethodProperties>,
}

#[get("/session_options/<purpose>")]
fn session_options(purpose: String, config: State<CoreConfig>) -> Json<SessionOptions> {
    let auth_methods = MethodProperties::filter_methods_by_purpose(&config.auth_methods, &purpose);
    let comm_methods = MethodProperties::filter_methods_by_purpose(&config.comm_methods, &purpose);

    Json(SessionOptions {
        auth_methods,
        comm_methods,
    })
}

#[post("/start")]
fn start() -> &'static str {
    "Hello, world!"
}

#[launch]
fn rocket() -> rocket::Rocket {
    let config_filename = env::var("IDC_CORE_CONFIG_FILE")
        .expect("No config file path defined, please set IDC_CORE_CONFIG_FILE");

    rocket::ignite()
        .manage(CoreConfig::from_file(&config_filename))
        .mount("/", routes![session_options, start])
}
