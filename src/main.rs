mod config;
mod methods;
mod options;

#[macro_use]
extern crate rocket;

use config::CoreConfig;
use options::session_options;
use std::env;

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
