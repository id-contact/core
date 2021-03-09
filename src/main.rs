mod config;
mod methods;
mod options;
mod start;
mod error;

#[macro_use]
extern crate rocket;

use config::CoreConfig;
use options::session_options;
use start::{session_start_auth_only, session_start_full, start_session_comm_only};
use std::env;

#[launch]
fn rocket() -> rocket::Rocket {
    let config_filename = env::var("IDC_CORE_CONFIG_FILE")
        .expect("No config file path defined, please set IDC_CORE_CONFIG_FILE");

    rocket::ignite()
        .manage(CoreConfig::from_file(&config_filename))
        .mount(
            "/",
            routes![
                session_options,
                session_start_full,
                session_start_auth_only,
                start_session_comm_only
            ],
        )
}
