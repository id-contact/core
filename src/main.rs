mod config;
mod error;
mod methods;
mod options;
mod sentry;
mod start;

#[macro_use]
extern crate rocket;

use config::CoreConfig;
use methods::auth_attr_shim;
use options::session_options;
use start::{session_start_auth_only, session_start_full, start_session_comm_only};
use std::env;

#[launch]
fn boot() -> rocket::Rocket {
    log::set_boxed_logger(Box::new(sentry::SentryLogger::new(Box::new(
        env_logger::builder().parse_default_env().build(),
    ))))
    .expect("failure to setup loggin");

    let config_filename = env::var("IDC_CORE_CONFIG_FILE")
        .expect("No config file path defined, please set IDC_CORE_CONFIG_FILE");

    rocket(CoreConfig::from_file(&config_filename))
}

fn rocket(config: CoreConfig) -> rocket::Rocket {
    let sentry_fairing = config.sentry_dsn().map(|dsn| sentry::SentryFairing::new(dsn));

    let base = rocket::ignite().manage(config).mount(
        "/",
        routes![
            session_options,
            session_start_full,
            session_start_auth_only,
            start_session_comm_only,
            auth_attr_shim,
        ],
    );

    match sentry_fairing {
        Some(sentry) => base.attach(sentry),
        None => base,
    }
}
