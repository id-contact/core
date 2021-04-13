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
use rocket::fairing::AdHoc;
use start::{session_start_auth_only, session_start_full, start_session_comm_only};

#[launch]
fn boot() -> rocket::Rocket {
    log::set_boxed_logger(Box::new(sentry::SentryLogger::new(Box::new(
        env_logger::builder().parse_default_env().build(),
    ))))
    .expect("failure to setup loggin");

    let base = setup_routes(rocket::ignite());
    let config = base
        .figment()
        .extract::<CoreConfig>()
        .expect("Could not parse configuration");
    match config.sentry_dsn() {
        Some(dsn) => base.attach(sentry::SentryFairing::new(dsn)),
        None => base,
    }
}

fn setup_routes(base: rocket::Rocket) -> rocket::Rocket {
    base.mount(
        "/",
        routes![
            session_options,
            session_start_full,
            session_start_auth_only,
            start_session_comm_only,
            auth_attr_shim,
        ],
    )
    .attach(AdHoc::config::<CoreConfig>())
}
