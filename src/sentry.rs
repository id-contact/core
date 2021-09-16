use log::Log;
use rocket::{
    fairing::{Fairing, Info, Kind},
    Request, Response,
};
use sentry::ClientInitGuard;

pub struct SentryLogger {
    inner: Box<dyn Log>,
}

impl SentryLogger {
    pub fn new(inner: Box<dyn Log>) -> SentryLogger {
        SentryLogger { inner }
    }
}

impl Log for SentryLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Warn || self.inner.enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        self.inner.log(record);

        if record.level() <= log::Level::Warn {
            // Choices here might need review in future.
            // The current mapping puts the location of the log function
            // as culprit, but sentry's documentation is extremely cagey
            // about where that sort of information needs to go, and in
            // general on when to use culprit vs transaction vs tags
            // vs extra.
            let uuid = sentry::types::Uuid::new_v4();
            let event = sentry::protocol::Event {
                event_id: uuid,
                message: Some(format!("{}", record.args())),
                logger: Some(record.target().into()),
                culprit: Some(format!(
                    "{}: {}:{}",
                    record.module_path().unwrap_or("(unknown_module)"),
                    record.file().unwrap_or("(unknown_file)"),
                    record.line().unwrap_or(0),
                )),
                level: sentry::Level::Info,
                ..Default::default()
            };
            sentry::capture_event(event);
        }
    }

    fn flush(&self) {
        todo!()
    }
}

pub struct SentryFairing {
    _guard: ClientInitGuard,
}

impl SentryFairing {
    pub fn new(dsn: &str) -> SentryFairing {
        return SentryFairing {
            _guard: sentry::init((
                dsn,
                sentry::ClientOptions {
                    release: sentry::release_name!(),
                    ..Default::default()
                },
            )),
        };
    }
}

#[rocket::async_trait]
impl Fairing for SentryFairing {
    // This is a request and response fairing named "GET/POST Counter".
    fn info(&self) -> Info {
        Info {
            name: "Sentry",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        if response.status().code < 200 || response.status().code >= 400 {
            sentry::capture_message(
                &format!(
                    "Abnormal response {} ({}), on request for {} ({})",
                    response.status().code,
                    response.status().reason().unwrap_or("Unknown reason"),
                    request.uri(),
                    match request.route() {
                        Some(r) => match &r.name {
                            Some(name) => name,
                            None => "Unnamed route",
                        },
                        None => "No route associated",
                    },
                ),
                sentry::Level::Error,
            );
        }
    }
}
