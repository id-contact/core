mod auth;
mod comm;

pub use auth::{auth_attr_shim, AuthenticationMethod};
pub use comm::CommunicationMethod;

pub type Tag = String;

pub trait Method {
    fn tag(&self) -> &Tag;
    fn name(&self) -> &str;
    fn image_path(&self) -> &str;
}
