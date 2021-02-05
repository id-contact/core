use crate::methods::{AuthenticationMethod, CommunicationMethod};
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct CoreConfig {
    pub auth_methods: Vec<AuthenticationMethod>,
    pub comm_methods: Vec<CommunicationMethod>,
}

impl CoreConfig {
    pub fn from_file(filename: &str) -> CoreConfig {
        let contents = fs::read_to_string(filename)
            .expect(&format!("Could not read the config file {}", filename));

        let config: CoreConfig = serde_yaml::from_str(&contents)
            .expect(&format!("Error parsing the config file {}", filename));

        config
    }
}
