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
            .unwrap_or_else(|_| panic!("Could not read the config file {}", filename));

        let config: CoreConfig = serde_yaml::from_str(&contents)
            .unwrap_or_else(|_| panic!("Error parsing the config file {}", filename));

        config
    }
}
