use crate::methods::{AuthenticationMethod, CommunicationMethod, Method};
use serde::Deserialize;
use std::{collections::HashMap, fs};

#[derive(Debug, Deserialize)]
struct RawCoreConfig {
    auth_methods: Vec<AuthenticationMethod>,
    comm_methods: Vec<CommunicationMethod>,
    purpose_attributes: HashMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(from = "RawCoreConfig")]
pub struct CoreConfig {
    pub auth_methods: HashMap<String, AuthenticationMethod>,
    pub comm_methods: HashMap<String, CommunicationMethod>,
    pub purpose_attributes: HashMap<String, Vec<String>>,
}

impl From<RawCoreConfig> for CoreConfig {
    fn from(config: RawCoreConfig) -> Self {
        CoreConfig {
            auth_methods: config.auth_methods.iter().map(|m| { (m.tag().clone(), m.clone()) }).collect(),
            comm_methods: config.comm_methods.iter().map(|m| { (m.tag().clone(), m.clone()) }).collect(),
            purpose_attributes: config.purpose_attributes,
        }
    }
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
