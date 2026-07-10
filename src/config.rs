use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
pub struct Config {
    pub postgres_connection_url: String,
    pub port: String,
    pub dns: DnsConfig,
    pub reconciler_interval_secs: u64,
}

#[derive(Deserialize)]
pub struct DnsConfig {
    pub addr: String,
    pub key_name: String,
    pub key: String,
}

impl Config {
    pub fn from_file(path: &str) -> Self {
        let file =
            fs::File::open(path).unwrap_or_else(|_| panic!("No config file found at {path}"));
        serde_json::from_reader(file).expect("unable to parse config.json")
    }
}
