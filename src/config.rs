use serde::{Deserialize, Serialize};

use crate::BannedConnection;

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    /// The port to listen on for proxy connections. IP:PORT
    pub proxy_host: String,
    /// The address of the auth server to proxy to. IP:PORT
    pub auth_host: String,
    /// Set the amount of connections to allow before dropping new connections.
    // this prevents syn flood attacks
    pub max_connections: usize,
    /// The amount of seconds to wait before dropping a connection.
    pub connection_timeout: u16,
    /// File to write banned ip addresses to.
    pub ban_file: String,
    /// File to write logs to.
    pub log_file: String,
    /// Invalid data sent from the client until banned.
    pub max_invalid_packets: u32,

    #[serde(skip_deserializing)]
    pub banned_connections: Vec<BannedConnection>,
}

impl Config {
    pub fn new() -> Result<Self, std::io::Error> {
        Ok(serde_json::from_reader(std::fs::File::open(
            "config.json",
        )?)?)
    }
}
