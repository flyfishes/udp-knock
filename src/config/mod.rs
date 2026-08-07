mod settings;

pub use settings::*;

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub client: ClientConfig,
    pub security: SecurityConfig,
    pub debug: bool,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind_addr: SocketAddr,
    pub allowed_clients: Vec<SocketAddr>,
    pub firewall: FirewallConfig,
    pub rate_limit: RateLimitConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server_addr: SocketAddr,
    pub timeout_secs: u64,
    pub retry_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub shared_key: String,
    pub timestamp_window_secs: i64,
    pub max_packet_size: usize,
    pub key_derivation_iterations: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    #[serde(default = "default_firewall_type")]
    pub firewall_type: String,
    pub default_zone: String,
    pub forward_chain: String,
    pub input_chain: String,
    pub output_chain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub max_requests_per_minute: u32,
    pub burst_size: u32,
}

fn default_firewall_type() -> String {
    "auto".to_string()
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn default_for_platform(platform: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config = match platform {
            "openwrt" => Self::default_openwrt(),
            "linux" => Self::default_linux(),
            "windows" => Self::default_windows(),
            _ => Self::default(),
        };
        Ok(config)
    }

    fn default_openwrt() -> Self {
        let mut config = Self::default();
        config.platform = "openwrt".to_string();
        config.server.firewall.firewall_type = "openwrt".to_string();
        config.server.firewall.default_zone = "lan".to_string();
        config.server.firewall.forward_chain = "forwarding_rule".to_string();
        config
    }

    fn default_linux() -> Self {
        let mut config = Self::default();
        config.platform = "linux".to_string();
        config.server.firewall.firewall_type = "iptables".to_string();
        config.server.firewall.default_zone = "public".to_string();
        config.server.firewall.forward_chain = "FORWARD".to_string();
        config
    }

    fn default_windows() -> Self {
        let mut config = Self::default();
        config.platform = "windows".to_string();
        config.server.firewall.firewall_type = "windows".to_string();
        config.server.firewall.default_zone = "Public".to_string();
        config.server.firewall.forward_chain = "Forward".to_string();
        config
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                bind_addr: "0.0.0.0:8888".parse().unwrap(),
                allowed_clients: vec![],
                firewall: FirewallConfig {
                    firewall_type: "auto".to_string(),
                    default_zone: "public".to_string(),
                    forward_chain: "FORWARD".to_string(),
                    input_chain: "INPUT".to_string(),
                    output_chain: "OUTPUT".to_string(),
                },
                rate_limit: RateLimitConfig {
                    max_requests_per_minute: 60,
                    burst_size: 10,
                },
            },
            client: ClientConfig {
                server_addr: "127.0.0.1:8888".parse().unwrap(),
                timeout_secs: 5,
                retry_count: 3,
            },
            security: SecurityConfig {
                shared_key: "change_this_default_key_1234567890".to_string(),
                timestamp_window_secs: 30,
                max_packet_size: 4096,
                key_derivation_iterations: 100000,
            },
            debug: false,
            platform: "unknown".to_string(),
        }
    }
}