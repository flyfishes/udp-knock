// src/config/settings.rs

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// 主配置结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub client: ClientConfig,
    pub security: SecurityConfig,
    pub debug: bool,
    pub platform: String,
}

/// 服务器配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind_addr: SocketAddr,
    pub allowed_clients: Vec<SocketAddr>,
    pub firewall: FirewallConfig,
    pub rate_limit: RateLimitConfig,
}

/// 客户端配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server_addr: SocketAddr,
    pub timeout_secs: u64,
    pub retry_count: u32,
}

/// 安全配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub shared_key: String,
    pub timestamp_window_secs: i64,
    pub max_packet_size: usize,
    pub key_derivation_iterations: u32,
}

/// 防火墙配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    #[serde(default = "default_firewall_type")]
    pub firewall_type: String,
    pub default_zone: String,
    pub forward_chain: String,
    pub input_chain: String,
    pub output_chain: String,
}

/// 速率限制配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub max_requests_per_minute: u32,
    pub burst_size: u32,
}

/// 默认防火墙类型
fn default_firewall_type() -> String {
    "auto".to_string()
}

impl Config {
    /// 从文件加载配置
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// 为指定平台生成默认配置
    pub fn default_for_platform(platform: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config = match platform {
            "openwrt" => Self::default_openwrt(),
            "linux" => Self::default_linux(),
            "windows" => Self::default_windows(),
            _ => Self::default(),
        };
        Ok(config)
    }

    /// OpenWrt 平台默认配置
    fn default_openwrt() -> Self {
        let mut config = Self::default();
        config.platform = "openwrt".to_string();
        config.server.firewall.firewall_type = "openwrt".to_string();
        config.server.firewall.default_zone = "lan".to_string();
        config.server.firewall.forward_chain = "forwarding_rule".to_string();
        config.server.firewall.input_chain = "input_rule".to_string();
        config.server.firewall.output_chain = "output_rule".to_string();
        config
    }

    /// Linux 平台默认配置
    fn default_linux() -> Self {
        let mut config = Self::default();
        config.platform = "linux".to_string();
        config.server.firewall.firewall_type = "iptables".to_string();
        config.server.firewall.default_zone = "public".to_string();
        config.server.firewall.forward_chain = "FORWARD".to_string();
        config.server.firewall.input_chain = "INPUT".to_string();
        config.server.firewall.output_chain = "OUTPUT".to_string();
        config
    }

    /// Windows 平台默认配置
    fn default_windows() -> Self {
        let mut config = Self::default();
        config.platform = "windows".to_string();
        config.server.firewall.firewall_type = "windows".to_string();
        config.server.firewall.default_zone = "Public".to_string();
        config.server.firewall.forward_chain = "Forward".to_string();
        config.server.firewall.input_chain = "Input".to_string();
        config.server.firewall.output_chain = "Output".to_string();
        config
    }

    /// 保存配置到文件
    pub fn save_to_file(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.server.bind_addr, "0.0.0.0:8888".parse().unwrap());
        assert_eq!(config.security.timestamp_window_secs, 30);
        assert!(!config.debug);
    }

    #[test]
    fn test_openwrt_config() {
        let config = Config::default_openwrt();
        assert_eq!(config.platform, "openwrt");
        assert_eq!(config.server.firewall.firewall_type, "openwrt");
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(config.server.bind_addr, parsed.server.bind_addr);
        assert_eq!(config.security.shared_key, parsed.security.shared_key);
    }
}