use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub client: ClientConfig,
    #[serde(default = "default_platform")]
    pub platform: String,
    #[serde(default)]
    pub debug: bool,
}

fn default_platform() -> String {
    "openwrt".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub shared_key: String,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u32,
}

fn default_rate_limit() -> u32 {
    60
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server_addr: String,
    pub shared_key: String,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

fn default_timeout() -> u64 {
    5
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                bind_addr: "0.0.0.0:9999".to_string(),
                shared_key: "change_this_shared_secret_key".to_string(),
                allowed_ips: Vec::new(),
                rate_limit: 60,
            },
            client: ClientConfig {
                server_addr: "127.0.0.1:9999".to_string(),
                shared_key: "change_this_shared_secret_key".to_string(),
                timeout: 5,
            },
            platform: "openwrt".to_string(),
            debug: false,
        }
    }
}

impl Config {
    pub fn load_or_default<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> {
        if path.as_ref().exists() {
            let content = fs::read_to_string(path)?;
            let config: Config = serde_json::from_str(&content)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Ok(config)
        } else {
            Ok(Config::default())
        }
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), io::Error> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn init_config<P: AsRef<Path>>(path: P, platform: Option<&str>) -> Result<Self, io::Error> {
        let mut config = Config::default();
        if let Some(p) = platform {
            config.platform = p.to_string();
        }
        config.save_to_file(path)?;
        Ok(config)
    }
}
