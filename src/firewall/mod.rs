use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    pub src: String,
    pub dest: String,
    pub proto: String,
    pub port: u16,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallStatus {
    pub active: bool,
    pub platform: String,
    pub total_rules: usize,
    pub active_rules: usize,
}

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum FirewallError {
    RuleNotFound(String),
    CommandFailed(String),
    NotImplemented(String),
    InvalidParameter(String),
}

impl std::fmt::Display for FirewallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallError::RuleNotFound(s) => write!(f, "Rule not found: {}", s),
            FirewallError::CommandFailed(s) => write!(f, "Firewall command failed: {}", s),
            FirewallError::NotImplemented(s) => write!(f, "Feature not implemented: {}", s),
            FirewallError::InvalidParameter(s) => write!(f, "Invalid parameter: {}", s),
        }
    }
}

impl std::error::Error for FirewallError {}

pub trait FirewallManager: Send + Sync {
    fn list_rules(&self) -> Result<Vec<FirewallRule>, FirewallError>;
    fn enable_rule(&self, name: &str) -> Result<(), FirewallError>;
    fn disable_rule(&self, name: &str) -> Result<(), FirewallError>;
    fn create_rule(
        &self,
        name: &str,
        src: &str,
        dest: &str,
        proto: &str,
        port: u16,
    ) -> Result<(), FirewallError>;
    fn delete_rule(&self, name: &str) -> Result<(), FirewallError>;
    fn get_status(&self) -> Result<FirewallStatus, FirewallError>;
}

pub mod linux;
pub mod openwrt;
pub mod windows;

pub fn get_firewall_manager(platform: &str) -> Box<dyn FirewallManager> {
    match platform.to_lowercase().as_str() {
        "openwrt" => Box::new(openwrt::OpenWrtFirewall::new()),
        "linux" => Box::new(linux::LinuxFirewall::new()),
        "windows" => Box::new(windows::WindowsFirewall::new()),
        _ => Box::new(openwrt::OpenWrtFirewall::new()),
    }
}
