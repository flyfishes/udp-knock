// src/firewall/mod.rs

pub mod traits;

// 平台模块
#[cfg(feature = "openwrt")]
pub mod openwrt;

#[cfg(feature = "linux")]
pub mod linux;

#[cfg(feature = "windows")]
pub mod windows;

// 重新导出
pub use traits::*;

#[cfg(feature = "openwrt")]
pub use openwrt::OpenWrtFirewall;

#[cfg(feature = "linux")]
pub use linux::LinuxFirewall;

#[cfg(feature = "windows")]
pub use windows::WindowsFirewall;

/// 创建防火墙管理器实例的工厂函数
pub fn create_firewall_manager(
    config: &crate::config::Config,
) -> Result<Box<dyn FirewallManager>, Box<dyn std::error::Error>> {
    let firewall_type = &config.server.firewall.firewall_type;
    let platform = &config.platform;

    #[cfg(feature = "openwrt")]
    if firewall_type == "openwrt" || (firewall_type == "auto" && platform == "openwrt") {
        return Ok(Box::new(OpenWrtFirewall::new(config)?));
    }

    #[cfg(feature = "linux")]
    if firewall_type == "iptables" || (firewall_type == "auto" && platform == "linux") {
        return Ok(Box::new(LinuxFirewall::new(config)?));
    }

    #[cfg(feature = "windows")]
    if firewall_type == "windows" || (firewall_type == "auto" && platform == "windows") {
        return Ok(Box::new(WindowsFirewall::new(config)?));
    }

    Err(format!(
        "不支持的防火墙类型: '{}' (平台: '{}')，或对应的 feature 未启用",
        firewall_type, platform
    )
    .into())
}