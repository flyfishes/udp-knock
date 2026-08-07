// src/lib.rs

pub mod config;
pub mod crypto;
pub mod server;
pub mod client;
pub mod firewall;
pub mod utils;

// 重新导出常用类型
pub use config::Config;
pub use server::Server;
pub use client::Client;
pub use crypto::Security;

#[cfg(test)]
mod tests {
    #[test]
    fn test_lib() {
        assert!(true);
    }
}