use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "udp-knock", about = "Secure remote firewall management tool")]
pub struct Cli {
    /// Config file path
    #[arg(short, long, default_value = "config.json")]
    pub config: String,

    /// Enable debug logging
    #[arg(short, long)]
    pub debug: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the server
    Server,

    /// Send a client command
    Client {
        /// Action: list, enable, disable, create, delete, status
        #[arg(short, long)]
        action: String,

        /// Parameters (comma-separated or space-separated depending on action)
        #[arg(short, long, num_args = 0..)]
        params: Vec<String>,

        /// Timeout in seconds
        #[arg(short, long)]
        timeout: Option<u64>,
    },

    /// Generate default config file
    Init {
        /// Target platform
        #[arg(short, long, default_value = "openwrt")]
        platform: String,
    },

    /// Quick status check (alias for client --action status)
    Status,
}