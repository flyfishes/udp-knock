use clap::{Parser, Subcommand};
use std::process;

mod client;
mod config;
mod crypto;
mod firewall;
mod server;

use client::Client;
use config::Config;
use firewall::get_firewall_manager;
use server::Server;

#[derive(Parser, Debug)]
#[command(
    name = "udp-knock",
    author = "UDP Knock Authors",
    version = "0.1.0",
    about = "Secure remote firewall management tool using encrypted UDP packets"
)]
struct Cli {
    /// Path to configuration file
    #[arg(short = 'c', long = "config", default_value = "config.json")]
    config: String,

    /// Enable debug output
    #[arg(short = 'd', long = "debug")]
    debug: bool,

    /// Target platform (openwrt, linux, windows)
    #[arg(short = 'p', long = "platform")]
    platform: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the UDP Knock server
    Server,

    /// Send a command to the remote UDP Knock server
    Client {
        /// Action name (list, enable, disable, create, delete, status)
        #[arg(short = 'a', long = "action")]
        action: Option<String>,

        /// Command parameters list
        #[arg(short = 'p', long = "params", num_args = 0..)]
        params: Vec<String>,

        /// Command timeout in seconds
        #[arg(short = 't', long = "timeout")]
        timeout: Option<u64>,
    },

    /// Initialize default configuration file
    Init {
        /// Platform to pre-configure
        #[arg(short = 'p', long = "platform")]
        platform: Option<String>,
    },

    /// Display current local firewall status directly
    Status,
}

fn main() {
    let cli = Cli::parse();

    // Initialize logger based on debug flag
    let log_level = if cli.debug {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    env_logger::Builder::new().filter_level(log_level).init();

    match cli.command {
        Commands::Init { platform } => {
            let plat = platform.or(cli.platform);
            match Config::init_config(&cli.config, plat.as_deref()) {
                Ok(_) => {
                    println!("Initialized configuration file at '{}'", cli.config);
                }
                Err(e) => {
                    eprintln!("Failed to initialize config file: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Server => {
            let mut cfg = Config::load_or_default(&cli.config).unwrap_or_else(|e| {
                eprintln!("Failed to load config: {}", e);
                process::exit(1);
            });

            if let Some(p) = cli.platform {
                cfg.platform = p;
            }
            if cli.debug {
                cfg.debug = true;
            }

            let srv = Server::new(cfg.server, cfg.platform, cfg.debug);
            if let Err(e) = srv.run() {
                eprintln!("Server error: {}", e);
                process::exit(1);
            }
        }
        Commands::Client {
            action,
            params,
            timeout,
        } => {
            let cfg = Config::load_or_default(&cli.config).unwrap_or_else(|e| {
                eprintln!("Failed to load config: {}", e);
                process::exit(1);
            });

            let act = action.unwrap_or_else(|| "status".to_string());
            let client = Client::new(cfg.client, cli.debug);

            if let Err(e) = client.send_command(&act, &params, timeout) {
                eprintln!("Client command failed: {}", e);
                process::exit(1);
            }
        }
        Commands::Status => {
            let cfg = Config::load_or_default(&cli.config).unwrap_or_default();
            let plat = cli.platform.unwrap_or(cfg.platform);
            let firewall = get_firewall_manager(&plat);

            match firewall.get_status() {
                Ok(st) => {
                    println!("Firewall Status:");
                    println!("  Platform: {}", st.platform);
                    println!("  Active: {}", st.active);
                    println!("  Total Rules: {}", st.total_rules);
                    println!("  Active Rules: {}", st.active_rules);
                }
                Err(e) => {
                    eprintln!("Failed to get firewall status: {}", e);
                    process::exit(1);
                }
            }
        }
    }
}
