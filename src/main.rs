mod cli;
mod client;
mod config;
mod crypto;
mod error;
mod firewall;
mod protocol;
mod server;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use cli::{Cli, Commands};
use client::Client;
use config::Config;
use protocol::Request;
use server::Server;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let filter = if cli.debug {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("warn")
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    match cli.command {
        Commands::Init { platform } => {
            let content = Config::generate_default(&platform);
            std::fs::write(&cli.config, &content)?;
            println!("Generated config at: {}", cli.config);
        }

        Commands::Server => {
            let config = Config::load(&cli.config)?;
            let srv = Server::new(config)?;
            srv.run().await?;
        }

        Commands::Client { action, params, timeout } => {
            let mut config = Config::load(&cli.config)?;
            if let Some(t) = timeout {
                config.timeout_secs = t;
            }

            let request = build_request(&action, &params)?;
            let client = Client::new(config);
            let response = client.send(request).await?;

            if response.success {
                println!("✅ {}", response.message);
                if let Some(data) = response.data {
                    println!("{}", serde_json::to_string_pretty(&data)?);
                }
            } else {
                eprintln!("❌ {}", response.message);
                std::process::exit(1);
            }
        }

        Commands::Status => {
            let config = Config::load(&cli.config)?;
            let client = Client::new(config);
            let response = client.send(Request::Status).await?;
            if response.success {
                println!("✅ {}", response.message);
                if let Some(data) = response.data {
                    println!("{}", serde_json::to_string_pretty(&data)?);
                }
            } else {
                eprintln!("❌ {}", response.message);
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

fn build_request(action: &str, params: &[String]) -> anyhow::Result<Request> {
    match action {
        "list" => Ok(Request::List),
        "status" => Ok(Request::Status),
        "enable" => {
            let name = params.first().ok_or_else(|| anyhow::anyhow!("enable requires <name>"))?;
            Ok(Request::Enable { name: name.clone() })
        }
        "disable" => {
            let name = params.first().ok_or_else(|| anyhow::anyhow!("disable requires <name>"))?;
            Ok(Request::Disable { name: name.clone() })
        }
        "delete" => {
            let name = params.first().ok_or_else(|| anyhow::anyhow!("delete requires <name>"))?;
            Ok(Request::Delete { name: name.clone() })
        }
        "create" => {
            if params.len() < 5 {
                anyhow::bail!("create requires <name> <src> <dest> <proto> <port>");
            }
            Ok(Request::Create {
                name: params[0].clone(),
                src: params[1].clone(),
                dest: params[2].clone(),
                proto: params[3].clone(),
                port: params[4].clone(),
            })
        }
        _ => anyhow::bail!("Unknown action: {}. Use: list|enable|disable|create|delete|status", action),
    }
}