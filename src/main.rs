use clap::{Parser, Subcommand};
use log::{info, error};
use std::path::Path;
use udp_knock::{Config, Server, Client};

#[derive(Parser)]
#[command(name = "udp-knock")]
#[command(about = "安全的UDP Knock工具 - 远程防火墙管理", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, default_value = "config.json")]
    config: String,

    #[arg(short, long)]
    debug: bool,

    #[arg(short, long)]
    platform: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// 启动服务器模式
    Server {
        #[arg(short, long)]
        daemon: bool,
    },
    /// 启动客户端模式
    Client {
        #[arg(short, long)]
        action: String,
        #[arg(short, long)]
        params: Vec<String>,
        #[arg(short = 't', long)]
        timeout: Option<u64>,
    },
    /// 生成默认配置文件
    Init {
        #[arg(short, long, default_value = "config.json")]
        output: String,
        #[arg(short, long)]
        platform: Option<String>,
    },
    /// 显示当前防火墙状态
    Status,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    // 初始化日志
    let log_level = if cli.debug { "debug" } else { "info" };
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(log_level)
    )
    .format_timestamp_millis()
    .init();

    // 处理Init命令
    if let Commands::Init { output, platform } = cli.command {
        let platform = platform.unwrap_or_else(|| get_platform());
        info!("为平台 {} 生成配置文件", platform);
        
        let config = Config::default_for_platform(&platform)?;
        let json = serde_json::to_string_pretty(&config)?;
        std::fs::write(&output, json)?;
        
        println!("配置文件已生成: {}", output);
        println!("请修改配置文件中的密钥和地址设置！");
        return Ok(());
    }

    // 加载配置
    let mut config = match Config::from_file(&cli.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("加载配置文件失败: {}", e);
            error!("请运行 'udp-knock init' 生成默认配置文件");
            return Err(e);
        }
    };

    if cli.debug {
        config.debug = true;
    }

    match cli.command {
        Commands::Server { daemon: _ } => {
            info!("启动UDP Knock服务器 (平台: {})", get_platform());
            let mut server = Server::new(config);
            server.start().await?;
        }
        Commands::Client { action, params, timeout } => {
            info!("启动UDP Knock客户端");
            if let Some(t) = timeout {
                config.client.timeout_secs = t;
            }
            
            let client = Client::new(config).await?;
            let result = client.send_command(&action, &params).await;
            
            match result {
                Ok(response) => {
                    println!("✅ 成功: {}", response);
                }
                Err(e) => {
                    eprintln!("❌ 失败: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Init { .. } => unreachable!(),
        Commands::Status => {
            info!("获取防火墙状态");
            let firewall = crate::firewall::create_firewall_manager(&config)?;
            let status = firewall.get_status()?;
            println!("防火墙状态:");
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
    }

    Ok(())
}

fn get_platform() -> String {
    #[cfg(target_os = "openwrt")]
    return "openwrt".to_string();
    #[cfg(all(target_os = "linux", not(target_os = "openwrt")))]
    return "linux".to_string();
    #[cfg(target_os = "windows")]
    return "windows".to_string();
    #[cfg(target_os = "macos")]
    return "macos".to_string();
    #[cfg(not(any(
        target_os = "openwrt",
        target_os = "linux",
        target_os = "windows",
        target_os = "macos"
    )))]
    return "unknown".to_string();
}