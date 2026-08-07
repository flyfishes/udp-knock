// src/server/mod.rs

mod handler;

use crate::config::Config;
use crate::crypto::Security;
use crate::firewall::create_firewall_manager;
use log::{info, error};
use tokio::net::UdpSocket;

pub struct Server {
    config: Config,
    security: Security,
    socket: Option<UdpSocket>,
}

impl Server {
    pub fn new(config: Config) -> Self {
        let security = Security::new(
            &config.security.shared_key,
            config.security.timestamp_window,
            config.debug,
        );

        Self {
            config,
            security,
            socket: None,
        }
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let bind_addr = self.config.server.bind_addr;
        let socket = UdpSocket::bind(bind_addr).await?;
        self.socket = Some(socket);

        info!("UDP Knock Server 启动在 {}", bind_addr);
        info!("调试模式: {}", self.config.debug);

        self.serve().await
    }

    async fn serve(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let socket = self.socket.as_ref().unwrap();
        let mut buf = vec![0u8; self.config.security.max_packet_size];

        // 创建防火墙管理器
        let firewall = create_firewall_manager(&self.config)?;

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((size, src_addr)) => {
                    let data = &buf[..size];
                    if let Ok(data_str) = String::from_utf8(data.to_vec()) {
                        if self.config.debug {
                            log::debug!("收到来自 {} 的数据包", src_addr);
                        }
                        
                        // 检查是否允许该客户端
                        if !self.is_client_allowed(&src_addr) {
                            if self.config.debug {
                                log::warn!("拒绝未授权的客户端: {}", src_addr);
                            }
                            continue;
                        }

                        // 处理请求
                        handler::handle_request(
                            &self.config,
                            &self.security,
                            firewall.as_ref(),
                            data_str,
                            src_addr,
                            socket,
                        ).await;
                    }
                }
                Err(e) => {
                    error!("接收数据失败: {}", e);
                }
            }
        }
    }

    fn is_client_allowed(&self, addr: &std::net::SocketAddr) -> bool {
        if self.config.server.allowed_clients.is_empty() {
            return true;
        }
        self.config.server.allowed_clients.contains(addr)
    }
}