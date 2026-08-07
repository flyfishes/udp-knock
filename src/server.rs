use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use governor::{Quota, RateLimiter};
use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::config::Config;
use crate::crypto::CryptoContext;
use crate::error::AppError;
use crate::firewall::{create_firewall_manager, FirewallManager};
use crate::protocol::{Request, Response};

pub struct Server {
    config: Arc<Config>,
    crypto: Arc<CryptoContext>,
    fw: Arc<dyn FirewallManager>,
    limiter: Arc<RateLimiter<governor::state::NotKeyed, governor::state::InMemoryState, governor::clock::DefaultClock>>,
}

impl Server {
    pub fn new(config: Config) -> Result<Self, AppError> {
        let crypto = CryptoContext::new(&config.shared_secret);
        let fw = create_firewall_manager(&config.platform)?;
        let quota = Quota::per_minute(std::num::NonZeroU64::new(config.rate_limit_rpm.max(1)).unwrap());
        let limiter = RateLimiter::direct(quota);

        Ok(Self {
            config: Arc::new(config),
            crypto: Arc::new(crypto),
            fw: Arc::from(fw),
            limiter: Arc::new(limiter),
        })
    }

    pub async fn run(&self) -> Result<(), AppError> {
        let socket = UdpSocket::bind(&self.config.listen_addr).await?;
        tracing::info!("UDP Knock server listening on {}", self.config.listen_addr);

        let mut buf = [0u8; 4096];
        loop {
            let (len, addr) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    warn!("recv_from error: {}", e);
                    continue;
                }
            };

            // Process in spawned task to avoid blocking listener
            let this = self.clone_refs();
            let packet = buf[..len].to_vec();
            let socket = socket.clone(); // UdpSocket is Clone-safe for send_to

            tokio::spawn(async move {
                this.handle_packet(&socket, &packet, addr).await;
            });
        }
    }

    async fn handle_packet(&self, socket: &UdpSocket, packet: &[u8], addr: SocketAddr) {
        // 1. IP whitelist check
        if !self.config.allowed_ips.is_empty() {
            let ip = addr.ip().to_string();
            if !self.config.allowed_ips.contains(&ip) {
                debug!("Rejected IP: {}", ip);
                return; // Silent drop
            }
        }

        // 2. Rate limit
        if self.limiter.check().is_err() {
            debug!("Rate limited: {}", addr);
            return; // Silent drop
        }

        // 3. Decrypt + verify
        let (plaintext, timestamp) = match self.crypto.open(packet) {
            Ok(v) => v,
            Err(e) => {
                debug!("Crypto failure from {}: {}", addr, e);
                return; // Silent drop
            }
        };

        // 4. Timestamp validation
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let window = self.config.time_window_secs;
        if now.abs_diff(timestamp) > window {
            debug!("Timestamp expired from {}: {} vs {}", addr, timestamp, now);
            return; // Silent drop
        }

        // 5. Parse command
        let request: Request = match serde_json::from_slice(&plaintext) {
            Ok(r) => r,
            Err(e) => {
                debug!("Parse error from {}: {}", addr, e);
                return; // Silent drop for malformed encrypted payloads
            }
        };

        // 6. Execute
        let response = self.execute(request).await;

        // 7. Encrypt and respond
        let resp_json = match serde_json::to_vec(&response) {
            Ok(v) => v,
            Err(e) => {
                warn!("Response serialization error: {}", e);
                return;
            }
        };

        let resp_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        match self.crypto.seal(&resp_json, resp_ts) {
            Ok(resp_packet) => {
                if let Err(e) = socket.send_to(&resp_packet, addr).await {
                    warn!("send_to error: {}", e);
                }
            }
            Err(e) => warn!("Response encryption error: {}", e),
        }
    }

    async fn execute(&self, req: Request) -> Response {
        match req {
            Request::List => match self.fw.list_rules().await {
                Ok(data) => Response::ok_with_data("Rules listed", data),
                Err(e) => Response::err(format!("List failed: {}", e)),
            },
            Request::Enable { name } => match self.fw.enable_rule(&name).await {
                Ok(_) => Response::ok(format!("Rule '{}' enabled", name)),
                Err(e) => Response::err(format!("Enable failed: {}", e)),
            },
            Request::Disable { name } => match self.fw.disable_rule(&name).await {
                Ok(_) => Response::ok(format!("Rule '{}' disabled", name)),
                Err(e) => Response::err(format!("Disable failed: {}", e)),
            },
            Request::Create { name, src, dest, proto, port } => {
                match self.fw.create_rule(&name, &src, &dest, &proto, &port).await {
                    Ok(_) => Response::ok(format!("Rule '{}' created", name)),
                    Err(e) => Response::err(format!("Create failed: {}", e)),
                }
            }
            Request::Delete { name } => match self.fw.delete_rule(&name).await {
                Ok(_) => Response::ok(format!("Rule '{}' deleted", name)),
                Err(e) => Response::err(format!("Delete failed: {}", e)),
            },
            Request::Status => match self.fw.status().await {
                Ok(data) => Response::ok_with_data("Status OK", data),
                Err(e) => Response::err(format!("Status failed: {}", e)),
            },
        }
    }

    /// Cheap clone of Arc references only
    fn clone_refs(&self) -> Self {
        Self {
            config: self.config.clone(),
            crypto: self.crypto.clone(),
            fw: self.fw.clone(),
            limiter: self.limiter.clone(),
        }
    }
}