use crate::config::ServerConfig;
use crate::crypto::{CryptoError, CryptoManager};
use crate::firewall::{get_firewall_manager, FirewallManager};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandPayload {
    pub action: String,
    #[serde(default)]
    pub params: Vec<String>,
    #[serde(default)]
    pub offset: usize,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePayload {
    pub success: bool,
    pub message: String,
    pub data: Option<serde_json::Value>,
    pub timestamp: u64,
}

struct RateLimiter {
    requests: Mutex<HashMap<String, Vec<Instant>>>,
    max_per_minute: u32,
}

impl RateLimiter {
    fn new(max_per_minute: u32) -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
            max_per_minute,
        }
    }

    fn check_and_record(&self, ip: &str) -> bool {
        if self.max_per_minute == 0 {
            return true;
        }

        let mut map = self.requests.lock().unwrap();
        let now = Instant::now();
        let window = Duration::from_secs(60);

        let timestamps = map.entry(ip.to_string()).or_default();
        timestamps.retain(|t| now.duration_since(*t) < window);

        if timestamps.len() >= self.max_per_minute as usize {
            false
        } else {
            timestamps.push(now);
            true
        }
    }
}

pub struct Server {
    config: ServerConfig,
    platform: String,
    debug: bool,
}

impl Server {
    pub fn new(config: ServerConfig, platform: String, debug: bool) -> Self {
        Self {
            config,
            platform,
            debug,
        }
    }

    pub fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let socket = UdpSocket::bind(&self.config.bind_addr)?;
        log::info!("Server running on UDP {}", self.config.bind_addr);

        let crypto = CryptoManager::new(&self.config.shared_key);
        let firewall: Box<dyn FirewallManager> = get_firewall_manager(&self.platform);
        let rate_limiter = RateLimiter::new(self.config.rate_limit);
        let mut buf = [0u8; 65535];

        loop {
            let (amt, src_addr) = match socket.recv_from(&mut buf) {
                Ok(res) => res,
                Err(e) => {
                    if self.debug {
                        log::error!("UDP receive error: {}", e);
                    }
                    continue;
                }
            };

            let client_ip = src_addr.ip().to_string();
            if self.debug {
                log::debug!("Received {} bytes from UDP client {}", amt, src_addr);
            }

            // 1. IP Whitelist check
            if !self.config.allowed_ips.is_empty() && !self.config.allowed_ips.contains(&client_ip)
            {
                if self.debug {
                    log::warn!("Silent drop: IP {} not in whitelist", client_ip);
                }
                continue;
            }

            // 2. Rate Limiting
            if !rate_limiter.check_and_record(&client_ip) {
                if self.debug {
                    log::warn!("Silent drop: IP {} exceeded rate limit", client_ip);
                }
                continue;
            }

            let raw_data = match std::str::from_utf8(&buf[..amt]) {
                Ok(s) => s.trim(),
                Err(_) => {
                    if self.debug {
                        log::warn!("Silent drop: Invalid UTF-8 from {}", client_ip);
                    }
                    continue;
                }
            };

            // 3. Decrypt payload (AES-256-GCM + HMAC verification)
            let plaintext_bytes = match crypto.decrypt(raw_data) {
                Ok(data) => data,
                Err(err) => {
                    if self.debug {
                        log::warn!(
                            "Silent drop: Decryption/HMAC failed for {}: {}",
                            client_ip,
                            err
                        );
                    }
                    // Silent drop on decryption or HMAC failure
                    continue;
                }
            };

            // 4. Parse Command Payload
            let payload: CommandPayload = match serde_json::from_slice(&plaintext_bytes) {
                Ok(p) => p,
                Err(e) => {
                    if self.debug {
                        log::warn!("Command JSON parsing failed for {}: {}", client_ip, e);
                    }
                    let err_resp = ResponsePayload {
                        success: false,
                        message: format!("Command JSON parsing failed: {}", e),
                        data: None,
                        timestamp: CryptoManager::current_timestamp(),
                    };
                    self.send_response(&socket, &src_addr, &crypto, &err_resp);
                    continue;
                }
            };

            if self.debug {
                log::debug!(
                    "Decrypted command from {}: action='{}', params={:?}, timestamp={}",
                    client_ip,
                    payload.action,
                    payload.params,
                    payload.timestamp
                );
            }

            // 5. Anti-replay Timestamp Verification (30-second window)
            if let Err(CryptoError::TimestampExpired) =
                CryptoManager::verify_timestamp(payload.timestamp, None)
            {
                if self.debug {
                    log::warn!(
                        "Silent drop: Timestamp expired for request from {}",
                        client_ip
                    );
                }
                continue;
            }

            // 6. Execute Firewall Command
            let response = self.execute_command(firewall.as_ref(), &payload);
            if self.debug {
                log::debug!(
                    "Executed action '{}' for {}: success={}, message='{}'",
                    payload.action,
                    client_ip,
                    response.success,
                    response.message
                );
            }

            // 7. Encrypt and Send Response
            self.send_response(&socket, &src_addr, &crypto, &response);
        }
    }

    fn execute_command(
        &self,
        firewall: &dyn FirewallManager,
        cmd: &CommandPayload,
    ) -> ResponsePayload {
        let ts = CryptoManager::current_timestamp();
        match cmd.action.to_lowercase().as_str() {
            "list" => match firewall.list_rules() {
                Ok(rules) => {
                    let filter = cmd.params.first().map(|s| s.to_lowercase());
                    let filtered_rules: Vec<_> = if let Some(ref f) = filter {
                        rules
                            .into_iter()
                            .filter(|r| r.name.to_lowercase().contains(f))
                            .collect()
                    } else {
                        rules
                    };

                    let total_count = filtered_rules.len();
                    let offset = cmd.offset.min(total_count);
                    let sliced_rules = &filtered_rules[offset..];

                    // Dynamically calculate payload size to prevent exceeding max UDP datagram limit (4096 bytes)
                    let mut safe_rules = Vec::new();
                    for rule in sliced_rules {
                        safe_rules.push(rule.clone());
                        let test_resp = ResponsePayload {
                            success: true,
                            message: "test".to_string(),
                            data: serde_json::to_value(&safe_rules).ok(),
                            timestamp: ts,
                        };
                        if serde_json::to_vec(&test_resp).map(|b| b.len()).unwrap_or(0) > 2500 {
                            safe_rules.pop();
                            break;
                        }
                    }

                    let count = safe_rules.len();
                    let start_idx = if count > 0 { offset + 1 } else { 0 };
                    let end_idx = offset + count;

                    let msg = if end_idx < total_count {
                        format!(
                            "Listed rules {}-{} of total {} rules (Use '-n {}' to view next page)",
                            start_idx, end_idx, total_count, end_idx
                        )
                    } else {
                        format!(
                            "Listed rules {}-{} of total {} rules",
                            start_idx, end_idx, total_count
                        )
                    };

                    ResponsePayload {
                        success: true,
                        message: msg,
                        data: serde_json::to_value(safe_rules).ok(),
                        timestamp: ts,
                    }
                }
                Err(e) => ResponsePayload {
                    success: false,
                    message: format!("Failed to list rules: {}", e),
                    data: None,
                    timestamp: ts,
                },
            },
            "enable" => {
                if let Some(rule_name) = cmd.params.first() {
                    let dir = cmd.params.get(1).map(|s| s.as_str());
                    match firewall.enable_rule(rule_name, dir) {
                        Ok(_) => ResponsePayload {
                            success: true,
                            message: format!("Rule '{}' enabled successfully", rule_name),
                            data: None,
                            timestamp: ts,
                        },
                        Err(e) => ResponsePayload {
                            success: false,
                            message: format!("Failed to enable rule: {}", e),
                            data: None,
                            timestamp: ts,
                        },
                    }
                } else {
                    ResponsePayload {
                        success: false,
                        message: "Missing rule name parameter".to_string(),
                        data: None,
                        timestamp: ts,
                    }
                }
            }
            "disable" => {
                if let Some(rule_name) = cmd.params.first() {
                    let dir = cmd.params.get(1).map(|s| s.as_str());
                    match firewall.disable_rule(rule_name, dir) {
                        Ok(_) => ResponsePayload {
                            success: true,
                            message: format!("Rule '{}' disabled successfully", rule_name),
                            data: None,
                            timestamp: ts,
                        },
                        Err(e) => ResponsePayload {
                            success: false,
                            message: format!("Failed to disable rule: {}", e),
                            data: None,
                            timestamp: ts,
                        },
                    }
                } else {
                    ResponsePayload {
                        success: false,
                        message: "Missing rule name parameter".to_string(),
                        data: None,
                        timestamp: ts,
                    }
                }
            }
            "create" => {
                if cmd.params.len() >= 5 {
                    let name = &cmd.params[0];
                    let src = &cmd.params[1];
                    let dest = &cmd.params[2];
                    let proto = &cmd.params[3];
                    let port: u16 = match cmd.params[4].parse() {
                        Ok(p) => p,
                        Err(_) => {
                            return ResponsePayload {
                                success: false,
                                message: "Invalid port parameter".to_string(),
                                data: None,
                                timestamp: ts,
                            };
                        }
                    };
                    let dir = cmd.params.get(5).map(|s| s.as_str());

                    match firewall.create_rule(name, src, dest, proto, port, dir) {
                        Ok(_) => ResponsePayload {
                            success: true,
                            message: format!("Rule '{}' created successfully", name),
                            data: None,
                            timestamp: ts,
                        },
                        Err(e) => ResponsePayload {
                            success: false,
                            message: format!("Failed to create rule: {}", e),
                            data: None,
                            timestamp: ts,
                        },
                    }
                } else {
                    ResponsePayload {
                        success: false,
                        message: "Usage: create <name> <src> <dest> <proto> <port> [in|out]"
                            .to_string(),
                        data: None,
                        timestamp: ts,
                    }
                }
            }
            "delete" => {
                if let Some(rule_name) = cmd.params.first() {
                    match firewall.delete_rule(rule_name) {
                        Ok(_) => ResponsePayload {
                            success: true,
                            message: format!("Rule '{}' deleted successfully", rule_name),
                            data: None,
                            timestamp: ts,
                        },
                        Err(e) => ResponsePayload {
                            success: false,
                            message: format!("Failed to delete rule: {}", e),
                            data: None,
                            timestamp: ts,
                        },
                    }
                } else {
                    ResponsePayload {
                        success: false,
                        message: "Missing rule name parameter".to_string(),
                        data: None,
                        timestamp: ts,
                    }
                }
            }
            "status" => match firewall.get_status() {
                Ok(st) => ResponsePayload {
                    success: true,
                    message: "Status retrieved successfully".to_string(),
                    data: serde_json::to_value(st).ok(),
                    timestamp: ts,
                },
                Err(e) => ResponsePayload {
                    success: false,
                    message: format!("Failed to get status: {}", e),
                    data: None,
                    timestamp: ts,
                },
            },
            unknown => ResponsePayload {
                success: false,
                message: format!("Unknown action: {}", unknown),
                data: None,
                timestamp: ts,
            },
        }
    }

    fn send_response(
        &self,
        socket: &UdpSocket,
        target: &SocketAddr,
        crypto: &CryptoManager,
        resp: &ResponsePayload,
    ) {
        if let Ok(json_bytes) = serde_json::to_vec(resp) {
            if let Ok(encrypted_payload) = crypto.encrypt(&json_bytes) {
                if let Err(e) = socket.send_to(encrypted_payload.as_bytes(), target) {
                    log::error!("Failed to send UDP response to {}: {}", target, e);
                } else if self.debug {
                    log::debug!(
                        "Sent encrypted response ({} bytes) to {}",
                        encrypted_payload.len(),
                        target
                    );
                }
            }
        }
    }
}
