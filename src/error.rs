use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Firewall error: {0}")]
    Firewall(String),
    #[error("Config error: {0}")]
    Config(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Timeout")]
    Timeout,
}

impl From<aes_gcm::Error> for AppError {
    fn from(e: aes_gcm::Error) -> Self {
        AppError::Crypto(e.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::Protocol(e.to_string())
    }
}