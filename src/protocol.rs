use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", content = "params")]
pub enum Request {
    #[serde(rename = "list")]
    List,
    #[serde(rename = "enable")]
    Enable { name: String },
    #[serde(rename = "disable")]
    Disable { name: String },
    #[serde(rename = "create")]
    Create {
        name: String,
        src: String,
        dest: String,
        proto: String,
        port: String,
    },
    #[serde(rename = "delete")]
    Delete { name: String },
    #[serde(rename = "status")]
    Status,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl Response {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
            data: None,
        }
    }

    pub fn ok_with_data(message: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            success: true,
            message: message.into(),
            data: Some(data),
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
            data: None,
        }
    }
}