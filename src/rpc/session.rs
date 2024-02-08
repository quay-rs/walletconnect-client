use crate::metadata::Empty;

use super::{
    super::{
        domain::MessageId,
        metadata::{Responder, SessionPropose, SessionRpcRequest, SessionSettlement},
    },
    Serializable,
};
use ethers::providers::JsonRpcError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Error {
    pub code: i64,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

impl Error {
    pub fn as_error_response(&self) -> JsonRpcError {
        JsonRpcError { code: self.code, message: self.message.clone(), data: self.data.clone() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum SessionParams {
    #[serde(rename = "wc_sessionPropose")]
    Propose(SessionPropose),
    #[serde(rename = "wc_sessionRequest")]
    Request(SessionRpcRequest),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SessionResultParams {
    Responder(Responder),
    Error(SessionError),
    Boolean(bool),
    Response(serde_json::Value),
}

pub trait SessionPayload: Serializable {
    fn into_params(self) -> SessionParams;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRequest {
    pub id: MessageId,
    pub jsonrpc: String,

    #[serde(flatten)]
    pub params: SessionParams,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SessionMessage {
    Message(WalletRequest),
    Response(SessionResponse),
    Error(SessionError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionResponse {
    pub id: MessageId,
    pub jsonrpc: String,

    pub result: SessionResultParams,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionError {
    pub id: MessageId,
    pub jsonrpc: String,

    pub error: Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletRequest {
    pub id: MessageId,
    pub jsonrpc: String,

    #[serde(flatten)]
    pub params: WalletMessage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum WalletMessage {
    #[serde(rename = "wc_sessionSettle")]
    Settlement(SessionSettlement),
    #[serde(rename = "wc_sessionPing")]
    Ping(Empty),
}
