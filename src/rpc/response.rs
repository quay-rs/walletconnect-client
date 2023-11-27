use super::{
    super::domain::MessageId, Params, RPCResponse, Serializable, ValidationError,
    JSON_RPC_VERSION_STR,
};
use serde::{Deserialize, Serialize};
/// Trait that adds validation capabilities and strong typing to errors and
/// successful responses. Implemented for all possible RPC request types.
pub trait RequestPayload: Serializable {
    /// The error representing a failed request.
    type Error: Into<ErrorData> + Send + 'static;

    /// The type of a successful response.
    type Response: Serializable;

    /// Validates the request parameters.
    fn validate(&self) -> Result<(), ValidationError> {
        Ok(())
    }

    fn into_params(self) -> Params;
}

/// Enum representing a JSON RPC response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Response {
    /// A response with a result.
    Success(SuccessfulResponse),

    /// Async response from the server
    RPCResponse(RPCResponse),

    /// A response for a failed request.
    Error(ErrorResponse),
}

impl Response {
    pub fn id(&self) -> MessageId {
        match self {
            Self::Success(response) => response.id,
            Self::RPCResponse(response) => response.id,
            Self::Error(response) => response.id,
        }
    }

    /// Validates the response parameters.
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Success(response) => response.validate(),
            Self::RPCResponse(response) => response.validate(),
            Self::Error(response) => response.validate(),
        }
    }
}

/// Data structure representing a successful JSON RPC response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuccessfulResponse {
    /// ID this message corresponds to.
    pub id: MessageId,

    /// RPC version.
    pub jsonrpc: String,

    /// The result for the message.
    pub result: serde_json::Value,
}

impl SuccessfulResponse {
    /// Create a new instance.
    pub fn new(id: MessageId, result: serde_json::Value) -> Self {
        Self { id, jsonrpc: JSON_RPC_VERSION_STR.to_string(), result }
    }

    /// Validates the parameters.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if &self.jsonrpc != JSON_RPC_VERSION_STR {
            Err(ValidationError::JsonRpcVersion)
        } else {
            // We can't really validate `serde_json::Value` without knowing the expected
            // value type.
            Ok(())
        }
    }
}

/// Data structure representing a JSON RPC error response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// ID this message corresponds to.
    pub id: MessageId,

    /// RPC version.
    pub jsonrpc: String,

    /// The ErrorResponse corresponding to this message.
    pub error: ErrorData,
}

impl ErrorResponse {
    /// Create a new instance.
    pub fn new(id: MessageId, error: ErrorData) -> Self {
        Self { id, jsonrpc: JSON_RPC_VERSION_STR.to_string(), error }
    }

    /// Validates the parameters.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if &self.jsonrpc != JSON_RPC_VERSION_STR {
            Err(ValidationError::JsonRpcVersion)
        } else {
            Ok(())
        }
    }
}

/// Data structure representing error response params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorData {
    /// Error code.
    pub code: i32,

    /// Error message.
    pub message: String,

    /// Error data, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}
