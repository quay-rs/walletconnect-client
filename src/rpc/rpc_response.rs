use super::{super::domain::MessageId, ResponseParams, ValidationError, JSON_RPC_VERSION_STR};
use serde::{Deserialize, Serialize};

/// Data structure representing a successful JSON RPC response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RPCResponse {
    /// ID this message corresponds to.
    pub id: MessageId,

    /// RPC version.
    pub jsonrpc: String,

    /// RPC params
    #[serde(flatten)]
    pub params: ResponseParams,
}

impl RPCResponse {
    /// Validates the parameters.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if !self.id.validate() {
            return Err(ValidationError::RequestId);
        }

        if &self.jsonrpc != JSON_RPC_VERSION_STR {
            return Err(ValidationError::JsonRpcVersion);
        }

        Ok(())
    }
}
