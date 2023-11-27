use super::{super::domain::MessageId, Params, ValidationError, JSON_RPC_VERSION_STR};
use serde::{Deserialize, Serialize};
/// Data structure representing a JSON RPC request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// ID this message corresponds to.
    pub id: MessageId,

    /// The JSON RPC version.
    pub jsonrpc: String,

    /// The parameters required to fulfill this request.
    #[serde(flatten)]
    pub params: Params,
}

impl Request {
    /// Create a new instance.
    pub fn new(id: MessageId, params: Params) -> Self {
        Self { id, jsonrpc: JSON_RPC_VERSION_STR.into(), params }
    }

    /// Validates the request payload.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if !self.id.validate() {
            return Err(ValidationError::RequestId);
        }

        if &self.jsonrpc != JSON_RPC_VERSION_STR {
            return Err(ValidationError::JsonRpcVersion);
        }

        // match &self.params {
        //     Params::Subscribe(params) => params.validate(),
        //     Params::Unsubscribe(params) => params.validate(),
        //     Params::FetchMessages(params) => params.validate(),
        //     Params::BatchSubscribe(params) => params.validate(),
        //     Params::BatchUnsubscribe(params) => params.validate(),
        //     Params::BatchFetchMessages(params) => params.validate(),
        //     Params::Publish(params) => params.validate(),
        //     Params::BatchReceiveMessages(params) => params.validate(),
        //     Params::WatchRegister(params) => params.validate(),
        //     Params::WatchUnregister(params) => params.validate(),
        //     Params::Subscription(params) => params.validate(),
        // }
        Ok(())
    }
}
