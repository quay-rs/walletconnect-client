use super::{
    super::domain::DidKey, super::jwt::JwtError, BoxError, GenericError, Params, RequestPayload,
    ValidationError,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error("Invalid TTL")]
    InvalidTtl,

    #[error("Service URL is invalid or too long")]
    InvalidServiceUrl,

    #[error("Webhook URL is invalid or too long")]
    InvalidWebhookUrl,

    #[error("Failed to decode JWT: {0}")]
    Jwt(#[from] JwtError),

    #[error("{0}")]
    Other(BoxError),
}

impl From<WatchError> for GenericError {
    fn from(err: WatchError) -> Self {
        Self::Request(Box::new(err))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchRegisterResponse {
    /// The Relay's public key (did:key).
    pub relay_id: DidKey,
}

/// Data structure representing watch registration request params.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchRegister {
    /// JWT with [`watch::WatchRegisterClaims`] payload.
    pub register_auth: String,
}

impl RequestPayload for WatchRegister {
    type Error = WatchError;
    type Response = WatchRegisterResponse;

    fn validate(&self) -> Result<(), ValidationError> {
        Ok(())
    }

    fn into_params(self) -> Params {
        Params::WatchRegister(self)
    }
}

/// Data structure representing watch unregistration request params.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchUnregister {
    /// JWT with [`watch::WatchUnregisterClaims`] payload.
    pub unregister_auth: String,
}

impl RequestPayload for WatchUnregister {
    type Error = WatchError;
    type Response = bool;

    fn validate(&self) -> Result<(), ValidationError> {
        Ok(())
    }

    fn into_params(self) -> Params {
        Params::WatchUnregister(self)
    }
}
