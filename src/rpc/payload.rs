use super::{
    super::domain::MessageId,
    {ErrorResponse, Request, Response, SessionRequest, ValidationError},
};
use serde::{Deserialize, Serialize};

/// Enum representing a JSON RPC payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Payload {
    /// An inbound request.
    Request(Request),

    /// An inbout session request
    SessionRequest(SessionRequest),

    /// An outbound response.
    Response(Response),
}

impl Payload {
    /// Returns the message ID contained within the payload.
    pub fn id(&self) -> MessageId {
        match self {
            Self::Request(req) => req.id,
            Self::SessionRequest(req) => req.id,
            Self::Response(Response::Success(r)) => r.id,
            Self::Response(Response::Error(r)) => r.id,
            Self::Response(Response::RPCResponse(r)) => r.id,
        }
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Request(request) => request.validate(),
            Self::Response(response) => response.validate(),
            _ => Ok(()),
        }
    }
}

impl<T> From<T> for Payload
where
    T: Into<ErrorResponse>,
{
    fn from(value: T) -> Self {
        Self::Response(Response::Error(value.into()))
    }
}
