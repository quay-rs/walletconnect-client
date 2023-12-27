use super::{super::domain::DecodingError, ErrorData};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Errors covering payload validation problems.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("Topic decoding failed: {0}")]
    TopicDecoding(DecodingError),

    #[error("Subscription ID decoding failed: {0}")]
    SubscriptionIdDecoding(DecodingError),

    #[error("Invalid request ID")]
    RequestId,

    #[error("Invalid JSON RPC version")]
    JsonRpcVersion,

    #[error("The batch contains too many items ({actual}). Maximum number of items is {limit}")]
    BatchLimitExceeded { limit: usize, actual: usize },

    #[error("The batch contains no items")]
    BatchEmpty,
}

#[derive(Debug, thiserror::Error)]
pub enum GenericError {
    #[error("Authorization error: {0}")]
    Authorization(BoxError),

    #[error("Too many requests")]
    TooManyRequests,

    /// Request parameters validation failed.
    #[error("Request validation error: {0}")]
    Validation(#[from] ValidationError),

    /// Request/response serialization error.
    #[error("Serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    /// An unsupported JSON RPC method.
    #[error("Unsupported request method")]
    RequestMethod,

    /// Generic request-specific error, which could not be caught by the request
    /// validation.
    #[error("Failed to process request: {0}")]
    Request(BoxError),

    /// Internal server error. These are not request-specific, but should not
    /// normally happen if the relay is fully operational.
    #[error("Internal error: {0}")]
    Other(BoxError),
}

impl GenericError {
    /// The error code. These are the standard JSONRPC error codes. The Relay
    /// specific errors are in 3000-4999 range to align with the websocket close
    /// codes.
    pub fn code(&self) -> i32 {
        match self {
            Self::Authorization(_) => 3000,
            Self::TooManyRequests => 3001,
            Self::Serialization(_) => -32700,
            Self::Validation(_) => -32602,
            Self::RequestMethod => -32601,
            Self::Request(_) => -32000,
            Self::Other(_) => -32603,
        }
    }
}

impl<T> From<T> for ErrorData
where
    T: Into<GenericError>,
{
    fn from(value: T) -> Self {
        let value = value.into();

        ErrorData { code: value.code(), message: value.to_string(), data: None }
    }
}
