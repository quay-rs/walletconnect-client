use super::{
    super::domain::{MessageId, SubscriptionId, Topic},
    get_message_id, BoxError, GenericError, MsgId, Params, Request, RequestPayload, Subscription,
    SubscriptionData, ValidationError, JSON_RPC_VERSION_STR,
};
use serde::{Deserialize, Serialize};

impl MsgId for Publish {
    fn msg_id(&self) -> String {
        get_message_id(&self.message)
    }
}

/// Data structure representing publish request params.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Publish {
    /// Topic to publish to.
    pub topic: Topic,

    /// Message to publish.
    pub message: String,

    /// Duration for which the message should be kept in the mailbox if it can't
    /// be delivered, in seconds.
    #[serde(rename = "ttl")]
    pub ttl_secs: u32,

    /// A label that identifies what type of message is sent based on the RPC
    /// method used.
    pub tag: u32,

    /// A flag that identifies whether the server should trigger a notification
    /// webhook to a client through a push server.
    #[serde(default, skip_serializing_if = "is_default")]
    pub prompt: bool,
}

impl Publish {
    /// Converts these publish params into subscription params.
    pub fn as_subscription(
        &self,
        subscription_id: SubscriptionId,
        published_at: i64,
    ) -> Subscription {
        Subscription {
            id: subscription_id,
            data: SubscriptionData {
                topic: self.topic.clone(),
                message: self.message.clone(),
                published_at,
                tag: self.tag,
            },
        }
    }

    /// Creates a subscription request from these publish params.
    pub fn as_subscription_request(
        &self,
        message_id: MessageId,
        subscription_id: SubscriptionId,
        published_at: i64,
    ) -> Request {
        Request {
            id: message_id,
            jsonrpc: JSON_RPC_VERSION_STR.to_string(),
            params: Params::Subscription(self.as_subscription(subscription_id, published_at)),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error("TTL too short")]
    TtlTooShort,

    #[error("TTL too long")]
    TtlTooLong,

    #[error("{0}")]
    Other(BoxError),
}

impl From<PublishError> for GenericError {
    fn from(err: PublishError) -> Self {
        Self::Request(Box::new(err))
    }
}

impl RequestPayload for Publish {
    type Error = PublishError;
    type Response = bool;

    fn validate(&self) -> Result<(), ValidationError> {
        self.topic.decode().map_err(ValidationError::TopicDecoding)?;

        Ok(())
    }

    fn into_params(self) -> Params {
        Params::Publish(self)
    }
}

fn is_default<T>(x: &T) -> bool
where
    T: Default + PartialEq + 'static,
{
    *x == Default::default()
}
