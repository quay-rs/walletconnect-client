use super::{
    super::domain::{SubscriptionId, Topic},
    get_message_id, GenericError, MsgId, Params, RequestPayload, ValidationError,
};
use serde::{Deserialize, Serialize};
impl MsgId for Subscription {
    fn msg_id(&self) -> String {
        get_message_id(&self.data.message)
    }
}

/// Data structure representing subscription request params.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Subscription {
    /// The id of the subscription.
    pub id: SubscriptionId,

    /// The published data.
    pub data: SubscriptionData,
}

impl RequestPayload for Subscription {
    type Error = GenericError;
    type Response = bool;

    fn validate(&self) -> Result<(), ValidationError> {
        self.id.decode().map_err(ValidationError::SubscriptionIdDecoding)?;

        self.data.topic.decode().map_err(ValidationError::TopicDecoding)?;

        Ok(())
    }

    fn into_params(self) -> Params {
        Params::Subscription(self)
    }
}

/// Data structure representing subscription message params.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionData {
    /// The topic of the subscription.
    pub topic: Topic,

    /// The message for the subscription.
    pub message: String,

    /// Message publish timestamp in UTC milliseconds.
    pub published_at: i64,

    /// A label that identifies what type of message is sent based on the RPC
    /// method used.
    // #[serde(default, skip_serializing_if = "is_default")]
    pub tag: u32,
}
