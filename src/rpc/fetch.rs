use super::{
    super::domain::Topic,
    {GenericError, Params, RequestPayload, SubscriptionData, ValidationError},
};
use serde::{Deserialize, Serialize};
/// Data structure representing fetch request params.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FetchMessages {
    /// The topic of the messages to fetch.
    pub topic: Topic,
}

impl RequestPayload for FetchMessages {
    type Error = GenericError;
    type Response = FetchResponse;

    fn validate(&self) -> Result<(), ValidationError> {
        self.topic.decode().map_err(ValidationError::TopicDecoding)?;

        Ok(())
    }

    fn into_params(self) -> Params {
        Params::FetchMessages(self)
    }
}

/// Data structure representing fetch response.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchResponse {
    /// Array of messages fetched from the mailbox.
    pub messages: Vec<SubscriptionData>,

    /// Flag that indicates whether the client should keep fetching the
    /// messages.
    pub has_more: bool,
}
