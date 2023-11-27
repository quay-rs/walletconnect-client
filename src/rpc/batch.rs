use super::{
    super::domain::{MessageId, SubscriptionId, Topic},
    {
        FetchResponse, GenericError, Params, RequestPayload, Unsubscribe, ValidationError,
        MAX_FETCH_BATCH_SIZE, MAX_RECEIVE_BATCH_SIZE, MAX_SUBSCRIPTION_BATCH_SIZE,
    },
};
use serde::{Deserialize, Serialize};
/// Multi-topic subscription request parameters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BatchSubscribe {
    /// The topics to subscribe to.
    pub topics: Vec<Topic>,
}

impl RequestPayload for BatchSubscribe {
    type Error = GenericError;
    type Response = Vec<SubscriptionId>;

    fn validate(&self) -> Result<(), ValidationError> {
        let batch_size = self.topics.len();

        if batch_size == 0 {
            return Err(ValidationError::BatchEmpty);
        }

        if batch_size > MAX_SUBSCRIPTION_BATCH_SIZE {
            return Err(ValidationError::BatchLimitExceeded {
                limit: MAX_SUBSCRIPTION_BATCH_SIZE,
                actual: batch_size,
            });
        }

        for topic in &self.topics {
            topic.decode().map_err(ValidationError::TopicDecoding)?;
        }

        Ok(())
    }

    fn into_params(self) -> Params {
        Params::BatchSubscribe(self)
    }
}

/// Multi-topic unsubscription request parameters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BatchUnsubscribe {
    /// The subscriptions to unsubscribe from.
    pub subscriptions: Vec<Unsubscribe>,
}

impl RequestPayload for BatchUnsubscribe {
    type Error = GenericError;
    type Response = bool;

    fn validate(&self) -> Result<(), ValidationError> {
        let batch_size = self.subscriptions.len();

        if batch_size == 0 {
            return Err(ValidationError::BatchEmpty);
        }

        if batch_size > MAX_SUBSCRIPTION_BATCH_SIZE {
            return Err(ValidationError::BatchLimitExceeded {
                limit: MAX_SUBSCRIPTION_BATCH_SIZE,
                actual: batch_size,
            });
        }

        for sub in &self.subscriptions {
            sub.validate()?;
        }

        Ok(())
    }

    fn into_params(self) -> Params {
        Params::BatchUnsubscribe(self)
    }
}

/// Data structure representing batch fetch request params.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BatchFetchMessages {
    /// The topics of the messages to fetch.
    pub topics: Vec<Topic>,
}

impl RequestPayload for BatchFetchMessages {
    type Error = GenericError;
    type Response = FetchResponse;

    fn validate(&self) -> Result<(), ValidationError> {
        let batch_size = self.topics.len();

        if batch_size == 0 {
            return Err(ValidationError::BatchEmpty);
        }

        if batch_size > MAX_FETCH_BATCH_SIZE {
            return Err(ValidationError::BatchLimitExceeded {
                limit: MAX_FETCH_BATCH_SIZE,
                actual: batch_size,
            });
        }

        for topic in &self.topics {
            topic.decode().map_err(ValidationError::TopicDecoding)?;
        }

        Ok(())
    }

    fn into_params(self) -> Params {
        Params::BatchFetchMessages(self)
    }
}

/// Represents a message receipt.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Receipt {
    /// The topic of the message to acknowledge.
    pub topic: Topic,

    /// The ID of the message to acknowledge.
    pub message_id: MessageId,
}

/// Data structure representing publish request params.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BatchReceiveMessages {
    /// The receipts to acknowledge.
    pub receipts: Vec<Receipt>,
}

impl RequestPayload for BatchReceiveMessages {
    type Error = GenericError;
    type Response = bool;

    fn validate(&self) -> Result<(), ValidationError> {
        let batch_size = self.receipts.len();

        if batch_size == 0 {
            return Err(ValidationError::BatchEmpty);
        }

        if batch_size > MAX_RECEIVE_BATCH_SIZE {
            return Err(ValidationError::BatchLimitExceeded {
                limit: MAX_RECEIVE_BATCH_SIZE,
                actual: batch_size,
            });
        }

        for receipt in &self.receipts {
            receipt.topic.decode().map_err(ValidationError::TopicDecoding)?;
        }

        Ok(())
    }

    fn into_params(self) -> Params {
        Params::BatchReceiveMessages(self)
    }
}
