pub mod client_id_as_did_key {

    use {
        crate::domain::DecodedClientId,
        serde::{Deserialize, Deserializer, Serialize, Serializer},
    };

    pub fn serialize<S>(data: &DecodedClientId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        data.to_did_key().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DecodedClientId, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        DecodedClientId::try_from_did_key(&String::deserialize(deserializer)?)
            .map_err(D::Error::custom)
    }
}
