use std::{array::TryFromSliceError, convert::Infallible};

use data_encoding::DecodeError;
use ed25519_dalek::{SecretKey, VerifyingKey};
use x25519_dalek::PublicKey;

use {
    super::{
        auth::{MULTICODEC_ED25519_BASE, MULTICODEC_ED25519_HEADER, MULTICODEC_ED25519_LENGTH},
        did::{combine_did_data, extract_did_data, DidError, DID_METHOD_KEY},
    },
    crate::new_type,
    derive_more::{AsMut, AsRef},
    serde::{Deserialize, Serialize},
    serde_aux::prelude::deserialize_number_from_string,
    std::{str::FromStr, sync::Arc},
};

#[derive(Debug, Clone, thiserror::Error)]
pub enum ClientIdDecodingError {
    #[error("Invalid issuer multicodec base")]
    Base,

    #[error("Invalid issuer base58")]
    Encoding,

    #[error("Invalid multicodec header")]
    Header,

    #[error("Invalid DID key data: {0}")]
    Did(#[from] DidError),

    #[error("Invalid issuer pubkey length")]
    Length,

    #[error(transparent)]
    DecodingError(#[from] DecodingError),

    #[error(transparent)]
    DecodeError(#[from] DecodeError),

    #[error(transparent)]
    Infallible(#[from] Infallible),

    #[error(transparent)]
    TryFromSliceError(#[from] TryFromSliceError),
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum DecodingError {
    #[error("Invalid encoding")]
    Encoding,

    #[error("Invalid data length")]
    Length,
}

new_type!(
    #[doc = "Represents the client ID type."]
    #[as_ref(forward)]
    #[from(forward)]
    ClientId: Arc<str>
);

impl ClientId {
    pub fn decode(&self) -> Result<DecodedClientId, ClientIdDecodingError> {
        DecodedClientId::try_from(self.clone())
    }
}

impl From<DecodedClientId> for ClientId {
    fn from(val: DecodedClientId) -> Self {
        Self(val.to_string().into())
    }
}

impl TryFrom<ClientId> for DecodedClientId {
    type Error = ClientIdDecodingError;

    fn try_from(value: ClientId) -> Result<Self, Self::Error> {
        value.as_ref().parse()
    }
}

impl From<DidKey> for ClientId {
    fn from(val: DidKey) -> Self {
        val.0.into()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, AsRef, AsMut, Serialize, Deserialize)]
#[as_ref(forward)]
#[as_mut(forward)]
pub struct DidKey(
    #[serde(with = "super::serde_helpers::client_id_as_did_key")] pub DecodedClientId,
);

impl From<DidKey> for VerifyingKey {
    fn from(val: DidKey) -> Self {
        val.0.as_verifying_key()
    }
}

impl From<DecodedClientId> for DidKey {
    fn from(val: DecodedClientId) -> Self {
        Self(val)
    }
}

impl TryFrom<ClientId> for DidKey {
    type Error = ClientIdDecodingError;

    fn try_from(value: ClientId) -> Result<Self, Self::Error> {
        value.decode().map(Self)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, AsRef, AsMut, Serialize, Deserialize)]
#[as_ref(forward)]
#[as_mut(forward)]
pub struct DecodedClientId(pub [u8; MULTICODEC_ED25519_LENGTH]);

impl DecodedClientId {
    #[inline]
    pub fn try_from_did_key(did: &str) -> Result<Self, ClientIdDecodingError> {
        extract_did_data(did, DID_METHOD_KEY)?.parse()
    }

    #[inline]
    pub fn to_did_key(&self) -> String {
        combine_did_data(DID_METHOD_KEY, &self.to_string())
    }

    #[inline]
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        Self(key.to_bytes())
    }

    #[inline]
    pub fn as_verifying_key(&self) -> VerifyingKey {
        // We know that the length is correct, so we can just unwrap.
        VerifyingKey::from_bytes(&self.0).unwrap()
    }

    #[inline]
    pub fn from_key(key: &PublicKey) -> Self {
        Self(key.to_bytes())
    }

    #[inline]
    pub fn as_public_key(&self) -> PublicKey {
        // We know that the length is correct, so we can just unwrap.
        PublicKey::from(self.0)
    }

    #[inline]
    pub fn to_hex(&self) -> String {
        data_encoding::HEXLOWER_PERMISSIVE.encode(&self.0)
    }

    #[inline]
    pub fn from_hex(string: &str) -> Result<Self, ClientIdDecodingError> {
        Ok(Self((&data_encoding::HEXLOWER_PERMISSIVE.decode(string.as_bytes())?)[..].try_into()?))
    }
}

impl From<VerifyingKey> for DecodedClientId {
    fn from(key: VerifyingKey) -> Self {
        Self::from_verifying_key(&key)
    }
}

impl From<DecodedClientId> for VerifyingKey {
    fn from(val: DecodedClientId) -> Self {
        val.as_verifying_key()
    }
}

impl From<DidKey> for DecodedClientId {
    fn from(val: DidKey) -> Self {
        val.0
    }
}

impl FromStr for DecodedClientId {
    type Err = ClientIdDecodingError;

    fn from_str(val: &str) -> Result<Self, Self::Err> {
        const TOTAL_DECODED_LENGTH: usize =
            MULTICODEC_ED25519_HEADER.len() + MULTICODEC_ED25519_LENGTH;

        let stripped =
            val.strip_prefix(MULTICODEC_ED25519_BASE).ok_or(ClientIdDecodingError::Base)?;

        let mut decoded: [u8; TOTAL_DECODED_LENGTH] = [0; TOTAL_DECODED_LENGTH];

        let decoded_len = bs58::decode(stripped)
            .onto(&mut decoded)
            .map_err(|_| ClientIdDecodingError::Encoding)?;

        if decoded_len != TOTAL_DECODED_LENGTH {
            return Err(ClientIdDecodingError::Length);
        }

        let pub_key = decoded
            .strip_prefix(&MULTICODEC_ED25519_HEADER)
            .ok_or(ClientIdDecodingError::Header)?;

        let mut data = Self::default();
        data.0.copy_from_slice(pub_key);

        Ok(data)
    }
}

impl std::fmt::Display for DecodedClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const PREFIX_LEN: usize = MULTICODEC_ED25519_HEADER.len();
        const TOTAL_LEN: usize = MULTICODEC_ED25519_LENGTH + PREFIX_LEN;

        let mut prefixed_data: [u8; TOTAL_LEN] = [0; TOTAL_LEN];
        prefixed_data[..PREFIX_LEN].copy_from_slice(&MULTICODEC_ED25519_HEADER);
        prefixed_data[PREFIX_LEN..].copy_from_slice(&self.0);

        let encoded_data = bs58::encode(prefixed_data).into_string();

        write!(f, "{MULTICODEC_ED25519_BASE}{encoded_data}")
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, AsRef, AsMut, Serialize, Deserialize)]
#[as_ref(forward)]
#[as_mut(forward)]
pub struct DecodedSymKey(pub [u8; MULTICODEC_ED25519_LENGTH]);

impl DecodedSymKey {
    #[inline]
    pub fn from_key(key: &SecretKey) -> Self {
        Self(*key)
    }

    #[inline]
    pub fn as_secret_key(&self) -> SecretKey {
        // We know that the length is correct, so we can just unwrap.
        self.0
    }
}

impl std::fmt::Display for DecodedSymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&data_encoding::HEXLOWER_PERMISSIVE.encode(&self.0))
    }
}

impl FromStr for DecodedSymKey {
    type Err = ClientIdDecodingError;

    fn from_str(val: &str) -> Result<Self, Self::Err> {
        const TOTAL_DECODED_LENGTH: usize =
            MULTICODEC_ED25519_HEADER.len() + MULTICODEC_ED25519_LENGTH;

        let stripped =
            val.strip_prefix(MULTICODEC_ED25519_BASE).ok_or(ClientIdDecodingError::Base)?;

        let mut decoded: [u8; TOTAL_DECODED_LENGTH] = [0; TOTAL_DECODED_LENGTH];

        let decoded_len = bs58::decode(stripped)
            .onto(&mut decoded)
            .map_err(|_| ClientIdDecodingError::Encoding)?;

        if decoded_len != TOTAL_DECODED_LENGTH {
            return Err(ClientIdDecodingError::Length);
        }

        let sym_key = decoded
            .strip_prefix(&MULTICODEC_ED25519_HEADER)
            .ok_or(ClientIdDecodingError::Header)?;

        let mut data = Self::default();
        data.0.copy_from_slice(sym_key);

        Ok(data)
    }
}

new_type!(
    #[doc = "Represents the topic type."]
    #[as_ref(forward)]
    #[from(forward)]
    Topic: Arc<str>
);

new_type!(
    #[doc = "Represents the subscription ID type."]
    #[as_ref(forward)]
    #[from(forward)]
    SubscriptionId: Arc<str>
);

new_type!(
    #[doc = "Represents the auth token subject type."]
    #[as_ref(forward)]
    #[from(forward)]
    AuthSubject: Arc<str>
);

new_type!(
    #[doc = "Represents the message ID type."]
    #[derive(Copy)]
    MessageId: #[serde(deserialize_with = "deserialize_number_from_string")] u64
);

impl MessageId {
    /// Minimum allowed value of a [`MessageId`].
    const MIN: Self = Self(1000000000);

    pub(crate) fn validate(&self) -> bool {
        self.0 >= Self::MIN.0
    }

    pub fn is_zero(&self) -> bool {
        // Message ID `0` is used when the client request failed to parse for whatever
        // reason, and the server doesn't know the message ID of that request, but still
        // wants to communicate the error.
        self.0 == 0
    }
}

new_type!(
    #[doc = "Represents the project ID type."]
    #[as_ref(forward)]
    #[from(forward)]
    ProjectId: Arc<str>
);

macro_rules! impl_byte_array_newtype {
    ($NewType:ident, $ParentType:ident, $ByteLength:expr) => {
        #[derive(
            Debug, Default, Clone, Hash, PartialEq, Eq, AsRef, AsMut, Serialize, Deserialize,
        )]
        #[as_ref(forward)]
        #[as_mut(forward)]
        #[serde(transparent)]
        pub struct $NewType(pub [u8; $ByteLength]);

        impl $NewType {
            pub const LENGTH: usize = $ByteLength;

            pub fn generate() -> Self {
                Self(rand::Rng::gen::<[u8; $ByteLength]>(&mut rand::thread_rng()))
            }

            pub fn from_bytes(bytes: [u8; $ByteLength]) -> Self {
                Self(bytes)
            }
        }

        impl FromStr for $NewType {
            type Err = DecodingError;

            fn from_str(val: &str) -> Result<Self, Self::Err> {
                let enc_len = val.len();
                if enc_len == 0 {
                    return Err(DecodingError::Length);
                }

                let dec_len = data_encoding::HEXLOWER_PERMISSIVE
                    .decode_len(enc_len)
                    .map_err(|_| DecodingError::Length)?;

                if dec_len != $ByteLength {
                    return Err(DecodingError::Length);
                }

                let mut data = Self::default();

                data_encoding::HEXLOWER_PERMISSIVE
                    .decode_mut(val.as_bytes(), &mut data.0)
                    .map_err(|_| DecodingError::Encoding)?;

                Ok(data)
            }
        }

        impl std::fmt::Display for $NewType {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&data_encoding::HEXLOWER_PERMISSIVE.encode(&self.0))
            }
        }

        const _: () = {
            impl $ParentType {
                pub fn decode(&self) -> Result<$NewType, DecodingError> {
                    $NewType::try_from(self.clone())
                }

                pub fn generate() -> Self {
                    Self::from($NewType::generate())
                }
            }
        };

        impl From<$NewType> for $ParentType {
            fn from(val: $NewType) -> Self {
                Self(val.to_string().into())
            }
        }

        impl TryFrom<$ParentType> for $NewType {
            type Error = DecodingError;

            fn try_from(value: $ParentType) -> Result<Self, Self::Error> {
                value.as_ref().parse()
            }
        }
    };
}

impl_byte_array_newtype!(DecodedTopic, Topic, 32);
impl_byte_array_newtype!(DecodedSubscription, SubscriptionId, 32);
impl_byte_array_newtype!(DecodedAuthSubject, AuthSubject, 32);
impl_byte_array_newtype!(DecodedProjectId, ProjectId, 16);
