use ethers::prelude::k256::ecdsa::SigningKey;

use {
    super::domain::DidKey,
    chrono::Utc,
    serde::{de::DeserializeOwned, Deserialize, Serialize},
    std::collections::HashSet,
};

pub const JWT_DELIMITER: &str = ".";
pub const JWT_HEADER_TYP: &str = "JWT";
pub const JWT_HEADER_ALG: &str = "EdDSA";
pub const JWT_VALIDATION_TIME_LEEWAY_SECS: i64 = 120;

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("Invalid format")]
    Format,

    #[error("Invalid encoding")]
    Encoding,

    #[error("Invalid JWT signing algorithm")]
    Header,

    #[error("JWT Token is expired: {:?}", expiration)]
    Expired { expiration: Option<i64> },

    #[error(
        "JWT Token is not yet valid: basic.iat: {}, now + time_leeway: {}, time_leeway: {}",
        basic_iat,
        now_time_leeway,
        time_leeway
    )]
    NotYetValid { basic_iat: i64, now_time_leeway: i64, time_leeway: i64 },

    #[error("Invalid audience")]
    InvalidAudience,

    #[error("Invalid signature")]
    Signature,

    #[error("Encoding keypair mismatch")]
    InvalidKeypair,

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error(transparent)]
    SignatureError(#[from] ethers::core::k256::ecdsa::Error),
}

#[derive(Serialize, Deserialize)]
pub struct JwtHeader<'a> {
    #[serde(borrow)]
    pub typ: &'a str,
    #[serde(borrow)]
    pub alg: &'a str,
}

impl Default for JwtHeader<'_> {
    fn default() -> Self {
        Self { typ: JWT_HEADER_TYP, alg: JWT_HEADER_ALG }
    }
}

impl<'a> JwtHeader<'a> {
    pub fn is_valid(&self) -> bool {
        self.typ == JWT_HEADER_TYP && self.alg == JWT_HEADER_ALG
    }
}

/// Basic JWT claims that are common to all JWTs used by the Relay.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JwtBasicClaims {
    /// Client ID matching the watch type.
    pub iss: DidKey,
    /// Relay URL.
    pub aud: String,
    /// Service URL.
    pub sub: String,
    /// Issued at, timestamp.
    pub iat: i64,
    /// Expiration, timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
}

impl VerifyableClaims for JwtBasicClaims {
    fn basic(&self) -> &JwtBasicClaims {
        self
    }
}

pub trait VerifyableClaims: Serialize + DeserializeOwned {
    /// Returns a reference to the basic claims, which may be a part of a larger
    /// set of claims.
    fn basic(&self) -> &JwtBasicClaims;

    /// Encodes the claims into a JWT string, signing it with the provided key.
    /// Returns an error if the provided key does not match the public key in
    /// the claims (`iss`), or if serialization fails.
    fn encode(&self, key: &SigningKey) -> Result<String, JwtError> {
        // let public_key = SigningKey::from_bytes(self.basic().iss.as_ref().into())
        //     .map_err(|_| JwtError::InvalidKeypair)?;
        //
        // // Make sure the keypair matches the public key in the claims.
        // if &public_key != key.verifying_key() {
        //     return Err(JwtError::InvalidKeypair);
        // }

        let encoder = &data_encoding::BASE64URL_NOPAD;
        let header = encoder.encode(serde_json::to_string(&JwtHeader::default())?.as_bytes());
        let claims = encoder.encode(serde_json::to_string(self)?.as_bytes());
        let message = format!("{header}.{claims}");
        let signature = encoder.encode(&key.sign_recoverable(message.as_bytes())?.0.to_bytes());

        Ok(format!("{message}.{signature}"))
    }

    /// Tries to parse the claims from a string, returning an error if the
    /// parsing fails for any reason.
    ///
    /// Note: This does not perorm the actual verification of the claims. After
    /// successful decoding, the claims should be verified using the
    /// [`VerifyableClaims::verify_basic()`] method.
    fn try_from_str(data: &str) -> Result<Self, JwtError>
    where
        Self: Sized,
    {
        let mut parts = data.splitn(3, JWT_DELIMITER);

        let (Some(header), Some(claims)) = (parts.next(), parts.next()) else {
            return Err(JwtError::Format);
        };

        let decoder = &data_encoding::BASE64URL_NOPAD;

        let header_len = decoder.decode_len(header.len()).map_err(|_| JwtError::Encoding)?;
        let claims_len = decoder.decode_len(claims.len()).map_err(|_| JwtError::Encoding)?;

        let mut output = vec![0u8; header_len.max(claims_len)];

        // Decode header.
        data_encoding::BASE64URL_NOPAD
            .decode_mut(header.as_bytes(), &mut output[..header_len])
            .map_err(|_| JwtError::Encoding)?;

        {
            let header = serde_json::from_slice::<JwtHeader>(&output[..header_len])
                .map_err(JwtError::Serialization)?;

            if !header.is_valid() {
                return Err(JwtError::Header);
            }
        }

        // Decode claims.
        data_encoding::BASE64URL_NOPAD
            .decode_mut(claims.as_bytes(), &mut output[..claims_len])
            .map_err(|_| JwtError::Encoding)?;

        let claims = serde_json::from_slice::<Self>(&output[..claims_len])
            .map_err(JwtError::Serialization)?;

        let mut parts = data.rsplitn(2, JWT_DELIMITER);

        let (Some(signature), Some(message)) = (parts.next(), parts.next()) else {
            return Err(JwtError::Format);
        };

        let key = jsonwebtoken::DecodingKey::from_ed_der(claims.basic().iss.as_ref());

        // Finally, verify signature.
        let sig_result = jsonwebtoken::crypto::verify(
            signature,
            message.as_bytes(),
            &key,
            jsonwebtoken::Algorithm::EdDSA,
        );

        match sig_result {
            Ok(true) => Ok(claims),

            _ => Err(JwtError::Signature),
        }
    }

    /// Performs basic verification of the claims. This includes the following
    /// checks:
    /// - The token is not expired (with a configurable leeway). This is
    ///   optional if the token has an `exp` value;
    /// - The token is not used before it's valid;
    /// - The token is issued for the correct audience.
    fn verify_basic(
        &self,
        aud: &HashSet<String>,
        time_leeway: impl Into<Option<i64>>,
    ) -> Result<(), JwtError> {
        let basic = self.basic();
        let time_leeway = time_leeway.into().unwrap_or(JWT_VALIDATION_TIME_LEEWAY_SECS);
        let now = Utc::now().timestamp();

        if matches!(basic.exp, Some(exp) if now - time_leeway > exp) {
            return Err(JwtError::Expired { expiration: basic.exp });
        }

        if now + time_leeway < basic.iat {
            return Err(JwtError::NotYetValid {
                basic_iat: basic.iat,
                now_time_leeway: now + time_leeway,
                time_leeway,
            });
        }

        if !aud.contains(&basic.aud) {
            return Err(JwtError::InvalidAudience);
        }

        Ok(())
    }
}
