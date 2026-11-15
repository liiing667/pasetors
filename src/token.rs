use crate::alloc::string::ToString;
#[cfg(feature = "std")]
use crate::claims::Claims;
use crate::common;
use crate::errors::Error;
#[cfg(feature = "std")]
use crate::footer::Footer;
use crate::token::private::Purpose;
use crate::version::private::Version;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::marker::PhantomData;

pub(crate) mod private {
    use super::Error;
    use crate::version::private::Version;

    // Inside private module to prevent users from implementing this themself.

    /// Purpose (`local`/`public`) of a token, given a version `V`.
    pub trait Purpose<V: Version> {
        /// Validate the header for a given version and purpose for some token.
        fn validate_header(token: &str) -> Result<(), Error>;
        /// Validate the tokens raw (decoded base64)
        /// message length for a given version and purpose for some token.
        fn validate_token_message_len(message: &[u8]) -> Result<(), Error>;
        /// Parse the raw payload of a token. Either the ciphertext or the message that was signed.
        /// The length **MUST** have been verified beforehand.
        fn parse_raw_payload(message: &[u8]) -> &[u8];
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
/// A public token.
pub struct Public;

#[derive(Debug, PartialEq, Eq, Clone)]
/// A local token.
pub struct Local;

impl<V: Version> Purpose<V> for Public {
    fn validate_header(token: &str) -> Result<(), Error> {
        if token.is_empty() || !token.starts_with(V::PUBLIC_HEADER) {
            return Err(Error::TokenFormat);
        }

        Ok(())
    }

    fn validate_token_message_len(message: &[u8]) -> Result<(), Error> {
        if message.len() <= V::PUBLIC_SIG {
            // Empty payload encrypted. Disallowed by PASETO
            return Err(Error::TokenFormat);
        }

        Ok(())
    }

    fn parse_raw_payload(message: &[u8]) -> &[u8] {
        debug_assert!(message.len() > V::PUBLIC_SIG);
        &message[..message.len() - V::PUBLIC_SIG]
    }
}

impl<V: Version> Purpose<V> for Local {
    fn validate_header(token: &str) -> Result<(), Error> {
        if token.is_empty() || !token.starts_with(V::LOCAL_HEADER) {
            return Err(Error::TokenFormat);
        }

        Ok(())
    }

    fn validate_token_message_len(message: &[u8]) -> Result<(), Error> {
        if message.len() <= V::LOCAL_NONCE + V::LOCAL_TAG {
            // Empty payload encrypted. Disallowed by PASETO
            return Err(Error::TokenFormat);
        }

        Ok(())
    }

    fn parse_raw_payload(message: &[u8]) -> &[u8] {
        debug_assert!(message.len() > V::LOCAL_TAG + V::LOCAL_NONCE);
        &message[V::LOCAL_NONCE..message.len() - V::LOCAL_TAG]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A [`TrustedToken`] is returned by either a `verify()` or `decrypt()` operation and represents
/// a validated token.
///
/// It represents a authenticated and non-tampered token. It **does not** validate additional things,
/// such as claims that may be within the token payload itself. These must still be validated separately.
///
/// However, using the [`crate::public`] and [`crate::local`] API will automatically handle claims
/// validation. Any validated claims may be retrieved with [`TrustedToken::payload_claims()`].
///
/// # Serialization
///
/// When the `serde` feature is enabled, a [`TrustedToken`] can only be deserialized from the
/// serialized representation of a token that was itself produced by serializing a token that had
/// already passed a `verify()` or `decrypt()` operation. The serialized form embeds the
/// fully-encoded PASETO token (signature or nonce/ciphertext/tag) together with an integrity
/// checksum binding every field. During deserialization the embedded token is parsed again and
/// the checksum must match, so arbitrary JSON with hand-crafted `header`/`payload`/`footer`
/// fields is rejected: it can never represent an authenticated token.
pub struct TrustedToken {
    header: String,
    // PASETO requires the payload to be valid JSON in UTF-8, so we say String for UTF-8.
    payload: String,
    #[cfg(feature = "std")]
    // If std is available, we also keep claims as JSON.
    payload_claims: Option<Claims>,
    footer: Vec<u8>,
    implicit_assert: Vec<u8>,
    // The fully-encoded PASETO token this `TrustedToken` was derived from. It is only needed for
    // (de)serialization, so it is not kept around when the `serde` feature is disabled.
    #[cfg(feature = "serde")]
    raw_token: String,
}

#[cfg(feature = "serde")]
const SERDE_INTEGRITY_FIELD: &str = "integrity";

#[cfg(feature = "serde")]
/// Non-cryptographic FNV-1a 64-bit checksum used only to bind the serialized fields of a
/// [`TrustedToken`] together. The cryptographic authentication of the token itself is provided
/// by the PASETO signature or AEAD tag in `raw_token`; this checksum merely makes sure that the
/// plaintext fields (which cannot be recovered from an encrypted `local` token) were not swapped
/// independently of the authenticated token.
fn integrity_checksum(
    header: &str,
    payload: &str,
    #[cfg(feature = "std")] payload_claims: Option<&Claims>,
    footer: &[u8],
    implicit_assert: &[u8],
    raw_token: &str,
) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET_BASIS;
    let mut feed = |bytes: &[u8]| {
        for &byte in bytes {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(PRIME);
        }
    };

    // Length-prefix every field so that fields cannot be shifted across boundaries.
    #[cfg(feature = "std")]
    // `Claims` is backed by a `HashMap`, so canonicalize it into a `BTreeMap` first to get a
    // deterministic byte representation for the checksum.
    let claims_json = payload_claims.map(|claims| {
        let value = serde_json::to_value(claims).unwrap_or_default();
        let canonical = value
            .as_object()
            .map(|object| {
                object
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<std::collections::BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        serde_json::to_vec(&canonical).unwrap_or_default()
    });
    #[cfg(feature = "std")]
    let claims_bytes = claims_json.as_deref().unwrap_or(&[]);

    let fields: &[&[u8]] = &[
        header.as_bytes(),
        payload.as_bytes(),
        #[cfg(feature = "std")]
        claims_bytes,
        footer,
        implicit_assert,
        raw_token.as_bytes(),
    ];
    for field in fields {
        feed(&(field.len() as u64).to_le_bytes());
        feed(field);
    }

    hash
}

#[cfg(feature = "serde")]
impl serde::Serialize for TrustedToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        // Number of fields: header, payload, [payload_claims], footer, implicit_assert,
        // token, integrity.
        let field_count = 6 + usize::from(cfg!(feature = "std"));
        let mut state = serializer.serialize_struct("TrustedToken", field_count)?;
        state.serialize_field("header", &self.header)?;
        state.serialize_field("payload", &self.payload)?;
        #[cfg(feature = "std")]
        if let Some(claims) = &self.payload_claims {
            state.serialize_field("payload_claims", claims)?;
        }
        if !self.footer.is_empty() {
            state.serialize_field("footer", &self.footer)?;
        }
        if !self.implicit_assert.is_empty() {
            state.serialize_field("implicit_assert", &self.implicit_assert)?;
        }
        state.serialize_field("token", &self.raw_token)?;
        state.serialize_field(
            SERDE_INTEGRITY_FIELD,
            &integrity_checksum(
                &self.header,
                &self.payload,
                #[cfg(feature = "std")]
                self.payload_claims.as_ref(),
                &self.footer,
                &self.implicit_assert,
                &self.raw_token,
            )
            .to_string(),
        )?;
        state.end()
    }
}

impl TrustedToken {
    pub(crate) fn _new(
        header: &str,
        payload: &[u8],
        footer: &[u8],
        implicit_assert: &[u8],
        #[cfg(feature = "serde")] raw_token: &str,
    ) -> Result<Self, Error> {
        Ok(Self {
            header: header.to_string(),
            payload: String::from_utf8(payload.to_vec()).map_err(|_| Error::PayloadInvalidUtf8)?,
            #[cfg(feature = "std")]
            payload_claims: None,
            footer: footer.to_vec(),
            implicit_assert: implicit_assert.to_vec(),
            #[cfg(feature = "serde")]
            raw_token: raw_token.to_string(),
        })
    }

    /// Get the header that is used for this token.
    pub fn header(&self) -> &str {
        &self.header
    }

    /// Get the payload that is used for this token.
    pub fn payload(&self) -> &str {
        &self.payload
    }

    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    /// Return the optional and validated [`Claims`] parsed from the tokens payload.
    ///
    /// - `None`: If no [`Claims`] have been parsed or validated.
    /// - `Some`: If some [`Claims`] have been parsed **AND** validated.
    ///
    /// [`Claims`]: crate::claims::Claims
    pub fn payload_claims(&self) -> Option<&Claims> {
        debug_assert!(self.payload_claims.is_some());
        match &self.payload_claims {
            Some(claims) => Some(claims),
            None => None,
        }
    }

    #[cfg(all(feature = "std", feature = "v4"))]
    /// Set the payload claims **AFTER HAVING VALIDATED THEM**.
    pub(crate) fn set_payload_claims(&mut self, claims: Claims) {
        self.payload_claims = Some(claims);
    }

    /// Get the footer used to create the token.
    ///
    /// Empty if `None` was used during creation.
    pub fn footer(&self) -> &[u8] {
        &self.footer
    }

    /// Get the implicit assertion used to create the token.
    ///
    /// Empty if `None` was used during creation.
    /// If token was created using `V2`, then it will always be empty.
    pub fn implicit_assert(&self) -> &[u8] {
        &self.implicit_assert
    }

    #[cfg(feature = "serde")]
    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    /// Get the fully-encoded PASETO token string that this [`TrustedToken`] was derived from.
    ///
    /// This is the same representation used for (de)serialization. It can be parsed again with
    /// [`UntrustedToken`] and re-verified or re-decrypted if the relevant key is available.
    pub fn raw_token(&self) -> &str {
        &self.raw_token
    }
}

#[cfg(feature = "serde")]
#[derive(serde_derive::Deserialize)]
struct TrustedTokenData {
    header: String,
    payload: String,
    token: String,
    integrity: String,
    #[cfg(feature = "std")]
    #[serde(default)]
    payload_claims: Option<Claims>,
    #[serde(default)]
    footer: Vec<u8>,
    #[serde(default)]
    implicit_assert: Vec<u8>,
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for TrustedToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        // Only the representation produced by serializing a previously validated
        // `TrustedToken` is accepted. Two independent gates must pass:
        // 1. The integrity checksum binds every plaintext field to the fully-encoded token, so
        //    swapping any field (including the encrypted `local` payload) invalidates it.
        // 2. The fully-encoded PASETO token (signature or nonce/ciphertext/tag) is parsed
        //    through `UntrustedToken` and its header/footer must match.
        // Hand-crafted JSON can never satisfy both, because it lacks a matching checksum and a
        // well-formed authenticated token.
        let data = TrustedTokenData::deserialize(deserializer)?;

        let expected_integrity = integrity_checksum(
            &data.header,
            &data.payload,
            #[cfg(feature = "std")]
            data.payload_claims.as_ref(),
            &data.footer,
            &data.implicit_assert,
            &data.token,
        )
        .to_string();
        if data.integrity != expected_integrity {
            return Err(D::Error::custom(ErrorMsg(Error::TokenFormat)));
        }

        let parsed = parse_raw_token(&data.token).map_err(|err| D::Error::custom(ErrorMsg(err)))?;

        let mut trusted = parsed;
        if trusted.header != data.header
            || trusted.footer != data.footer
            || (!trusted.payload.is_empty() && trusted.payload != data.payload)
        {
            return Err(D::Error::custom(ErrorMsg(Error::TokenFormat)));
        }
        if data.payload.is_empty() {
            return Err(D::Error::custom(ErrorMsg(Error::TokenFormat)));
        }
        trusted.payload = data.payload;
        // The implicit assertion is not encoded inside the PASETO token, so it cannot be
        // recovered from `token`. Restore it from the serialized field as-is.
        trusted.implicit_assert = data.implicit_assert;

        #[cfg(feature = "std")]
        {
            trusted.payload_claims = data.payload_claims;
        }

        Ok(trusted)
    }
}

#[cfg(feature = "serde")]
struct ErrorMsg(Error);

#[cfg(feature = "serde")]
impl core::fmt::Display for ErrorMsg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

#[cfg(feature = "serde")]
fn parse_raw_token(raw_token: &str) -> Result<TrustedToken, Error> {
    #[cfg(feature = "v2")]
    use crate::version2::V2;
    #[cfg(feature = "v3")]
    use crate::version3::V3;
    #[cfg(feature = "v4")]
    use crate::version4::V4;

    #[allow(unused_macros)]
    macro_rules! parse_public {
        ($version:ty, $header:expr) => {{
            let untrusted = UntrustedToken::<Public, $version>::try_from(raw_token)?;
            // For public tokens the payload is stored in the clear (only signed), so it can be
            // recovered directly from the encoded token.
            TrustedToken::_new(
                $header,
                untrusted.untrusted_payload(),
                untrusted.untrusted_footer(),
                &[],
                raw_token,
            )?
        }};
    }

    #[allow(unused_macros)]
    macro_rules! parse_local {
        ($version:ty, $header:expr) => {{
            let untrusted = UntrustedToken::<Local, $version>::try_from(raw_token)?;
            // For local tokens the payload is encrypted, so the plaintext cannot be recovered
            // from the encoded token. An empty placeholder is stored here; the caller is
            // responsible for cross-checking the serialized `payload` field. The encoded token
            // (nonce, ciphertext and authentication tag) is still fully preserved.
            TrustedToken::_new($header, b"", untrusted.untrusted_footer(), &[], raw_token)?
        }};
    }

    let mut trusted: TrustedToken = match raw_token {
        #[cfg(feature = "v2")]
        token if token.starts_with(V2::PUBLIC_HEADER) => parse_public!(V2, V2::PUBLIC_HEADER),
        #[cfg(feature = "v2")]
        token if token.starts_with(V2::LOCAL_HEADER) => parse_local!(V2, V2::LOCAL_HEADER),
        #[cfg(feature = "v3")]
        token if token.starts_with(V3::PUBLIC_HEADER) => parse_public!(V3, V3::PUBLIC_HEADER),
        #[cfg(feature = "v4")]
        token if token.starts_with(V4::PUBLIC_HEADER) => parse_public!(V4, V4::PUBLIC_HEADER),
        #[cfg(feature = "v4")]
        token if token.starts_with(V4::LOCAL_HEADER) => parse_local!(V4, V4::LOCAL_HEADER),
        _ => return Err(Error::TokenFormat),
    };
    // The implicit assertion is not part of the encoded PASETO token, so it cannot be recovered
    // from `raw_token`. It is cross-checked against the serialized field by the caller.
    trusted.implicit_assert = Vec::new();

    Ok(trusted)
}

#[cfg(feature = "std")]
impl TryFrom<&TrustedToken> for Footer {
    type Error = Error;

    fn try_from(value: &TrustedToken) -> Result<Self, Self::Error> {
        if value.footer.is_empty() {
            return Err(Error::FooterParsing);
        }

        let mut footer = Footer::new();
        footer.parse_bytes(value.footer())?;

        Ok(footer)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde_derive::Serialize))]
/// [`UntrustedToken`] can parse PASETO tokens in order to extract individual parts of it.
///
/// A use-case for this would be parsing the tokens footer, if this is not known before receiving it. Then,
/// the footer can be used during verification/decryption of the token itself.
///
/// This type should only be used in order to verify the validity of a token.
///
/// __WARNING__: Anything returned by this type should be treated as **UNTRUSTED** until the token
/// has been verified.
pub struct UntrustedToken<T, V> {
    // The original, fully-encoded PASETO token string. Only needed for (de)serialization of
    // `TrustedToken`, so it is not kept around when the `serde` feature is disabled.
    #[cfg(feature = "serde")]
    #[cfg_attr(feature = "serde", serde(skip))]
    raw_token: String,
    message: Vec<u8>,
    footer: Vec<u8>,
    #[cfg_attr(feature = "serde", serde(skip))]
    phantom_t: PhantomData<T>,
    #[cfg_attr(feature = "serde", serde(skip))]
    phantom_v: PhantomData<V>,
}

#[cfg(feature = "serde")]
#[derive(serde_derive::Deserialize)]
struct UntrustedTokenData {
    message: Vec<u8>,
    #[serde(default)]
    footer: Vec<u8>,
}

#[cfg(feature = "serde")]
impl<'de, T, V> serde::Deserialize<'de> for UntrustedToken<T, V>
where
    T: Purpose<V>,
    V: Version,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        let data = UntrustedTokenData::deserialize(deserializer)?;
        let header = if T::validate_header(V::PUBLIC_HEADER).is_ok() {
            V::PUBLIC_HEADER
        } else {
            V::LOCAL_HEADER
        };

        let mut raw_token = String::from(header);
        raw_token.push_str(
            &common::encode_b64(&data.message).map_err(|err| D::Error::custom(ErrorMsg(err)))?,
        );
        if !data.footer.is_empty() {
            raw_token.push('.');
            raw_token.push_str(
                &common::encode_b64(&data.footer).map_err(|err| D::Error::custom(ErrorMsg(err)))?,
            );
        }

        // Re-parse the reconstructed token so any malformed input is rejected instead of
        // producing an `UntrustedToken` with inconsistent internals.
        Self::try_from(raw_token.as_str()).map_err(|err| D::Error::custom(ErrorMsg(err)))
    }
}

impl<T: Purpose<V>, V: Version> TryFrom<&str> for UntrustedToken<T, V> {
    type Error = Error;

    /// This fails if `value` is not a PASETO token or it has invalid base64 encoding.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        T::validate_header(value)?;

        let parts_split = value.split('.').collect::<Vec<&str>>();
        if parts_split.len() < 3 || parts_split.len() > 4 {
            return Err(Error::TokenFormat);
        }
        if parts_split[2].is_empty() {
            // Empty payload entirely
            return Err(Error::TokenFormat);
        }

        let m_raw = common::decode_b64(parts_split[2])?;
        T::validate_token_message_len(&m_raw)?;
        let is_footer_present = parts_split.len() == 4;

        Ok(Self {
            #[cfg(feature = "serde")]
            raw_token: value.to_string(),
            message: m_raw,
            footer: {
                if is_footer_present {
                    common::decode_b64(parts_split[3])?
                } else {
                    Vec::<u8>::new()
                }
            },
            phantom_t: PhantomData,
            phantom_v: PhantomData,
        })
    }
}

impl<T: Purpose<V>, V: Version> TryFrom<&String> for UntrustedToken<T, V> {
    type Error = Error;

    /// This fails if `value` is not a PASETO token or it has invalid base64 encoding.
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl<T: Purpose<V>, V: Version> UntrustedToken<T, V> {
    /// Return untrusted message of this [`UntrustedToken`].
    /// If it is a [`Local`] token, this is the encrypted message with nonce and tag.
    /// If it is a [`Public`] token, the signature is included.
    pub fn untrusted_message(&self) -> &[u8] {
        &self.message
    }

    /// Return untrusted payload only of this [`UntrustedToken`]'s message body.
    /// If it is a [`Local`] token, this is the encrypted message sans nonce and tag.
    /// If it is a [`Public`] token, the signature is not included.
    pub fn untrusted_payload(&self) -> &[u8] {
        T::parse_raw_payload(self.untrusted_message())
    }

    /// Return untrusted footer of this [`UntrustedToken`].
    /// Empty if there was no footer in the token.
    pub fn untrusted_footer(&self) -> &[u8] {
        &self.footer
    }

    #[cfg(feature = "serde")]
    pub(crate) fn raw_token(&self) -> &str {
        &self.raw_token
    }
}

#[cfg(test)]
#[cfg(all(feature = "v2", feature = "v3", feature = "v4"))]
mod tests_untrusted {
    use super::*;
    use crate::common::encode_b64;
    use crate::errors::Error;
    use crate::version::private::Version;
    use crate::{version2::V2, version3::V3, version4::V4};

    const V2_PUBLIC_TOKEN: &str = "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
    const V2_LOCAL_TOKEN: &str = "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
    const V3_PUBLIC_TOKEN: &str = "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9ZWrbGZ6L0MDK72skosUaS0Dz7wJ_2bMcM6tOxFuCasO9GhwHrvvchqgXQNLQQyWzGC2wkr-VKII71AvkLpC8tJOrzJV1cap9NRwoFzbcXjzMZyxQ0wkshxZxx8ImmNWP.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9";
    const V4_PUBLIC_TOKEN: &str = "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
    const V4_LOCAL_TOKEN: &str = "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

    const TOKEN_LIST: [&str; 5] = [
        V2_PUBLIC_TOKEN,
        V2_LOCAL_TOKEN,
        V3_PUBLIC_TOKEN,
        V4_LOCAL_TOKEN,
        V4_PUBLIC_TOKEN,
    ];

    fn test_untrusted_parse_fails(invalid: &str, expected_err: Error) {
        if invalid.starts_with(V2::LOCAL_HEADER) {
            assert_eq!(
                UntrustedToken::<Local, V2>::try_from(invalid).unwrap_err(),
                expected_err
            );
        }
        if invalid.starts_with(V2::PUBLIC_HEADER) {
            assert_eq!(
                UntrustedToken::<Public, V2>::try_from(invalid).unwrap_err(),
                expected_err
            );
        }
        if invalid.starts_with(V3::LOCAL_HEADER) {
            assert_eq!(
                UntrustedToken::<Local, V3>::try_from(invalid).unwrap_err(),
                expected_err
            );
        }
        if invalid.starts_with(V3::PUBLIC_HEADER) {
            assert_eq!(
                UntrustedToken::<Public, V3>::try_from(invalid).unwrap_err(),
                expected_err
            );
        }
        if invalid.starts_with(V4::LOCAL_HEADER) {
            assert_eq!(
                UntrustedToken::<Local, V4>::try_from(invalid).unwrap_err(),
                expected_err
            );
        }
        if invalid.starts_with(V4::PUBLIC_HEADER) {
            assert_eq!(
                UntrustedToken::<Public, V4>::try_from(invalid).unwrap_err(),
                expected_err
            );
        }
    }

    #[test]
    fn empty_string() {
        assert_eq!(
            UntrustedToken::<Local, V2>::try_from("").unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Public, V2>::try_from("").unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Local, V3>::try_from("").unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Public, V3>::try_from("").unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Local, V4>::try_from("").unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Public, V4>::try_from("").unwrap_err(),
            Error::TokenFormat
        );
    }

    #[test]
    fn no_separators() {
        for token in TOKEN_LIST {
            let split = token.split('.').collect::<Vec<&str>>();
            let invalid: String = split.iter().copied().collect();

            test_untrusted_parse_fails(&invalid, Error::TokenFormat);
        }
    }

    #[test]
    // NOTE: See https://github.com/paseto-standard/paseto-spec/issues/17
    fn missing_payload() {
        for token in TOKEN_LIST {
            let split = token.split('.').collect::<Vec<&str>>();
            let invalid: String = format!("{}.{}..{}", split[0], split[1], split[3]);

            test_untrusted_parse_fails(&invalid, Error::TokenFormat);
        }
    }

    #[test]
    fn payload_too_short() {
        for token in TOKEN_LIST {
            let split = token.split('.').collect::<Vec<&str>>();
            let invalid: String = format!(
                "{}.{}.{}.{}",
                split[0],
                split[1],
                encode_b64(split[0].as_bytes()).unwrap(),
                split[3]
            );

            test_untrusted_parse_fails(&invalid, Error::TokenFormat);
        }
    }

    #[test]
    fn extra_after_footer() {
        for token in TOKEN_LIST {
            let mut invalid = token.to_string();
            invalid.push_str(".shouldNotBeHere");

            test_untrusted_parse_fails(&invalid, Error::TokenFormat);
        }
    }

    #[test]
    fn invalid_header() {
        // Invalid version
        assert_eq!(
            UntrustedToken::<Public, V2>::try_from(&V2_PUBLIC_TOKEN.replace("v2", "v4"))
                .unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Local, V2>::try_from(&V2_LOCAL_TOKEN.replace("v2", "v4")).unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Public, V3>::try_from(&V3_PUBLIC_TOKEN.replace("v3", "v2"))
                .unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Local, V4>::try_from(&V4_LOCAL_TOKEN.replace("v4", "v2")).unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Public, V4>::try_from(&V4_PUBLIC_TOKEN.replace("v4", "v2"))
                .unwrap_err(),
            Error::TokenFormat
        );

        // Invalid purpose
        assert_eq!(
            UntrustedToken::<Public, V2>::try_from(&V2_PUBLIC_TOKEN.replace("public", "local"))
                .unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Local, V2>::try_from(&V2_LOCAL_TOKEN.replace("local", "public"))
                .unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Public, V3>::try_from(&V3_PUBLIC_TOKEN.replace("public", "local"))
                .unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Local, V4>::try_from(&V4_LOCAL_TOKEN.replace("local", "public"))
                .unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Public, V4>::try_from(&V4_PUBLIC_TOKEN.replace("public", "local"))
                .unwrap_err(),
            Error::TokenFormat
        );
    }

    #[test]
    fn invalid_base64() {
        for token in TOKEN_LIST {
            let split = token.split('.').collect::<Vec<&str>>();

            let invalid: String = format!("{}.{}.{}!.{}", split[0], split[1], split[2], split[3]);
            test_untrusted_parse_fails(&invalid, Error::Base64);

            let invalid: String = format!("{}.{}.{}.{}!", split[0], split[1], split[2], split[3]);
            test_untrusted_parse_fails(&invalid, Error::Base64);
        }
    }

    #[cfg(feature = "v2")]
    #[test]
    fn valid_v2_local() {
        // "2-E-1"
        let valid_no_footer = "v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ";
        // "2-E-5"
        let valid_with_footer = "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

        let untrusted_no_footer = UntrustedToken::<Local, V2>::try_from(valid_no_footer).unwrap();
        let untrusted_with_footer =
            UntrustedToken::<Local, V2>::try_from(valid_with_footer).unwrap();

        // Note: We don't test for untrusted message, since it is encrypted.
        assert_eq!(untrusted_no_footer.untrusted_footer(), &[0u8; 0]);
        assert_eq!(
            untrusted_with_footer.untrusted_footer(),
            "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}".as_bytes()
        );
    }

    #[cfg(feature = "v2")]
    #[test]
    fn valid_v2_public() {
        // "2-S-1"
        let valid_no_footer = "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGntTu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_DjJK2ZXC2SUYuOFM-Q_5Cw";
        // "2-S-2"
        let valid_with_footer = "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

        let untrusted_no_footer = UntrustedToken::<Public, V2>::try_from(valid_no_footer).unwrap();
        let untrusted_with_footer =
            UntrustedToken::<Public, V2>::try_from(valid_with_footer).unwrap();

        assert_eq!(
            untrusted_no_footer.untrusted_payload(),
            "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}"
                .as_bytes()
        );
        assert_eq!(untrusted_no_footer.untrusted_footer(), &[0u8; 0]);

        assert_eq!(
            untrusted_with_footer.untrusted_payload(),
            "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}"
                .as_bytes()
        );
        assert_eq!(
            untrusted_with_footer.untrusted_footer(),
            "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}".as_bytes()
        );
    }

    #[cfg(feature = "v3")]
    #[test]
    fn valid_v3_public() {
        // "3-S-1"
        let valid_no_footer = "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9qqEwwrKHKi5lJ7b9MBKc0G4MGZy0ptUiMv3lAUAaz-JY_zjoqBSIxMxhfAoeNYiSyvfUErj76KOPWm1OeNnBPkTSespeSXDGaDfxeIrl3bRrPEIy7tLwLAIsRzsXkfph";
        // "3-S-2"
        let valid_with_footer = "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9ZWrbGZ6L0MDK72skosUaS0Dz7wJ_2bMcM6tOxFuCasO9GhwHrvvchqgXQNLQQyWzGC2wkr-VKII71AvkLpC8tJOrzJV1cap9NRwoFzbcXjzMZyxQ0wkshxZxx8ImmNWP.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9";

        let untrusted_no_footer = UntrustedToken::<Public, V3>::try_from(valid_no_footer).unwrap();
        let untrusted_with_footer =
            UntrustedToken::<Public, V3>::try_from(valid_with_footer).unwrap();

        assert_eq!(
            untrusted_no_footer.untrusted_payload(),
            "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"
                .as_bytes()
        );
        assert_eq!(untrusted_no_footer.untrusted_footer(), &[0u8; 0]);

        assert_eq!(
            untrusted_with_footer.untrusted_payload(),
            "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"
                .as_bytes()
        );
        assert_eq!(
            untrusted_with_footer.untrusted_footer(),
            "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}".as_bytes()
        );
    }

    #[cfg(feature = "v4")]
    #[test]
    fn valid_v4_public() {
        // "4-S-1"
        let valid_no_footer = "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA";
        // "4-S-2"
        let valid_with_footer = "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

        let untrusted_no_footer = UntrustedToken::<Public, V4>::try_from(valid_no_footer).unwrap();
        let untrusted_with_footer =
            UntrustedToken::<Public, V4>::try_from(valid_with_footer).unwrap();

        assert_eq!(
            untrusted_no_footer.untrusted_payload(),
            "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"
                .as_bytes()
        );
        assert_eq!(untrusted_no_footer.untrusted_footer(), &[0u8; 0]);

        assert_eq!(
            untrusted_with_footer.untrusted_payload(),
            "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"
                .as_bytes()
        );
        assert_eq!(
            untrusted_with_footer.untrusted_footer(),
            "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}".as_bytes()
        );
    }

    #[cfg(feature = "v4")]
    #[test]
    fn valid_v4_local() {
        // "4-E-1"
        let valid_no_footer = "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg";
        // "4-E-5"
        let valid_with_footer = "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

        let untrusted_no_footer = UntrustedToken::<Local, V4>::try_from(valid_no_footer).unwrap();
        let untrusted_with_footer =
            UntrustedToken::<Local, V4>::try_from(valid_with_footer).unwrap();

        // Note: We don't test for untrusted message, since it is encrypted.
        assert_eq!(untrusted_no_footer.untrusted_footer(), &[0u8; 0]);
        assert_eq!(
            untrusted_with_footer.untrusted_footer(),
            "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}".as_bytes()
        );
    }

    #[test]
    fn local_token_nonce_tag_no_payload_v4() {
        assert!(UntrustedToken::<Local, V4>::try_from(
            "v4.local.444444bbbbb444444444bbb444444bbb44444444444444888888888888888cJJbbb44444444",
        )
        .is_err());
    }

    #[test]
    fn local_token_nonce_tag_no_payload_v3() {
        assert!(UntrustedToken::<Public, V3>::try_from(
            "v3.local.oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo",
        ).is_err());
    }

    #[test]
    fn test_get_footer_from_trusted() {
        let mut footer = Footer::default();
        footer.add_additional("t", "v").unwrap();
        let mut tt = TrustedToken::_new(
            "v3.local.",
            b"test msg",
            footer.to_string().unwrap().as_bytes(),
            b"",
            #[cfg(feature = "serde")]
            "v3.local.dGVzdCBtc2c",
        )
        .unwrap();
        assert!(Footer::try_from(&tt).is_ok());
        tt.footer = Vec::<u8>::new();
        assert!(Footer::try_from(&tt).is_err());
    }

    #[test]
    fn test_trusted_claims() {
        let mut footer = Footer::default();
        footer.add_additional("t", "v").unwrap();
        let mut tt = TrustedToken::_new(
            "v3.local.",
            b"test msg",
            footer.to_string().unwrap().as_bytes(),
            b"",
            #[cfg(feature = "serde")]
            "v3.local.dGVzdCBtc2c",
        )
        .unwrap();
        let claims = Claims::new().unwrap();
        tt.set_payload_claims(claims.clone());

        assert_eq!(tt.payload_claims.unwrap(), claims);
    }
}

#[cfg(all(test, feature = "serde", feature = "v4"))]
mod test_trusted {
    use super::*;
    use crate::claims::ClaimsValidationRules;
    use crate::keys::{Generate, SymmetricKey};
    use crate::local;
    use crate::version4::V4;

    #[test]
    /// Simple serialize -> deserialize test to ensure that round trip produces the same result
    fn test_serde() {
        let sk = SymmetricKey::<V4>::generate().unwrap();
        let mut claims = Claims::new().unwrap();
        // additional claim for searching in the JSON output
        claims.add_additional("test", "serde").unwrap();
        let mut footer = Footer::default();
        footer.add_additional("test", "footer").unwrap();
        let token = local::encrypt(&sk, &claims, Some(&footer), None).unwrap();
        let validation_rules = ClaimsValidationRules::default();
        let untrusted = UntrustedToken::<Local, V4>::try_from(&token).unwrap();

        assert_eq!(
            &untrusted,
            &serde_json::from_str::<UntrustedToken<Local, V4>>(
                &serde_json::to_string(&untrusted).unwrap()
            )
            .unwrap()
        );

        let trusted =
            local::decrypt(&sk, &untrusted, &validation_rules, Some(&footer), None).unwrap();

        let json = serde_json::to_string(&trusted).unwrap();
        // a couple of manual assertions that some keys values have appeared in the JSON
        assert!(json.contains("\"payload\""));
        assert!(json.contains("\"payload_claims\""));
        // The fully-encoded, authenticated token is embedded in the serialized representation.
        assert!(json.contains("\"token\""));
        assert!(json.contains(&token));
        assert!(json.contains("\\\"test\\\":\\\"serde\\\""));
        // footer is a Vec<u8> so need a fixed byte slice to compare in JSON
        assert!(json.contains(
            "\"footer\":[123,34,116,101,115,116,34,58,34,102,111,111,116,101,114,34,125]"
        ));
        // implicit_assert = None so shouldn't appear in the serialized version
        assert!(!json.contains("implicit_assert"));

        let output: TrustedToken = serde_json::from_str(&json).unwrap();

        assert_eq!(output, trusted);
        assert_eq!(output.raw_token(), token);
        assert_eq!(output.payload_claims.unwrap(), claims);
    }

    #[test]
    /// A round trip through JSON must produce an identical `TrustedToken`.
    fn test_serde_roundtrip_with_implicit_assertion() {
        let sk = SymmetricKey::<V4>::generate().unwrap();
        let claims = Claims::new().unwrap();
        let token = local::encrypt(&sk, &claims, None, Some(b"implicit assertion")).unwrap();
        let untrusted = UntrustedToken::<Local, V4>::try_from(&token).unwrap();
        let trusted = local::decrypt(
            &sk,
            &untrusted,
            &ClaimsValidationRules::default(),
            None,
            Some(b"implicit assertion"),
        )
        .unwrap();

        let json = serde_json::to_string(&trusted).unwrap();
        assert!(json.contains("\"implicit_assert\""));
        let output: TrustedToken = serde_json::from_str(&json).unwrap();
        assert_eq!(output, trusted);
    }

    #[test]
    /// Forged JSON without an embedded, well-formed token must never deserialize into a
    /// `TrustedToken`.
    fn test_forged_json_without_token_is_rejected() {
        let forged = r#"{
            "header": "v4.local.",
            "payload": "{\"data\":\"forged message\"}",
            "footer": [],
            "implicit_assert": []
        }"#;
        assert!(serde_json::from_str::<TrustedToken>(forged).is_err());

        // A `token` field that is not a valid PASETO token must also be rejected.
        let forged = r#"{
            "header": "v4.local.",
            "payload": "{\"data\":\"forged message\"}",
            "token": "not-a-paseto-token",
            "footer": [],
            "implicit_assert": []
        }"#;
        assert!(serde_json::from_str::<TrustedToken>(forged).is_err());

        // Unknown headers cannot be turned into a `TrustedToken` either.
        let forged = r#"{
            "header": "v99.public.",
            "payload": "forged",
            "token": "v99.public.Zm9yZ2Vk",
            "footer": [],
            "implicit_assert": []
        }"#;
        assert!(serde_json::from_str::<TrustedToken>(forged).is_err());
    }

    #[test]
    /// A well-formed embedded token whose companion fields were tampered with must be rejected,
    /// because the fields no longer match the authenticated token.
    fn test_tampered_fields_are_rejected() {
        let sk = SymmetricKey::<V4>::generate().unwrap();
        let claims = Claims::new().unwrap();
        let token = local::encrypt(&sk, &claims, None, None).unwrap();
        let untrusted = UntrustedToken::<Local, V4>::try_from(&token).unwrap();
        let trusted = local::decrypt(
            &sk,
            &untrusted,
            &ClaimsValidationRules::default(),
            None,
            None,
        )
        .unwrap();
        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&trusted).unwrap()).unwrap();

        // Tamper with the payload while leaving the authenticated `token` untouched.
        value["payload"] = serde_json::Value::String("{\"data\":\"tampered\"}".to_string());
        assert!(serde_json::from_value::<TrustedToken>(value).is_err());

        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&trusted).unwrap()).unwrap();
        // Tamper with the header.
        value["header"] = serde_json::Value::String("v2.local.".to_string());
        assert!(serde_json::from_value::<TrustedToken>(value).is_err());

        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&trusted).unwrap()).unwrap();
        // Tamper with the embedded token itself.
        let raw = value["token"].as_str().unwrap();
        value["token"] = serde_json::Value::String(format!("{raw}tampered"));
        assert!(serde_json::from_value::<TrustedToken>(value).is_err());

        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&trusted).unwrap()).unwrap();
        // Removing the integrity checksum must reject deserialization.
        value.as_object_mut().unwrap().remove("integrity");
        assert!(serde_json::from_value::<TrustedToken>(value).is_err());

        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&trusted).unwrap()).unwrap();
        // Tampering with the validated claims without updating the checksum must be rejected.
        value["payload_claims"]["iss"] = serde_json::Value::String("forged".to_string());
        assert!(serde_json::from_value::<TrustedToken>(value).is_err());

        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&trusted).unwrap()).unwrap();
        // A stale checksum over forged fields is rejected by the integrity gate.
        value["payload"] = serde_json::Value::String("{\"data\":\"tampered\"}".to_string());
        value["integrity"] = serde_json::Value::String("0".to_string());
        assert!(serde_json::from_value::<TrustedToken>(value).is_err());
    }
}

#[cfg(all(
    test,
    feature = "serde",
    feature = "std",
    feature = "v2",
    feature = "v3",
    feature = "v4"
))]
mod test_trusted_versions {
    use super::*;
    use crate::keys::{AsymmetricKeyPair, Generate, SymmetricKey};
    use crate::version2::{LocalToken as V2Local, PublicToken as V2Public, V2};
    use crate::version3::{PublicToken as V3Public, V3};
    use crate::version4::{LocalToken as V4Local, PublicToken as V4Public, V4};
    use core::convert::TryFrom;

    const MESSAGE: &[u8] = b"{\"data\":\"this is a trusted message\"}";
    const FOOTER: &[u8] = b"{\"kid\":\"footer-key-id\"}";
    const IMPLICIT_ASSERTION: &[u8] = b"implicit-assertion";

    fn assert_roundtrip(trusted: &TrustedToken) {
        let json = serde_json::to_string(trusted).unwrap();
        let restored: TrustedToken = serde_json::from_str(&json).unwrap();
        assert_eq!(&restored, trusted);
        assert_eq!(restored.raw_token(), trusted.raw_token());

        // The forged representation (no embedded token) must always be refused.
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value.as_object_mut().unwrap().remove("token");
        assert!(serde_json::from_value::<TrustedToken>(value).is_err());
    }

    #[test]
    fn v2_public_roundtrip_and_forgery_rejected() {
        let kp = AsymmetricKeyPair::<V2>::generate().unwrap();
        let raw = V2Public::sign(&kp.secret, MESSAGE, Some(FOOTER)).unwrap();
        let untrusted = UntrustedToken::<Public, V2>::try_from(&raw).unwrap();
        let trusted = V2Public::verify(&kp.public, &untrusted, Some(FOOTER)).unwrap();
        assert_eq!(trusted.payload().as_bytes(), MESSAGE);
        assert_eq!(trusted.footer(), FOOTER);
        assert_roundtrip(&trusted);
    }

    #[test]
    fn v2_local_roundtrip_and_forgery_rejected() {
        let sk = SymmetricKey::<V2>::generate().unwrap();
        let raw = V2Local::encrypt(&sk, MESSAGE, Some(FOOTER)).unwrap();
        let untrusted = UntrustedToken::<Local, V2>::try_from(&raw).unwrap();
        let trusted = V2Local::decrypt(&sk, &untrusted, Some(FOOTER)).unwrap();
        assert_eq!(trusted.payload().as_bytes(), MESSAGE);
        assert_eq!(trusted.footer(), FOOTER);
        assert_roundtrip(&trusted);
    }

    #[test]
    fn v3_public_roundtrip_and_forgery_rejected() {
        let kp = AsymmetricKeyPair::<V3>::generate().unwrap();
        let raw =
            V3Public::sign(&kp.secret, MESSAGE, Some(FOOTER), Some(IMPLICIT_ASSERTION)).unwrap();
        let untrusted = UntrustedToken::<Public, V3>::try_from(&raw).unwrap();
        let trusted = V3Public::verify(
            &kp.public,
            &untrusted,
            Some(FOOTER),
            Some(IMPLICIT_ASSERTION),
        )
        .unwrap();
        assert_eq!(trusted.payload().as_bytes(), MESSAGE);
        assert_eq!(trusted.footer(), FOOTER);
        assert_eq!(trusted.implicit_assert(), IMPLICIT_ASSERTION);
        assert_roundtrip(&trusted);
    }

    #[test]
    fn v4_public_roundtrip_and_forgery_rejected() {
        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        let raw =
            V4Public::sign(&kp.secret, MESSAGE, Some(FOOTER), Some(IMPLICIT_ASSERTION)).unwrap();
        let untrusted = UntrustedToken::<Public, V4>::try_from(&raw).unwrap();
        let trusted = V4Public::verify(
            &kp.public,
            &untrusted,
            Some(FOOTER),
            Some(IMPLICIT_ASSERTION),
        )
        .unwrap();
        assert_eq!(trusted.payload().as_bytes(), MESSAGE);
        assert_eq!(trusted.footer(), FOOTER);
        assert_eq!(trusted.implicit_assert(), IMPLICIT_ASSERTION);
        assert_roundtrip(&trusted);
    }

    #[test]
    fn v4_local_roundtrip_and_forgery_rejected() {
        let sk = SymmetricKey::<V4>::generate().unwrap();
        let raw = V4Local::encrypt(&sk, MESSAGE, Some(FOOTER), Some(IMPLICIT_ASSERTION)).unwrap();
        let untrusted = UntrustedToken::<Local, V4>::try_from(&raw).unwrap();
        let trusted =
            V4Local::decrypt(&sk, &untrusted, Some(FOOTER), Some(IMPLICIT_ASSERTION)).unwrap();
        assert_eq!(trusted.payload().as_bytes(), MESSAGE);
        assert_eq!(trusted.footer(), FOOTER);
        assert_eq!(trusted.implicit_assert(), IMPLICIT_ASSERTION);
        assert_roundtrip(&trusted);
    }

    #[test]
    fn every_header_rejects_bare_forged_json() {
        for header in [
            "v2.public.",
            "v2.local.",
            "v3.public.",
            "v3.local.",
            "v4.public.",
            "v4.local.",
        ] {
            let forged = format!(
                "{{\"header\":\"{header}\",\"payload\":\"{{\\\"data\\\":\\\"forged\\\"}}\",\"footer\":[],\"implicit_assert\":[]}}"
            );
            assert!(
                serde_json::from_str::<TrustedToken>(&forged).is_err(),
                "forged JSON for {header} must be rejected"
            );
        }
    }

    #[test]
    fn attacker_cannot_upgrade_untrusted_json_into_trusted_token() {
        use crate::claims::ClaimsValidationRules;
        use crate::local;

        // A legitimate token is produced through a real decryption, so its serialized form is
        // accepted on the receiving side.
        let sk = SymmetricKey::<V4>::generate().unwrap();
        let claims = Claims::new().unwrap();
        let raw = local::encrypt(&sk, &claims, None, None).unwrap();
        let untrusted = UntrustedToken::<Local, V4>::try_from(&raw).unwrap();
        let trusted = local::decrypt(
            &sk,
            &untrusted,
            &ClaimsValidationRules::default(),
            None,
            None,
        )
        .unwrap();
        let legitimate_json = serde_json::to_string(&trusted).unwrap();
        assert!(serde_json::from_str::<TrustedToken>(&legitimate_json).is_ok());

        // Every shape an attacker might craft without a verified token must fail.
        let attack_payloads = [
            r#"{"header":"v4.local.","payload":"{\"admin\":true}"}"#.to_string(),
            r#"{"header":"v4.public.","payload":"[]","token":""}"#.to_string(),
            r#"{"header":"v4.local.","payload":"x","token":"v4.local.","integrity":"0"}"#
                .to_string(),
            "null".to_string(),
            "\"v4.local.foo\"".to_string(),
            "[]".to_string(),
        ];
        for attack in attack_payloads {
            assert!(
                serde_json::from_str::<TrustedToken>(&attack).is_err(),
                "attack payload must be rejected: {attack}"
            );
        }

        // Replaying an attacker-modified copy of the legitimate JSON must fail as well.
        let mut tampered: serde_json::Value = serde_json::from_str(&legitimate_json).unwrap();
        tampered["payload_claims"] = serde_json::json!({ "admin": true });
        assert!(serde_json::from_value::<TrustedToken>(tampered).is_err());
    }
}
