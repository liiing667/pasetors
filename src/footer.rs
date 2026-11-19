#![cfg_attr(docsrs, doc(cfg(feature = "std")))]

use crate::errors::Error;
use crate::json_policy::JsonPolicy;
#[cfg(feature = "paserk")]
use crate::paserk::{FormatAsPaserk, Id};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq, Clone)]
/// A footer with optional claims that are JSON-encoded.
pub struct Footer {
    list_of: HashMap<String, Value>,
    max_keys: usize,
    max_len: usize,
    max_depth: usize,
}

impl Default for Footer {
    fn default() -> Self {
        Self::new()
    }
}

impl Footer {
    /// Keys for registered claims in the footer, that are reserved for usage by PASETO in top-level.
    pub const REGISTERED_CLAIMS: [&'static str; 2] = ["kid", "wpk"];

    /// All PASERK types that are (implemented in this library) unsafe in the footer.
    pub const DISALLOWED_FOOTER: [&'static str; 8] = [
        "k2.local.",
        "k4.local.",
        "k2.secret.",
        "k3.secret.",
        "k4.secret.",
        "k2.public.",
        "k3.public.",
        "k4.public.",
    ];

    /// See [PASETO docs] for the reason behind this limit.
    ///
    /// Maximum number of named keys within an object.
    ///
    /// [PASETO docs]: https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#enforcing-maximum-depth-without-parsing-the-json-string
    pub const DEFAULT_MAX_KEYS: usize = 512;

    /// See [PASETO docs] for the reason behind this limit.
    ///
    /// Maximum length of the JSON-encoded string.
    ///
    /// [PASETO docs]: https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#enforcing-maximum-depth-without-parsing-the-json-string
    pub const DEFAULT_MAX_LEN: usize = 8192;

    /// See [PASETO docs] for the reason behind this limit.
    ///
    /// This matches the recursion limit used internally by `serde_json`. It is
    /// used as the default depth budget and can be changed with
    /// [`Self::max_depth`].
    ///
    /// [PASETO docs]: https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#enforcing-maximum-depth-without-parsing-the-json-string
    pub const MAX_RECURSION_DEPTH: usize = 128;

    /// Create a new `Footer` instance.
    pub fn new() -> Self {
        Self {
            list_of: HashMap::new(),
            max_keys: Self::DEFAULT_MAX_KEYS,
            max_len: Self::DEFAULT_MAX_LEN,
            max_depth: Self::MAX_RECURSION_DEPTH,
        }
    }

    /// The unified pre-parse budget derived from the currently configured limits.
    fn policy(&self) -> JsonPolicy {
        JsonPolicy::new(self.max_len, self.max_keys, self.max_depth)
    }

    /// Change the default (512) amount of maximum number of named keys within an object.
    ///
    /// __NOTE__: There should be no need to change this if you don't know this is a specific problem for you.
    pub fn max_keys(&mut self, max_keys: usize) {
        self.max_keys = max_keys;
    }

    /// Change the default (8192) amount of maximum number of named keys within an object.
    ///
    /// __NOTE__: There should be no need to change this if you don't know this is a specific problem for you.
    pub fn max_len(&mut self, max_len: usize) {
        self.max_len = max_len;
    }

    /// Change the default (128) maximum nesting depth of JSON maps and arrays.
    ///
    /// The depth is measured on the raw input before parsing, so inputs exceeding
    /// it are rejected before any JSON value is constructed.
    ///
    /// __NOTE__: There should be no need to change this if you don't know this is a specific problem for you.
    pub fn max_depth(&mut self, max_depth: usize) {
        self.max_depth = max_depth;
    }

    /// Add additional claims. If `claim` already exists, it is replaced with the new.
    ///
    /// Errors:
    /// - `claim` is a reserved claim (see [`Self::REGISTERED_CLAIMS`])
    /// - `value` is any of (starts with) the disallowed PASERK types (see [`Self::DISALLOWED_FOOTER`]).
    pub fn add_additional(&mut self, claim: &str, value: &str) -> Result<(), Error> {
        for unsafe_value in Self::DISALLOWED_FOOTER {
            if value.starts_with(unsafe_value) {
                return Err(Error::InvalidClaim);
            }
        }

        if !Self::REGISTERED_CLAIMS.contains(&claim) {
            self.list_of.insert(claim.into(), value.into());
            Ok(())
        } else {
            Err(Error::InvalidClaim)
        }
    }

    /// Checks whether a specific claim has been added to the list.
    ///
    /// E.g `contains_claim("kid") == true` if `kid` has been added before.
    pub fn contains_claim(&self, claim: &str) -> bool {
        self.list_of.contains_key(claim)
    }

    /// Return Some(claim value) if claims list contains the `claim`.
    /// None otherwise.
    pub fn get_claim(&self, claim: &str) -> Option<&Value> {
        self.list_of.get(claim)
    }

    #[cfg(feature = "paserk")]
    /// Set the `kid` claim. If it already exists, replace it with the new.
    pub fn key_id(&mut self, id: &Id) {
        let mut paserk_kid = String::new();
        id.fmt(&mut paserk_kid).unwrap();

        self.list_of.insert("kid".into(), paserk_kid.into());
    }

    /// Attempt to create `Footer` from a sequence of bytes.
    ///
    /// Errors:
    /// - `bytes` contains non-UTF-8 sequences
    /// - `bytes` does not decode as valid JSON
    /// - `bytes` top-most JSON object does not decode to a map
    /// - if any registered claims exist and they are not a `String`
    /// - a pre-parse resource limit is exceeded ([`Error::LimitExceeded`]):
    ///   JSON-encoded length, number of named keys or nesting depth (128 by default)
    pub fn parse_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        // All resource limits are enforced on the raw bytes first, so the
        // length, member and depth budgets are applied before UTF-8 decoding
        // and before any JSON parsing takes place.
        self.policy().enforce(bytes)?;

        let input = String::from_utf8(bytes.to_vec()).map_err(|_| Error::FooterParsing)?;
        self.list_of = serde_json::from_str(&input).map_err(|_| Error::FooterParsing)?;

        Ok(())
    }

    /// Attempt to parse a `Footer` from a string.
    ///
    /// Errors:
    /// - `string` does not decode as valid JSON
    /// - `string` top-most JSON object does not decode to a map
    /// - if any registered claims exist and they are not a `String`
    /// - a pre-parse resource limit is exceeded ([`Error::LimitExceeded`]):
    ///   JSON-encoded length, number of named keys or nesting depth (128 by default)
    pub fn parse_string(&mut self, string: &str) -> Result<(), Error> {
        self.policy().enforce(string.as_bytes())?;

        self.list_of = serde_json::from_str(string).map_err(|_| Error::FooterParsing)?;

        Ok(())
    }

    /// Return the JSON serialized representation of `Self`.
    ///
    /// Errors:
    /// - `self` cannot be serialized as JSON
    pub fn to_string(&self) -> Result<String, Error> {
        match serde_json::to_string(&self.list_of) {
            Ok(ret) => Ok(ret),
            Err(_) => Err(Error::FooterParsing),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::footer::Footer;

    #[test]
    fn err_on_max_keys() {
        let mut footer = Footer::default();
        for n in 1..=11 {
            footer
                .add_additional(format!("{n}").as_str(), "test")
                .unwrap();
        }

        let mut footer_parse = Footer::default();
        footer_parse.max_keys(10);
        assert!(
            footer_parse
                .parse_bytes(footer.to_string().unwrap().as_bytes())
                .is_err()
        );
    }

    #[test]
    fn err_on_max_len() {
        let mut footer = Footer::new();
        for n in 1..=11 {
            footer
                .add_additional(format!("{n}").as_str(), "test")
                .unwrap();
        }
        let ser_footer = footer.to_string().unwrap();

        let mut footer_parse = Footer::new();
        footer_parse.max_len(ser_footer.len() - 1);
        assert!(footer_parse.parse_bytes(ser_footer.as_bytes()).is_err());
    }

    #[test]
    fn err_on_custom_with_registered() {
        let mut footer = Footer::new();

        assert!(footer.add_additional("wpk", "test").is_err());
        assert!(footer.add_additional("kid", "test").is_err());
        assert!(footer.add_additional("custom", "test").is_ok());
    }

    #[test]
    #[cfg(all(feature = "paserk", feature = "v2", feature = "v3", feature = "v4"))]
    fn err_on_disallowed_in_footer() {
        use crate::keys::{AsymmetricKeyPair, Generate, SymmetricKey};
        use crate::paserk::FormatAsPaserk;
        use crate::version2::V2;
        use crate::version3::V3;
        use crate::version4::V4;

        let mut footer = Footer::new();

        let kpv2 = AsymmetricKeyPair::<V2>::generate().unwrap();
        let kpv3 = AsymmetricKeyPair::<V3>::generate().unwrap();
        let kpv4 = AsymmetricKeyPair::<V4>::generate().unwrap();
        let skv2 = SymmetricKey::<V2>::generate().unwrap();
        let skv4 = SymmetricKey::<V4>::generate().unwrap();

        let mut buf = String::new();
        kpv2.secret.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("wpk", &buf).is_err());
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_err());

        let mut buf = String::new();
        kpv2.public.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("wpk", &buf).is_err());
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_err());

        let mut buf = String::new();
        kpv3.secret.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("wpk", &buf).is_err());
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_err());

        let mut buf = String::new();
        kpv3.public.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("wpk", &buf).is_err());
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_err());

        let mut buf = String::new();
        kpv4.secret.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("wpk", &buf).is_err());
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_err());

        let mut buf = String::new();
        kpv4.public.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("wpk", &buf).is_err());
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_err());

        let mut buf = String::new();
        skv2.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("wpk", &buf).is_err());
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_err());

        let mut buf = String::new();
        skv4.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("wpk", &buf).is_err());
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_err());
    }

    #[test]
    #[cfg(all(feature = "paserk", feature = "v2", feature = "v3", feature = "v4"))]
    fn kid_in_footer() {
        use crate::keys::{AsymmetricKeyPair, Generate, SymmetricKey};
        use crate::paserk::{FormatAsPaserk, Id};
        use crate::version2::V2;
        use crate::version3::V3;
        use crate::version4::V4;

        let mut footer = Footer::new();

        let kpv2 = AsymmetricKeyPair::<V2>::generate().unwrap();
        let kpv3 = AsymmetricKeyPair::<V3>::generate().unwrap();
        let kpv4 = AsymmetricKeyPair::<V4>::generate().unwrap();
        let skv2 = SymmetricKey::<V2>::generate().unwrap();
        let skv4 = SymmetricKey::<V4>::generate().unwrap();

        let mut buf = String::new();
        let paserk_id = Id::from(&kpv2.secret);
        paserk_id.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_ok());
        footer.key_id(&paserk_id);
        assert!(footer.contains_claim("kid"));
        assert_eq!(footer.get_claim("kid").unwrap().as_str().unwrap(), buf);

        let mut buf = String::new();
        let paserk_id = Id::from(&kpv2.public);
        paserk_id.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_ok());
        footer.key_id(&paserk_id);
        assert!(footer.contains_claim("kid"));
        assert_eq!(footer.get_claim("kid").unwrap().as_str().unwrap(), buf);

        let mut buf = String::new();
        let paserk_id = Id::from(&kpv3.secret);
        paserk_id.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_ok());
        footer.key_id(&paserk_id);
        assert!(footer.contains_claim("kid"));
        assert_eq!(footer.get_claim("kid").unwrap().as_str().unwrap(), buf);

        let mut buf = String::new();
        let paserk_id = Id::from(&kpv3.public);
        paserk_id.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_ok());
        footer.key_id(&paserk_id);
        assert!(footer.contains_claim("kid"));
        assert_eq!(footer.get_claim("kid").unwrap().as_str().unwrap(), buf);

        let mut buf = String::new();
        let paserk_id = Id::from(&kpv4.secret);
        paserk_id.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_ok());
        footer.key_id(&paserk_id);
        assert!(footer.contains_claim("kid"));
        assert_eq!(footer.get_claim("kid").unwrap().as_str().unwrap(), buf);

        let mut buf = String::new();
        let paserk_id = Id::from(&kpv4.public);
        paserk_id.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_ok());
        footer.key_id(&paserk_id);
        assert!(footer.contains_claim("kid"));
        assert_eq!(footer.get_claim("kid").unwrap().as_str().unwrap(), buf);

        let mut buf = String::new();
        let paserk_id = Id::from(&skv2);
        paserk_id.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_ok());
        footer.key_id(&paserk_id);
        assert!(footer.contains_claim("kid"));
        assert_eq!(footer.get_claim("kid").unwrap().as_str().unwrap(), buf);

        let mut buf = String::new();
        let paserk_id = Id::from(&skv4);
        paserk_id.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_ok());
        footer.key_id(&paserk_id);
        assert!(footer.contains_claim("kid"));
        assert_eq!(footer.get_claim("kid").unwrap().as_str().unwrap(), buf);
    }

    #[test]
    fn err_on_max_depth() {
        let mut footer = Footer::new();
        footer.max_depth(3);

        // Four nested containers exceed the configured depth of three.
        let too_deep = r#"{"a":[{"b":1}]}"#;
        assert_eq!(
            footer.parse_bytes(too_deep.as_bytes()),
            Err(crate::errors::Error::LimitExceeded)
        );

        // Exactly at the limit still parses.
        let at_limit = r#"{"a":{"b":1}}"#;
        assert!(footer.parse_bytes(at_limit.as_bytes()).is_ok());
    }

    #[test]
    fn default_depth_budget_rejects_parser_stack_abuse() {
        // serde_json itself gives up at a depth of 128. The policy must reject
        // such input before the recursive parser is ever reached.
        let deeply_nested = format!("{}{}{}", "[".repeat(128), "1", "]".repeat(128));

        let mut footer = Footer::new();
        assert_eq!(
            footer.parse_bytes(deeply_nested.as_bytes()),
            Err(crate::errors::Error::LimitExceeded)
        );
    }

    #[test]
    fn embedded_json_strings_cannot_inflate_key_count() {
        // The escaped `":` sequences are string content. A regex scanning the
        // whole document would count them as keys; the policy must not.
        let embedded = r#"{"payload":"{\"k1\":1,\"k2\":2,\"k3\":3,\"k4\":4}"}"#;

        let mut strict_footer = Footer::new();
        strict_footer.max_keys(1);
        assert!(strict_footer.parse_bytes(embedded.as_bytes()).is_ok());
        assert!(strict_footer.contains_claim("payload"));

        // Two genuine top-level members still exceed a one-key budget.
        let two_real_keys = r#"{"payload":"x","other":"y"}"#;
        let mut strict_footer = Footer::new();
        strict_footer.max_keys(1);
        assert_eq!(
            strict_footer.parse_bytes(two_real_keys.as_bytes()),
            Err(crate::errors::Error::LimitExceeded)
        );
    }

    #[test]
    fn braces_hidden_in_strings_do_not_affect_depth() {
        let input = r#"{"a":"[[[[{{{","b":"still a value"}"#;

        let mut footer = Footer::new();
        footer.max_depth(2);
        assert!(footer.parse_bytes(input.as_bytes()).is_ok());
    }

    #[test]
    fn limit_violations_stop_before_object_construction() {
        let oversized = r#"{"a":"this is longer than the configured budget"}"#;
        let too_many = r#"{"a":1,"b":2,"c":3}"#;
        let too_deep = r#"{"a":[{"b":1}]}"#;

        let mut length_limited = Footer::new();
        length_limited.max_len(10);
        assert_eq!(
            length_limited.parse_bytes(oversized.as_bytes()),
            Err(crate::errors::Error::LimitExceeded)
        );

        let mut key_limited = Footer::new();
        key_limited.max_keys(2);
        assert_eq!(
            key_limited.parse_bytes(too_many.as_bytes()),
            Err(crate::errors::Error::LimitExceeded)
        );

        let mut depth_limited = Footer::new();
        depth_limited.max_depth(3);
        assert_eq!(
            depth_limited.parse_bytes(too_deep.as_bytes()),
            Err(crate::errors::Error::LimitExceeded)
        );

        // No untrusted member survives a rejected parse.
        for footer in [length_limited, key_limited, depth_limited] {
            assert!(!footer.contains_claim("a"));
            assert_eq!(footer.to_string().unwrap(), "{}");
        }
    }

    #[test]
    fn valid_footer_within_custom_budgets_round_trips() {
        let mut builder = Footer::new();
        builder.add_additional("custom", "value").unwrap();
        let serialized = builder.to_string().unwrap();

        let mut parser = Footer::new();
        parser.max_len(serialized.len());
        parser.max_keys(1);
        parser.max_depth(2);

        assert!(parser.parse_bytes(serialized.as_bytes()).is_ok());
        assert_eq!(parser.to_string().unwrap(), serialized);
        assert_eq!(parser.get_claim("custom").unwrap(), "value");
    }

    #[test]
    fn invalid_utf8_is_rejected_without_touching_the_parser() {
        // Length/depth/key checks run on raw bytes first; this input is within
        // every budget but is not valid UTF-8, so it must fail as a parsing
        // error rather than producing a footer.
        let mut footer = Footer::new();
        assert_eq!(
            footer.parse_bytes(&[b'{', 0xff, b'}']),
            Err(crate::errors::Error::FooterParsing)
        );
    }
}
