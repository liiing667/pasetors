#![cfg_attr(docsrs, doc(cfg(feature = "std")))]

//! Strict JSON parsing for token payloads (claims) and footers.
//!
//! PASETO payloads and footers are JSON objects that routinely cross trust and
//! language boundaries. JSON implementations disagree on how to resolve
//! duplicate object members ("first wins" vs. "last wins"), so a payload that
//! verifies cryptographically can still identify two different identities to
//! two different services. To prevent such ambiguity from becoming a trusted
//! result, parsing here enforces _single-value member semantics_: any object
//! member name may appear at most once, at any nesting level. Nesting depth
//! and the total number of object members are bounded as well, and each
//! violation is reported with distinct evidence via [`StrictJsonError`].

use crate::errors::Error;
use serde::Deserialize;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::fmt;

/// Error message raised inside the `serde` visitor on a duplicate member.
/// Matched against the `serde_json` error message after parsing.
const DUPLICATE_MEMBER_MSG: &str = "duplicate object member (single-value member semantics)";

/// Prefix of the error `serde_json` produces when its recursion limit is hit.
const RECURSION_LIMIT_MSG: &str = "recursion limit exceeded";

/// Reason a JSON document was rejected by the strict parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StrictJsonError {
    /// The document is not valid JSON or the top-level value is not an object.
    Invalid,
    /// An object contained the same member name more than once.
    DuplicateMember,
    /// The document is nested deeper than the maximum allowed depth.
    DepthExceeded,
    /// The document contains more object members than the maximum allowed.
    TooManyMembers,
}

impl StrictJsonError {
    /// Map to the public [`Error`], using `invalid` as evidence for malformed JSON.
    pub(crate) fn into_error(self, invalid: Error) -> Error {
        match self {
            StrictJsonError::Invalid => invalid,
            StrictJsonError::DuplicateMember => Error::JsonDuplicateMember,
            StrictJsonError::DepthExceeded => Error::JsonDepthExceeded,
            StrictJsonError::TooManyMembers => Error::JsonTooManyMembers,
        }
    }
}

/// Parse `string` as a JSON object with single-value member semantics.
///
/// - A member name appearing more than once in the same object (at any nesting
///   level) is rejected with [`StrictJsonError::DuplicateMember`].
/// - Nesting beyond `max_depth` levels is rejected with
///   [`StrictJsonError::DepthExceeded`].
/// - More than `max_members` object members in total (counted over the whole
///   document) is rejected with [`StrictJsonError::TooManyMembers`].
pub(crate) fn parse_object(
    string: &str,
    max_depth: usize,
    max_members: usize,
) -> Result<HashMap<String, Value>, StrictJsonError> {
    let StrictValue(value) = serde_json::from_str::<StrictValue>(string).map_err(classify_error)?;

    let mut members = 0usize;
    check_limits(&value, 1, max_depth, &mut members, max_members)?;

    match value {
        Value::Object(map) => Ok(map.into_iter().collect()),
        _ => Err(StrictJsonError::Invalid),
    }
}

/// Classify a `serde_json` failure into strict-parser evidence.
fn classify_error(error: serde_json::Error) -> StrictJsonError {
    let msg = error.to_string();
    if msg.starts_with(DUPLICATE_MEMBER_MSG) {
        StrictJsonError::DuplicateMember
    } else if msg.starts_with(RECURSION_LIMIT_MSG) {
        StrictJsonError::DepthExceeded
    } else {
        StrictJsonError::Invalid
    }
}

/// Enforce depth and member-count limits on an already-parsed value.
fn check_limits(
    value: &Value,
    depth: usize,
    max_depth: usize,
    members: &mut usize,
    max_members: usize,
) -> Result<(), StrictJsonError> {
    if depth > max_depth {
        return Err(StrictJsonError::DepthExceeded);
    }

    match value {
        Value::Array(items) => {
            for item in items {
                check_limits(item, depth + 1, max_depth, members, max_members)?;
            }
        }
        Value::Object(map) => {
            *members += map.len();
            if *members > max_members {
                return Err(StrictJsonError::TooManyMembers);
            }
            for item in map.values() {
                check_limits(item, depth + 1, max_depth, members, max_members)?;
            }
        }
        _ => {}
    }

    Ok(())
}

/// A JSON value deserialized with single-value member semantics.
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor).map(StrictValue)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any valid JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
        Ok(serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StrictValue::deserialize(deserializer).map(|strict| strict.0)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut items = Vec::new();
        while let Some(StrictValue(item)) = seq.next_element::<StrictValue>()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A>(self, mut access: A) -> Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut map = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if map.contains_key(&key) {
                return Err(de::Error::custom(DUPLICATE_MEMBER_MSG));
            }
            let StrictValue(value) = access.next_value::<StrictValue>()?;
            map.insert(key, value);
        }
        Ok(Value::Object(map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_member_top_level() {
        let json = r#"{"aud":"audit-log","aud":"attacker"}"#;
        assert_eq!(
            parse_object(json, 128, 512).unwrap_err(),
            StrictJsonError::DuplicateMember
        );
    }

    #[test]
    fn duplicate_member_nested() {
        let json = r#"{"outer":{"sub":"alice","sub":"mallory"}}"#;
        assert_eq!(
            parse_object(json, 128, 512).unwrap_err(),
            StrictJsonError::DuplicateMember
        );
    }

    #[test]
    fn duplicate_member_escaped_key() {
        // `a` and its escaped form are the same member name once decoded.
        let json = "{\"a\":1,\"\\u0061\":2}";
        assert_eq!(
            parse_object(json, 128, 512).unwrap_err(),
            StrictJsonError::DuplicateMember
        );
    }

    #[test]
    fn duplicate_member_in_array_element() {
        let json = r#"{"list":[{"k":1,"k":2}]}"#;
        assert_eq!(
            parse_object(json, 128, 512).unwrap_err(),
            StrictJsonError::DuplicateMember
        );
    }

    #[test]
    fn same_name_in_different_objects_is_fine() {
        let json = r#"{"a":{"k":1},"b":{"k":2}}"#;
        assert!(parse_object(json, 128, 512).is_ok());
    }

    #[test]
    fn depth_limit() {
        let json = format!("{}{}{}", "{\"a\":".repeat(200), "1", "}".repeat(200));
        assert_eq!(
            parse_object(&json, 128, 512).unwrap_err(),
            StrictJsonError::DepthExceeded
        );

        let json = format!("{}{}{}", "{\"a\":".repeat(64), "1", "}".repeat(64));
        assert!(parse_object(&json, 128, 512).is_ok());
    }

    #[test]
    fn member_count_limit() {
        let json = format!(
            "{{{}}}",
            (0..3)
                .map(|n| format!("\"k{n}\":{n}"))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(
            parse_object(&json, 128, 2).unwrap_err(),
            StrictJsonError::TooManyMembers
        );
        assert!(parse_object(&json, 128, 3).is_ok());
    }

    #[test]
    fn member_count_includes_nested() {
        let json = r#"{"a":{"b":1,"c":2}}"#;
        assert_eq!(
            parse_object(json, 128, 2).unwrap_err(),
            StrictJsonError::TooManyMembers
        );
    }

    #[test]
    fn top_level_must_be_object() {
        assert_eq!(
            parse_object("[1,2,3]", 128, 512).unwrap_err(),
            StrictJsonError::Invalid
        );
        assert_eq!(
            parse_object("\"string\"", 128, 512).unwrap_err(),
            StrictJsonError::Invalid
        );
    }

    #[test]
    fn invalid_json() {
        assert_eq!(
            parse_object("{not json", 128, 512).unwrap_err(),
            StrictJsonError::Invalid
        );
    }

    #[test]
    fn multilingual_round_trip() {
        let json = r#"{"issuer":"例え.example","name":"Jürgen ☃","emoji":"🦀","arabic":"مرحبا","nested":{"中文":"值"},"num":42,"float":1.5,"bool":true,"null":null,"arr":["a",1,false]}"#;
        let parsed = parse_object(json, 128, 512).unwrap();
        assert_eq!(parsed["issuer"], Value::String("例え.example".into()));
        assert_eq!(parsed["name"], Value::String("Jürgen ☃".into()));
        assert_eq!(parsed["emoji"], Value::String("🦀".into()));
        assert_eq!(parsed["arabic"], Value::String("مرحبا".into()));
        assert_eq!(parsed["nested"]["中文"], Value::String("值".into()));
        assert_eq!(parsed["num"], Value::from(42));
        assert_eq!(parsed["float"], Value::from(1.5));
        assert_eq!(parsed["bool"], Value::Bool(true));
        assert_eq!(parsed["null"], Value::Null);
        assert_eq!(
            parsed["arr"],
            Value::Array(vec![
                Value::String("a".into()),
                Value::from(1),
                Value::Bool(false)
            ])
        );
    }
}
