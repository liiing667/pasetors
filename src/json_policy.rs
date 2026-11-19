#![cfg_attr(docsrs, doc(cfg(feature = "std")))]

use crate::errors::Error;

/// A unified, parser-independent resource budget for untrusted JSON.
///
/// Every limit is enforced on the raw input bytes *before* any JSON value is
/// constructed, so an input that exceeds one of the budgets can never reach the
/// recursive `serde_json` parser nor cause a `HashMap` to be populated. The
/// checks are a single linear scan over the input with a fixed-size depth
/// counter, which means their cost is always proportional to
/// [`JsonPolicy::max_len`] and never to the structure of the payload.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct JsonPolicy {
    /// Maximum length, in bytes, of the JSON-encoded input.
    max_len: usize,
    /// Maximum number of object members (keys) at any depth.
    max_members: usize,
    /// Value that the nesting depth is not allowed to reach.
    max_depth: usize,
}

impl JsonPolicy {
    /// The default budget shared by both [`crate::claims::Claims`] and
    /// [`crate::footer::Footer`].
    ///
    /// See the [PASETO implementation guide] for the rationale behind the
    /// limits.
    ///
    /// [PASETO implementation guide]: https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#enforcing-maximum-depth-without-parsing-the-json-string
    pub(crate) const fn new(max_len: usize, max_members: usize, max_depth: usize) -> Self {
        Self {
            max_len,
            max_members,
            max_depth,
        }
    }

    /// Enforce the whole policy against raw JSON bytes before a parser is
    /// invoked.
    ///
    /// The byte-length limit is checked first so the structural scan below is
    /// always bounded by it. The structural scan counts object members and
    /// nesting depth in a single pass while honoring JSON string escaping, so
    /// payloads that hide braces or `":` sequences inside string values cannot
    /// inflate the counters nor evade the limits. The scan stops at the first
    /// budget that is reached.
    pub(crate) fn enforce(&self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > self.max_len {
            return Err(Error::LimitExceeded);
        }

        scan(bytes, &mut |members, depth| {
            if members > self.max_members || depth >= self.max_depth {
                Err(Error::LimitExceeded)
            } else {
                Ok(())
            }
        })
    }
}

/// Single-pass structural scan over raw JSON bytes.
///
/// The callback is invoked whenever an object member is counted or the nesting
/// depth increases, carrying the running totals. Only JSON string syntax
/// (quotes and escape sequences) is interpreted; full syntactic validation is
/// left to `serde_json`, which runs only after the policy accepted the input.
/// The depth counter saturates on mismatched closing brackets so malformed
/// input stays memory-safe regardless of structure.
fn scan<F>(input: &[u8], mut on_progress: F) -> Result<(), Error>
where
    F: FnMut(usize, usize) -> Result<(), Error>,
{
    let mut members = 0usize;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut index = 0usize;

    while index < input.len() {
        let byte = input[index];

        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
                if is_key(input, index) {
                    members += 1;
                    on_progress(members, depth)?;
                }
            }
            index += 1;
            continue;
        }

        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                on_progress(members, depth)?;
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }

    Ok(())
}

/// Return whether the string ending at `closing_quote` is an object key, i.e.
/// the first non-whitespace byte after it is a colon.
fn is_key(input: &[u8], closing_quote: usize) -> bool {
    input
        .iter()
        .skip(closing_quote + 1)
        .copied()
        .find(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        == Some(b':')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only totals collected by driving the shared scanning core without
    /// any budget attached.
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    struct Counters {
        members: usize,
        max_depth: usize,
    }

    fn scan_counters(input: &[u8]) -> Counters {
        let mut counters = Counters::default();
        scan(input, &mut |members, depth| {
            counters.members = members;
            counters.max_depth = counters.max_depth.max(depth);
            Ok(())
        })
        .unwrap();
        counters
    }

    const POLICY: JsonPolicy = JsonPolicy::new(
        crate::footer::Footer::DEFAULT_MAX_LEN,
        crate::footer::Footer::DEFAULT_MAX_KEYS,
        crate::footer::Footer::MAX_RECURSION_DEPTH,
    );

    #[test]
    fn counts_members_at_every_depth() {
        assert_eq!(
            scan_counters(br#"{"a":1,"b":{"c":2},"d":[1,2]}"#),
            Counters {
                members: 4,
                max_depth: 2
            }
        );
    }

    #[test]
    fn ignores_structure_hidden_in_strings() {
        assert_eq!(
            scan_counters(
                br#"{"a":"{\"x\":1,\"y\":2}","b":"[\"nested\"]","c":"escaped quote \": still a value"}"#
            ),
            Counters {
                members: 3,
                max_depth: 1
            }
        );
    }

    #[test]
    fn tracks_depth_for_objects_and_arrays() {
        assert_eq!(
            scan_counters(br#"{"a":[[{}]]}"#),
            Counters {
                members: 1,
                max_depth: 4
            }
        );
    }

    #[test]
    fn depth_counter_saturates_on_malformed_input() {
        assert_eq!(
            scan_counters(br#"{"a":1}}}"#),
            Counters {
                members: 1,
                max_depth: 1
            }
        );
    }

    #[test]
    fn policy_accepts_inputs_within_budget() {
        assert!(POLICY.enforce(br#"{"a":1}"#).is_ok());
        assert!(POLICY.enforce(br#"[]"#).is_ok());
    }

    #[test]
    fn policy_rejects_oversized_input_before_scanning() {
        let policy = JsonPolicy::new(4, usize::MAX, usize::MAX);
        assert_eq!(policy.enforce(br#"{"a":1}"#), Err(Error::LimitExceeded));
    }

    #[test]
    fn policy_rejects_too_many_members() {
        let policy = JsonPolicy::new(usize::MAX, 2, usize::MAX);
        assert_eq!(
            policy.enforce(br#"{"a":1,"b":2,"c":3}"#),
            Err(Error::LimitExceeded)
        );
    }

    #[test]
    fn policy_rejects_too_deep_input() {
        let policy = JsonPolicy::new(usize::MAX, usize::MAX, 3);
        assert_eq!(
            policy.enforce(br#"{"a":[[{}]]}"#),
            Err(Error::LimitExceeded)
        );
        assert!(policy.enforce(br#"{"a":{"b":1}}"#).is_ok());
    }

    #[test]
    fn member_count_cannot_be_inflated_by_embedded_json_strings() {
        // The embedded `":` pairs are string content, not object members.
        let embedded = r#"{"payload":"{\"k1\":1,\"k2\":2,\"k3\":3}"}"#;
        let policy = JsonPolicy::new(usize::MAX, 1, usize::MAX);
        assert!(policy.enforce(embedded.as_bytes()).is_ok());

        let two_real_members = r#"{"payload":"x","other":"y"}"#;
        assert_eq!(
            policy.enforce(two_real_members.as_bytes()),
            Err(Error::LimitExceeded)
        );
    }

    #[test]
    fn scan_stops_at_first_exceeded_budget() {
        // Depth limit is hit long before the rest of the document is reached.
        let policy = JsonPolicy::new(usize::MAX, usize::MAX, 2);
        let input = br#"{"a":[{"b":1},{"c":2}]}"#;
        assert_eq!(policy.enforce(input), Err(Error::LimitExceeded));
    }
}
