//! Shared serde helpers for wire-format compatibility across SDKs.

/// Deserialize a `u128` from either a JSON number or a JSON string;
/// serialize as a JSON number. The string form is required by JavaScript
/// clients (JS numbers are f64 and lose precision above 2^53).
///
/// Bincode-safe: dispatches on `is_human_readable()` so structs that
/// round-trip through `bincode` keep working — the JSON-only `RawValue`
/// path is only entered for human-readable formats.
pub mod u128_flexible {
    use serde::de::Error as DeError;
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_json::value::RawValue;
    use std::str::FromStr;

    pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
        // Preserve the canonical Rust wire shape (number, not string).
        serializer.serialize_u128(*value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
        if !deserializer.is_human_readable() {
            // Binary format (bincode, postcard, …): nothing to disambiguate,
            // and `RawValue` is JSON-only. Fall back to the native u128
            // deserialization the format already supports.
            return u128::deserialize(deserializer);
        }

        // `RawValue` gives the original JSON bytes without going through
        // `serde_json::Number` (which f64-routes large integers without
        // `arbitrary_precision`). We dispatch on string-vs-number ourselves.
        let raw: &RawValue = <&RawValue>::deserialize(deserializer)?;
        let s = raw.get().trim();

        if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
            // JSON string — strip quotes and parse decimal digits.
            // Use serde_json to unescape in case the sender included
            // escapes (unlikely for a decimal, but cheap insurance).
            let inner: String = serde_json::from_str(s).map_err(|e| {
                D::Error::custom(format!("invalid u128 JSON string {:?}: {}", s, e))
            })?;
            u128::from_str(inner.trim()).map_err(|e| {
                D::Error::custom(format!("invalid u128 decimal string {:?}: {}", inner, e))
            })
        } else {
            // JSON number — parse the raw digits directly.
            u128::from_str(s)
                .map_err(|e| D::Error::custom(format!("invalid u128 JSON number {:?}: {}", s, e)))
        }
    }
}

/// Serialize `Vec<u8>` as base64 (URL-safe, no padding) for compact JSON.
///
/// `serde_json`'s default representation of `Vec<u8>` is a JSON array of
/// numbers — fine for short fields like a 32-byte hash but catastrophic for
/// multi-kilobyte binary blobs (a GKR proof or a GroveDB proof). This helper
/// encodes as base64 instead, keeping JSON payloads compact without giving up
/// on JSON as the transport.
pub mod bytes_base64 {
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use base64::Engine;
    use serde::de::Error as DeError;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = STANDARD_NO_PAD.encode(value);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        STANDARD_NO_PAD
            .decode(s.as_bytes())
            .map_err(|e| D::Error::custom(format!("invalid base64: {}", e)))
    }
}

/// `Option<Vec<u8>>` companion for [`bytes_base64`]. `None` serializes
/// as JSON `null`; `Some(_)` serializes as the base64 string the
/// unwrapped helper produces.
pub mod option_bytes_base64 {
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use base64::Engine;
    use serde::de::Error as DeError;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        value: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => serializer.serialize_str(&STANDARD_NO_PAD.encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        opt.map(|s| {
            STANDARD_NO_PAD
                .decode(s.as_bytes())
                .map_err(|e| D::Error::custom(format!("invalid base64: {}", e)))
        })
        .transpose()
    }
}

/// Same as [`u128_flexible`] but for `Option<u128>` fields.
///
/// Explicit `null` (or an absent field paired with `#[serde(default)]`)
/// deserializes as `None`; anything else defers to `u128_flexible`.
pub mod option_u128_flexible {
    use serde::de::Error as DeError;
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_json::value::RawValue;

    pub fn serialize<S: Serializer>(
        value: &Option<u128>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            // `serialize_some` emits the Option discriminator before the
            // inner value on binary formats (bincode writes a 1-byte tag),
            // and is a no-op wrapper on JSON (writes the bare number).
            // Calling `u128_flexible::serialize(v, serializer)` directly
            // would skip the discriminator and corrupt the binary wire form.
            Some(v) => serializer.serialize_some(v),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u128>, D::Error> {
        if !deserializer.is_human_readable() {
            // Binary format: native Option<u128>. `RawValue` is JSON-only.
            return Option::<u128>::deserialize(deserializer);
        }

        // Peek at the raw JSON to distinguish `null` from a number or
        // string without reifying it into `serde_json::Value` (which,
        // absent `arbitrary_precision`, would lose precision on any
        // u128 > 2^53).
        let raw: &RawValue = <&RawValue>::deserialize(deserializer)?;
        let s = raw.get().trim();
        if s == "null" {
            return Ok(None);
        }
        // Delegate to u128_flexible by re-deserializing the raw bytes
        // via a fresh serde_json deserializer. This keeps both paths
        // (string / number) in exactly one place.
        let v: u128 = serde_json::from_str::<U128Flex>(s)
            .map_err(|e| D::Error::custom(format!("invalid u128: {}", e)))?
            .0;
        Ok(Some(v))
    }

    // Newtype so we can attach the field-level serde attribute and
    // route deserialization through `u128_flexible`.
    #[derive(serde::Deserialize)]
    struct U128Flex(#[serde(with = "super::u128_flexible")] u128);
}

#[cfg(test)]
mod tests {
    use super::{option_u128_flexible, u128_flexible};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Wrap {
        #[serde(with = "u128_flexible")]
        v: u128,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct OptWrap {
        #[serde(default, with = "option_u128_flexible")]
        v: Option<u128>,
    }

    #[test]
    fn option_accepts_null() {
        let got: OptWrap = serde_json::from_str(r#"{"v": null}"#).unwrap();
        assert_eq!(got.v, None);
    }

    #[test]
    fn option_accepts_number() {
        let got: OptWrap = serde_json::from_str(r#"{"v": 100000000000000000000000}"#).unwrap();
        assert_eq!(got.v, Some(100_000_000_000_000_000_000_000));
    }

    #[test]
    fn option_accepts_string() {
        let got: OptWrap = serde_json::from_str(r#"{"v": "100000000000000000000000"}"#).unwrap();
        assert_eq!(got.v, Some(100_000_000_000_000_000_000_000));
    }

    #[test]
    fn option_accepts_missing_field_as_none() {
        let got: OptWrap = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(got.v, None);
    }

    #[test]
    fn option_serializes_none_as_null() {
        let json = serde_json::to_string(&OptWrap { v: None }).unwrap();
        assert_eq!(json, r#"{"v":null}"#);
    }

    #[test]
    fn option_serializes_some_as_number() {
        let json = serde_json::to_string(&OptWrap {
            v: Some(100_000_000_000_000_000_000_000),
        })
        .unwrap();
        assert_eq!(json, r#"{"v":100000000000000000000000}"#);
    }

    #[test]
    fn accepts_json_number() {
        let got: Wrap = serde_json::from_str(r#"{"v": 100000000000000000000000}"#).unwrap();
        assert_eq!(got.v, 100_000_000_000_000_000_000_000);
    }

    #[test]
    fn accepts_json_string() {
        let got: Wrap = serde_json::from_str(r#"{"v": "100000000000000000000000"}"#).unwrap();
        assert_eq!(got.v, 100_000_000_000_000_000_000_000);
    }

    #[test]
    fn serializes_as_number() {
        let wrap = Wrap {
            v: 100_000_000_000_000_000_000_000,
        };
        let json = serde_json::to_string(&wrap).unwrap();
        // Number, not quoted — preserves the existing Rust wire shape.
        assert_eq!(json, r#"{"v":100000000000000000000000}"#);
    }

    #[test]
    fn rejects_negative() {
        let err =
            serde_json::from_str::<Wrap>(r#"{"v": -1}"#).expect_err("negative must not parse");
        let msg = err.to_string();
        // `u128::from_str("-1")` fails with "invalid digit found in string";
        // we don't require the word "negative" — just that the parse rejects it.
        assert!(
            msg.contains("invalid u128") || msg.contains("negative"),
            "got: {}",
            msg
        );
    }

    #[test]
    fn rejects_garbage_string() {
        let err =
            serde_json::from_str::<Wrap>(r#"{"v": "abc"}"#).expect_err("non-numeric must fail");
        assert!(err.to_string().contains("invalid u128 decimal string"));
    }

    /// A JSON integer too large to fit in an f64 losslessly (10^23) must
    /// parse to the exact u128 value, not the f64-rounded one.
    #[test]
    fn preserves_precision_for_large_json_numbers() {
        let got: Wrap = serde_json::from_str(r#"{"v": 100000000000000000000000}"#).unwrap();
        assert_eq!(got.v, 100_000_000_000_000_000_000_000);
    }

    /// Binary formats must round-trip through `u128_flexible` without
    /// hitting the JSON-only `RawValue` path.
    #[test]
    fn bincode_round_trip() {
        let wrap = Wrap {
            v: 100_000_000_000_000_000_000_000,
        };
        let bytes = bincode::serialize(&wrap).expect("bincode serialize");
        let got: Wrap = bincode::deserialize(&bytes).expect("bincode deserialize");
        assert_eq!(got, wrap);
    }

    #[test]
    fn option_bincode_round_trip() {
        for v in [None, Some(0u128), Some(100_000_000_000_000_000_000_000u128)] {
            let wrap = OptWrap { v };
            let bytes = bincode::serialize(&wrap).expect("bincode serialize");
            let got: OptWrap = bincode::deserialize(&bytes).expect("bincode deserialize");
            assert_eq!(got, wrap);
        }
    }
}
