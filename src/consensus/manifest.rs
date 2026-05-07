use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use std::fmt;

use super::chains::SupportedChain;

/// Current manifest schema version. The consensus validator rejects any
/// `RegisterSubgrove` whose manifest declares a different version, so a
/// schema bump is a coordinated change: update this constant, expand the
/// validator to handle the new shape (or fork the type), and migrate
/// existing fixtures.
pub const MANIFEST_SPEC_VERSION: &str = "1.0.0";

/// Upper bounds on manifest size, chosen to keep on-chain storage bounded
/// and to limit the work the validator and indexer service have to do per
/// `RegisterSubgrove`.
pub const MAX_DATA_SOURCES: usize = 64;
pub const MAX_EVENTS_PER_SOURCE: usize = 32;
pub const MAX_NAME_LEN: usize = 64;
pub const MAX_ABI_LEN: usize = 64;
pub const MAX_DESCRIPTION_LEN: usize = 1024;

/// Canonical Willow manifest for `BlockchainIndexing` subgroves.
///
/// Stored on-chain as the JSON-serialized bytes of this type; consensus
/// rejects any `manifest_content` payload that does not deserialize into
/// this exact shape (with `deny_unknown_fields`) and pass `validate()`.
///
/// Designed to be the single source of truth across consumers: the Rust
/// SDK builds it, the consensus validator enforces it, and downstream
/// readers (light client, indexer service, explorer, every SDK) decode
/// the same bytes off-chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct WillowManifest {
    /// Schema version. Must equal `MANIFEST_SPEC_VERSION`.
    pub spec_version: String,
    /// Optional human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// One or more contract data sources to index.
    pub data_sources: Vec<DataSource>,
}

/// One indexed contract within a manifest. Each data source pins exactly
/// one chain, contract address, ABI, start block, and event set; manifests
/// that need to index multiple chains or multiple contracts have one
/// `DataSource` per (chain, contract) pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct DataSource {
    /// Human-readable label (e.g. "UniswapV3Pool"). Used for log lines and
    /// SDK ergonomics; not load-bearing for indexing.
    pub name: String,
    /// The chain this data source targets. Must be in `SupportedChain`.
    pub network: SupportedChain,
    /// Contract address on `network`.
    pub address: EvmAddress,
    /// ABI registry name. Resolved at indexing time against a known set of
    /// ABIs (e.g. "ERC20", "ERC4626"); the consensus validator only checks
    /// that the string is non-empty and bounded.
    pub abi: String,
    /// Block at which to start indexing this data source.
    pub start_block: u64,
    /// Solidity event signatures to subscribe to. Must be non-empty.
    pub events: Vec<EventSignature>,
}

/// A 20-byte EVM address, deserialized from the canonical `0x`-prefixed
/// 40-hex-character string form. Stored as raw bytes so the serialized
/// form is normalized (lowercase hex, exact length) on every round-trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvmAddress(pub [u8; 20]);

impl EvmAddress {
    pub fn parse(s: &str) -> Result<Self, String> {
        let stripped = s
            .strip_prefix("0x")
            .ok_or_else(|| format!("EVM address must start with 0x: {:?}", s))?;
        if stripped.len() != 40 {
            return Err(format!(
                "EVM address must be 0x + 40 hex chars (got {} hex chars)",
                stripped.len()
            ));
        }
        let mut bytes = [0u8; 20];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let hi = hex_nibble(stripped.as_bytes()[i * 2])?;
            let lo = hex_nibble(stripped.as_bytes()[i * 2 + 1])?;
            *byte = (hi << 4) | lo;
        }
        Ok(EvmAddress(bytes))
    }

    pub fn to_canonical_string(&self) -> String {
        let mut s = String::with_capacity(42);
        s.push_str("0x");
        for byte in &self.0 {
            s.push(nibble_hex(byte >> 4));
            s.push(nibble_hex(byte & 0x0f));
        }
        s
    }
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => Err(format!("invalid hex digit {:?}", other as char)),
    }
}

fn nibble_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => unreachable!("nibble out of range"),
    }
}

impl fmt::Display for EvmAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_canonical_string())
    }
}

impl Serialize for EvmAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_canonical_string())
    }
}

impl<'de> Deserialize<'de> for EvmAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AddrVisitor;
        impl Visitor<'_> for AddrVisitor {
            type Value = EvmAddress;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a 0x-prefixed 40-hex-character EVM address")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<EvmAddress, E> {
                EvmAddress::parse(v).map_err(de::Error::custom)
            }
        }
        deserializer.deserialize_str(AddrVisitor)
    }
}

/// A parsed Solidity event signature of the form `Name(type1,type2,...)`.
/// Whitespace inside the signature is rejected to keep the canonical form
/// stable across producers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventSignature {
    /// Full canonical signature (e.g. `Transfer(address,address,uint256)`).
    raw: String,
}

impl EventSignature {
    pub fn parse(s: &str) -> Result<Self, String> {
        if s.is_empty() {
            return Err("event signature must not be empty".into());
        }
        let open = s
            .find('(')
            .ok_or_else(|| format!("event signature missing '(': {:?}", s))?;
        if !s.ends_with(')') {
            return Err(format!("event signature missing trailing ')': {:?}", s));
        }
        let name = &s[..open];
        let params = &s[open + 1..s.len() - 1];

        if !is_solidity_identifier(name) {
            return Err(format!("event name {:?} is not a valid identifier", name));
        }

        if !params.is_empty() {
            for part in params.split(',') {
                if !is_solidity_param_type(part) {
                    return Err(format!("invalid parameter type {:?} in {:?}", part, s));
                }
            }
        }

        Ok(EventSignature { raw: s.to_string() })
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

fn is_solidity_identifier(s: &str) -> bool {
    let mut bytes = s.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn is_solidity_param_type(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'[' || b == b']')
}

impl fmt::Display for EventSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl Serialize for EventSignature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for EventSignature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SigVisitor;
        impl Visitor<'_> for SigVisitor {
            type Value = EventSignature;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a Solidity event signature, e.g. Transfer(address,address,uint256)")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<EventSignature, E> {
                EventSignature::parse(v).map_err(de::Error::custom)
            }
        }
        deserializer.deserialize_str(SigVisitor)
    }
}

impl WillowManifest {
    /// Decode and validate a manifest from on-chain bytes. Combines the
    /// strict-shape `serde_json` step (which rejects unknown fields,
    /// non-canonical chains, malformed addresses, and malformed event
    /// signatures) with the cross-field `validate()` step.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let manifest: WillowManifest =
            serde_json::from_slice(bytes).map_err(|e| format!("invalid manifest: {}", e))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Cross-field invariants enforced after deserialization. The strict
    /// serde shape catches structural problems (unknown fields, bad chain
    /// strings, malformed addresses); this catches range / cardinality /
    /// length problems that serde alone won't.
    pub fn validate(&self) -> Result<(), String> {
        if self.spec_version != MANIFEST_SPEC_VERSION {
            return Err(format!(
                "unsupported manifest spec_version {:?} (expected {:?})",
                self.spec_version, MANIFEST_SPEC_VERSION,
            ));
        }
        if let Some(desc) = &self.description {
            if desc.len() > MAX_DESCRIPTION_LEN {
                return Err(format!(
                    "manifest description length {} exceeds maximum {}",
                    desc.len(),
                    MAX_DESCRIPTION_LEN,
                ));
            }
        }
        if self.data_sources.is_empty() {
            return Err("manifest must declare at least one data source".into());
        }
        if self.data_sources.len() > MAX_DATA_SOURCES {
            return Err(format!(
                "manifest has {} data sources (maximum {})",
                self.data_sources.len(),
                MAX_DATA_SOURCES,
            ));
        }
        for (idx, ds) in self.data_sources.iter().enumerate() {
            ds.validate()
                .map_err(|e| format!("data_sources[{}]: {}", idx, e))?;
        }
        Ok(())
    }
}

impl DataSource {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("data source name must not be empty".into());
        }
        if self.name.len() > MAX_NAME_LEN {
            return Err(format!(
                "data source name length {} exceeds maximum {}",
                self.name.len(),
                MAX_NAME_LEN,
            ));
        }
        if !self
            .name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(format!(
                "data source name {:?} must be alphanumeric, '-', or '_'",
                self.name
            ));
        }
        if self.abi.is_empty() {
            return Err("data source abi must not be empty".into());
        }
        if self.abi.len() > MAX_ABI_LEN {
            return Err(format!(
                "data source abi length {} exceeds maximum {}",
                self.abi.len(),
                MAX_ABI_LEN,
            ));
        }
        if self.events.is_empty() {
            return Err("data source must subscribe to at least one event".into());
        }
        if self.events.len() > MAX_EVENTS_PER_SOURCE {
            return Err(format!(
                "data source has {} events (maximum {})",
                self.events.len(),
                MAX_EVENTS_PER_SOURCE,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_manifest_json() -> &'static [u8] {
        br#"{
            "spec_version": "1.0.0",
            "data_sources": [
                {
                    "name": "UniswapV3Pool",
                    "network": "mainnet",
                    "address": "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640",
                    "abi": "UniswapV3Pool",
                    "start_block": 12369621,
                    "events": ["Swap(address,address,int256,int256,uint160,uint128,int24)"]
                }
            ]
        }"#
    }

    #[test]
    fn round_trip_canonical() {
        let manifest = WillowManifest::from_bytes(good_manifest_json()).unwrap();
        assert_eq!(manifest.spec_version, MANIFEST_SPEC_VERSION);
        assert_eq!(manifest.data_sources.len(), 1);
        let ds = &manifest.data_sources[0];
        assert_eq!(ds.network, SupportedChain::Mainnet);
        assert_eq!(
            ds.address.to_canonical_string(),
            "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640"
        );

        let bytes = serde_json::to_vec(&manifest).unwrap();
        let again = WillowManifest::from_bytes(&bytes).unwrap();
        assert_eq!(manifest, again);
    }

    #[test]
    fn rejects_unsupported_chain() {
        let json = br#"{
            "spec_version": "1.0.0",
            "data_sources": [{
                "name": "T", "network": "frobnitz",
                "address": "0x0000000000000000000000000000000000000000",
                "abi": "ERC20", "start_block": 0,
                "events": ["Transfer(address,address,uint256)"]
            }]
        }"#;
        let err = WillowManifest::from_bytes(json).unwrap_err();
        assert!(err.contains("frobnitz") || err.contains("variant"), "{err}");
    }

    #[test]
    fn rejects_legacy_ethereum_alias() {
        let json = br#"{
            "spec_version": "1.0.0",
            "data_sources": [{
                "name": "T", "network": "ethereum",
                "address": "0x0000000000000000000000000000000000000000",
                "abi": "ERC20", "start_block": 0,
                "events": ["Transfer(address,address,uint256)"]
            }]
        }"#;
        assert!(WillowManifest::from_bytes(json).is_err());
    }

    #[test]
    fn rejects_unknown_field() {
        let json = br#"{
            "spec_version": "1.0.0",
            "data_sources": [],
            "extra_field": 1
        }"#;
        let err = WillowManifest::from_bytes(json).unwrap_err();
        assert!(
            err.contains("extra_field") || err.contains("unknown field"),
            "{err}"
        );
    }

    #[test]
    fn rejects_empty_data_sources() {
        let json = br#"{
            "spec_version": "1.0.0",
            "data_sources": []
        }"#;
        let err = WillowManifest::from_bytes(json).unwrap_err();
        assert!(err.contains("at least one"), "{err}");
    }

    #[test]
    fn rejects_bad_address() {
        let json = br#"{
            "spec_version": "1.0.0",
            "data_sources": [{
                "name": "T", "network": "mainnet",
                "address": "not-an-address",
                "abi": "ERC20", "start_block": 0,
                "events": ["Transfer(address,address,uint256)"]
            }]
        }"#;
        assert!(WillowManifest::from_bytes(json).is_err());
    }

    #[test]
    fn rejects_short_address() {
        let json = br#"{
            "spec_version": "1.0.0",
            "data_sources": [{
                "name": "T", "network": "mainnet",
                "address": "0xabc",
                "abi": "ERC20", "start_block": 0,
                "events": ["Transfer(address,address,uint256)"]
            }]
        }"#;
        assert!(WillowManifest::from_bytes(json).is_err());
    }

    #[test]
    fn rejects_bad_event_sig() {
        let json = br#"{
            "spec_version": "1.0.0",
            "data_sources": [{
                "name": "T", "network": "mainnet",
                "address": "0x0000000000000000000000000000000000000000",
                "abi": "ERC20", "start_block": 0,
                "events": ["nope no parens"]
            }]
        }"#;
        assert!(WillowManifest::from_bytes(json).is_err());
    }

    #[test]
    fn rejects_empty_events() {
        let json = br#"{
            "spec_version": "1.0.0",
            "data_sources": [{
                "name": "T", "network": "mainnet",
                "address": "0x0000000000000000000000000000000000000000",
                "abi": "ERC20", "start_block": 0,
                "events": []
            }]
        }"#;
        let err = WillowManifest::from_bytes(json).unwrap_err();
        assert!(err.contains("at least one event"), "{err}");
    }

    #[test]
    fn rejects_wrong_spec_version() {
        let json = br#"{
            "spec_version": "0.0.5",
            "data_sources": [{
                "name": "T", "network": "mainnet",
                "address": "0x0000000000000000000000000000000000000000",
                "abi": "ERC20", "start_block": 0,
                "events": ["Transfer(address,address,uint256)"]
            }]
        }"#;
        let err = WillowManifest::from_bytes(json).unwrap_err();
        assert!(err.contains("spec_version"), "{err}");
    }

    #[test]
    fn rejects_non_object_root() {
        assert!(WillowManifest::from_bytes(b"null").is_err());
        assert!(WillowManifest::from_bytes(b"[]").is_err());
        assert!(WillowManifest::from_bytes(b"42").is_err());
        assert!(WillowManifest::from_bytes(b"\"string\"").is_err());
    }

    #[test]
    fn accepts_every_canonical_chain() {
        for chain in SupportedChain::ALL {
            let json = format!(
                r#"{{
                    "spec_version": "1.0.0",
                    "data_sources": [{{
                        "name": "T", "network": "{}",
                        "address": "0x0000000000000000000000000000000000000000",
                        "abi": "ERC20", "start_block": 0,
                        "events": ["Transfer(address,address,uint256)"]
                    }}]
                }}"#,
                chain.canonical_id()
            );
            let manifest = WillowManifest::from_bytes(json.as_bytes())
                .unwrap_or_else(|e| panic!("{}: {}", chain, e));
            assert_eq!(manifest.data_sources[0].network, *chain);
        }
    }

    #[test]
    fn evm_address_uppercase_normalises_to_lower() {
        let addr = EvmAddress::parse("0xAABBCCDDEEFF00112233445566778899AABBCCDD").unwrap();
        assert_eq!(
            addr.to_canonical_string(),
            "0xaabbccddeeff00112233445566778899aabbccdd"
        );
    }

    #[test]
    fn event_sig_no_whitespace() {
        EventSignature::parse("Transfer(address,address,uint256)").unwrap();
        assert!(EventSignature::parse("Transfer (address,address,uint256)").is_err());
        assert!(EventSignature::parse("Transfer(address, address)").is_err());
        assert!(EventSignature::parse("Transfer").is_err());
        assert!(EventSignature::parse("9Bad(uint256)").is_err());
    }

    #[test]
    fn data_source_name_charset() {
        let bad_name = br#"{
            "spec_version": "1.0.0",
            "data_sources": [{
                "name": "Has Space",
                "network": "mainnet",
                "address": "0x0000000000000000000000000000000000000000",
                "abi": "ERC20", "start_block": 0,
                "events": ["Transfer(address,address,uint256)"]
            }]
        }"#;
        let err = WillowManifest::from_bytes(bad_name).unwrap_err();
        assert!(err.contains("alphanumeric"), "{err}");
    }
}
