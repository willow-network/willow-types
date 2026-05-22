use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use std::fmt;

use super::chains::{ChainFamily, SupportedChain};

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

/// A single data source within a manifest, dispatched by chain family.
///
/// The wire form has **no extra discriminator field**: a `DataSource`
/// deserializes from the same flat object the indexer ecosystem has used
/// since v1, with dispatch driven by the `network` field's `ChainFamily`.
/// EVM networks parse as [`EvmDataSource`]; Solana clusters parse as
/// [`SolanaDataSource`]. This keeps every manifest deployed before Solana
/// support landed parsing unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataSource {
    Evm(EvmDataSource),
    Solana(SolanaDataSource),
}

/// One indexed EVM contract within a manifest. Each data source pins
/// exactly one chain, contract address, ABI, start block, and event set;
/// manifests that need to index multiple chains or multiple contracts
/// have one entry per (chain, contract) pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct EvmDataSource {
    /// Human-readable label (e.g. "UniswapV3Pool"). Used for log lines and
    /// SDK ergonomics; not load-bearing for indexing.
    pub name: String,
    /// The chain this data source targets. Must be an EVM-family chain
    /// (cross-checked in `validate()`).
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

/// One indexed Solana program within a manifest. Each data source pins
/// exactly one cluster, program id, start slot, and instruction filter
/// set. Manifests targeting multiple programs use one entry per
/// (cluster, program) pair.
///
/// v1 scope: instruction filtering by variable-length leading-byte
/// discriminator (1-byte SPL tag, 4-byte System program tag, 8-byte
/// Anchor hash, etc.). Account-state filtering (track all accounts
/// owned by program X with discriminator Y) is a planned schema
/// extension and is not in v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct SolanaDataSource {
    /// Human-readable label. Used for log lines and SDK ergonomics; not
    /// load-bearing for indexing.
    pub name: String,
    /// The Solana cluster this data source targets. Must be a Solana-family
    /// chain (cross-checked in `validate()`).
    pub network: SupportedChain,
    /// Program id (32-byte Ed25519 pubkey) on `network`.
    pub program_id: SolanaPubkey,
    /// Slot at which to start indexing this data source. Solana's analogue
    /// of an EVM start block.
    pub start_slot: u64,
    /// Instruction discriminators to subscribe to. Length is
    /// program-specific: Anchor uses 8 bytes (`sha256("global:" +
    /// method_name)[..8]`), native SPL uses 1 byte, System program uses
    /// 4 bytes. Must be non-empty.
    pub instructions: Vec<InstructionDiscriminator>,
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

/// A 32-byte Solana program id / account pubkey. Stored as raw bytes;
/// the serialized form is the canonical base58 string Solana RPC and
/// explorers use (e.g. `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`).
/// Round-trip is exact — any input that successfully parses re-encodes
/// to the same string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SolanaPubkey(pub [u8; 32]);

impl SolanaPubkey {
    pub fn parse(s: &str) -> Result<Self, String> {
        // bs58 emits a fresh Vec; we copy into a fixed-size array so the
        // bound is enforced statically and downstream code can rely on it.
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| format!("invalid base58 pubkey {:?}: {}", s, e))?;
        if bytes.len() != 32 {
            return Err(format!(
                "Solana pubkey must decode to 32 bytes (got {})",
                bytes.len()
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(SolanaPubkey(out))
    }

    pub fn to_canonical_string(&self) -> String {
        bs58::encode(self.0).into_string()
    }
}

impl fmt::Display for SolanaPubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_canonical_string())
    }
}

impl Serialize for SolanaPubkey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_canonical_string())
    }
}

impl<'de> Deserialize<'de> for SolanaPubkey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PubkeyVisitor;
        impl Visitor<'_> for PubkeyVisitor {
            type Value = SolanaPubkey;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a base58-encoded 32-byte Solana pubkey")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<SolanaPubkey, E> {
                SolanaPubkey::parse(v).map_err(de::Error::custom)
            }
        }
        deserializer.deserialize_str(PubkeyVisitor)
    }
}

/// A parsed Solidity event signature of the form
/// `Name(type1 [indexed], type2 [indexed], ...)`.
///
/// Each param is `<solidity-type>` optionally followed by ` indexed`.
/// The `indexed` keyword is significant — it tells the decoder to read
/// the param from log topics (one 32-byte slot per indexed param)
/// instead of the ABI-encoded data blob. Solidity allows indexed params
/// at any position (interleaved with non-indexed), so the parser tracks
/// per-position flags rather than assuming "first N params are indexed".
///
/// `raw` preserves whatever the user wrote; `canonical()` strips the
/// `indexed` keyword to produce the topic0-hash input.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventSignature {
    /// User-facing form, e.g. `Supply(address indexed,address,address indexed,uint256,uint16 indexed)`.
    raw: String,
    /// Param Solidity type strings (without `indexed`), in declaration order.
    param_types: Vec<String>,
    /// Per-position `indexed` flag, same length as `param_types`.
    indexed: Vec<bool>,
    /// Event name (left of `(`).
    name: String,
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

        let mut param_types: Vec<String> = Vec::new();
        let mut indexed: Vec<bool> = Vec::new();
        if !params.is_empty() {
            for part in params.split(',') {
                // Strict: the only whitespace allowed is exactly one
                // space between the type and the literal `indexed`
                // keyword. No leading/trailing whitespace; no whitespace
                // inside the type.
                let (ty, is_indexed) = match part.split_once(' ') {
                    Some((ty, rest)) => {
                        if rest != "indexed" {
                            return Err(format!(
                                "invalid parameter modifier {:?} in {:?} \
                                 (only `indexed` is allowed; whitespace must be a single \
                                 separator between the type and `indexed`)",
                                rest, s
                            ));
                        }
                        (ty, true)
                    }
                    None => (part, false),
                };
                if !is_solidity_param_type(ty) {
                    return Err(format!("invalid parameter type {:?} in {:?}", ty, s));
                }
                param_types.push(ty.to_string());
                indexed.push(is_indexed);
            }
        }

        let indexed_count = indexed.iter().filter(|b| **b).count();
        if indexed_count > 3 {
            return Err(format!(
                "event {:?} has {} indexed params; Solidity allows at most 3",
                s, indexed_count
            ));
        }

        Ok(EventSignature {
            raw: s.to_string(),
            param_types,
            indexed,
            name: name.to_string(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Topic0-hash input: `Name(type1,type2,...)` with no `indexed`
    /// keyword and no whitespace. Matches what `keccak256` runs over in
    /// every Solidity compiler.
    pub fn canonical(&self) -> String {
        let mut out = String::with_capacity(self.raw.len());
        out.push_str(&self.name);
        out.push('(');
        for (i, ty) in self.param_types.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(ty);
        }
        out.push(')');
        out
    }

    /// Event name, e.g. `Supply`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Param Solidity type strings (without `indexed`), in declaration order.
    pub fn param_types(&self) -> &[String] {
        &self.param_types
    }

    /// Per-position `indexed` flags, in declaration order. `true` means
    /// the param is carried in a log topic; `false` means it lives in
    /// the ABI-encoded data blob.
    pub fn indexed(&self) -> &[bool] {
        &self.indexed
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

/// Solana instruction discriminator — the leading bytes of an instruction
/// data buffer used to identify the method being invoked. Length is
/// program-specific: Anchor programs use 8 bytes (`sha256("global:" +
/// method_name)[..8]`); native SPL programs use 1 byte (e.g. `0x03` for
/// `Transfer`); the System program uses 4-byte little-endian tags.
/// Serialized as `0x` + 2N hex characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InstructionDiscriminator(pub Vec<u8>);

impl InstructionDiscriminator {
    pub fn parse(s: &str) -> Result<Self, String> {
        let stripped = s
            .strip_prefix("0x")
            .ok_or_else(|| format!("instruction discriminator must start with 0x: {:?}", s))?;
        if stripped.is_empty() || stripped.len() % 2 != 0 {
            return Err(format!(
                "instruction discriminator must be 0x + an even, non-zero number of hex chars (got {} hex chars)",
                stripped.len()
            ));
        }
        let mut bytes = vec![0u8; stripped.len() / 2];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let hi = hex_nibble(stripped.as_bytes()[i * 2])?;
            let lo = hex_nibble(stripped.as_bytes()[i * 2 + 1])?;
            *byte = (hi << 4) | lo;
        }
        Ok(InstructionDiscriminator(bytes))
    }

    pub fn to_canonical_string(&self) -> String {
        let mut s = String::with_capacity(2 + self.0.len() * 2);
        s.push_str("0x");
        for byte in &self.0 {
            s.push(nibble_hex(byte >> 4));
            s.push(nibble_hex(byte & 0x0f));
        }
        s
    }
}

impl fmt::Display for InstructionDiscriminator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_canonical_string())
    }
}

impl Serialize for InstructionDiscriminator {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_canonical_string())
    }
}

impl<'de> Deserialize<'de> for InstructionDiscriminator {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DiscVisitor;
        impl Visitor<'_> for DiscVisitor {
            type Value = InstructionDiscriminator;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a 0x-prefixed instruction discriminator (even hex chars, >= 2)")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<InstructionDiscriminator, E> {
                InstructionDiscriminator::parse(v).map_err(de::Error::custom)
            }
        }
        deserializer.deserialize_str(DiscVisitor)
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
    /// Validate the data source, dispatching to the family-specific
    /// checks and cross-checking that the `network` field's family
    /// matches the variant. The dispatch invariant means a manifest
    /// can't smuggle EVM fields into a Solana data source (or vice
    /// versa) by lying about `network`: custom `Deserialize` picks the
    /// variant from the family, so any mismatch here is a programmer
    /// error rather than user input.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            DataSource::Evm(d) => {
                if d.network.family() != ChainFamily::Evm {
                    return Err(format!(
                        "evm data source on non-evm network {:?}",
                        d.network.canonical_id()
                    ));
                }
                d.validate()
            }
            DataSource::Solana(d) => {
                if d.network.family() != ChainFamily::Solana {
                    return Err(format!(
                        "solana data source on non-solana network {:?}",
                        d.network.canonical_id()
                    ));
                }
                d.validate()
            }
        }
    }

    /// Human-readable label, available without matching on the variant.
    pub fn name(&self) -> &str {
        match self {
            DataSource::Evm(d) => &d.name,
            DataSource::Solana(d) => &d.name,
        }
    }

    /// The chain this data source targets, available without matching.
    pub fn network(&self) -> SupportedChain {
        match self {
            DataSource::Evm(d) => d.network,
            DataSource::Solana(d) => d.network,
        }
    }
}

impl Serialize for DataSource {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Wire form has no discriminator wrapper — the `network` field
        // already carries the dispatch information. Delegate straight to
        // the inner struct so existing manifests serialize unchanged.
        match self {
            DataSource::Evm(d) => d.serialize(serializer),
            DataSource::Solana(d) => d.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for DataSource {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Peek at the `network` field via a JSON Value buffer, then
        // dispatch by `ChainFamily`. JSON-only — willow-types serializes
        // manifests as JSON throughout, so this is sufficient and keeps
        // the wire form identical to a directly-derived struct.
        #[derive(Deserialize)]
        struct NetworkHint {
            network: SupportedChain,
        }
        let value = serde_json::Value::deserialize(deserializer)?;
        let hint: NetworkHint = serde_json::from_value(value.clone()).map_err(de::Error::custom)?;
        match hint.network.family() {
            ChainFamily::Evm => serde_json::from_value::<EvmDataSource>(value)
                .map(DataSource::Evm)
                .map_err(de::Error::custom),
            ChainFamily::Solana => serde_json::from_value::<SolanaDataSource>(value)
                .map(DataSource::Solana)
                .map_err(de::Error::custom),
        }
    }
}

impl EvmDataSource {
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

impl SolanaDataSource {
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
        if self.instructions.is_empty() {
            return Err("data source must subscribe to at least one instruction".into());
        }
        if self.instructions.len() > MAX_EVENTS_PER_SOURCE {
            return Err(format!(
                "data source has {} instructions (maximum {})",
                self.instructions.len(),
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
        assert_eq!(ds.network(), SupportedChain::Mainnet);
        let DataSource::Evm(evm) = ds else {
            panic!("expected EVM data source");
        };
        assert_eq!(
            evm.address.to_canonical_string(),
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
            let json = match chain.family() {
                ChainFamily::Evm => format!(
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
                ),
                ChainFamily::Solana => format!(
                    r#"{{
                        "spec_version": "1.0.0",
                        "data_sources": [{{
                            "name": "T", "network": "{}",
                            "program_id": "11111111111111111111111111111111",
                            "start_slot": 0,
                            "instructions": ["0x0000000000000000"]
                        }}]
                    }}"#,
                    chain.canonical_id()
                ),
            };
            let manifest = WillowManifest::from_bytes(json.as_bytes())
                .unwrap_or_else(|e| panic!("{}: {}", chain, e));
            assert_eq!(manifest.data_sources[0].network(), *chain);
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
    fn event_sig_indexed_keyword() {
        // The only modifier we accept inside a param is exactly ` indexed`.
        let sig = EventSignature::parse(
            "Supply(address indexed,address,address indexed,uint256,uint16 indexed)",
        )
        .unwrap();
        assert_eq!(sig.name(), "Supply");
        assert_eq!(
            sig.param_types(),
            &["address", "address", "address", "uint256", "uint16"]
        );
        assert_eq!(sig.indexed(), &[true, false, true, false, true]);
        // Canonical form is what gets keccak'd for topic0.
        assert_eq!(
            sig.canonical(),
            "Supply(address,address,address,uint256,uint16)"
        );
    }

    #[test]
    fn event_sig_indexed_count_limit() {
        // Solidity limits to 3 indexed params per event.
        let err = EventSignature::parse(
            "Bad(uint256 indexed,uint256 indexed,uint256 indexed,uint256 indexed)",
        )
        .unwrap_err();
        assert!(err.contains("at most 3"), "{err}");
    }

    #[test]
    fn event_sig_rejects_unknown_modifier() {
        assert!(EventSignature::parse("X(address memory)").is_err());
        assert!(EventSignature::parse("X(address  indexed)").is_err());
    }

    #[test]
    fn event_sig_topic0_independent_of_indexed_keyword() {
        // Two signatures that differ only in `indexed` placement must
        // hash to the same topic0 — that's the contract Solidity enforces
        // and what on-chain logs match against.
        let with =
            EventSignature::parse("Transfer(address indexed,address indexed,uint256)").unwrap();
        let without = EventSignature::parse("Transfer(address,address,uint256)").unwrap();
        assert_eq!(with.canonical(), without.canonical());
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

    fn good_solana_manifest_json() -> &'static [u8] {
        br#"{
            "spec_version": "1.0.0",
            "data_sources": [
                {
                    "name": "SplToken",
                    "network": "solana-mainnet",
                    "program_id": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                    "start_slot": 200000000,
                    "instructions": ["0x0300000000000000"]
                }
            ]
        }"#
    }

    #[test]
    fn round_trip_solana() {
        let manifest = WillowManifest::from_bytes(good_solana_manifest_json()).unwrap();
        assert_eq!(manifest.data_sources.len(), 1);
        let ds = &manifest.data_sources[0];
        assert_eq!(ds.network(), SupportedChain::SolanaMainnet);
        let DataSource::Solana(sol) = ds else {
            panic!("expected Solana data source");
        };
        assert_eq!(
            sol.program_id.to_canonical_string(),
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        );
        assert_eq!(sol.start_slot, 200_000_000);
        assert_eq!(sol.instructions.len(), 1);
        assert_eq!(
            sol.instructions[0].to_canonical_string(),
            "0x0300000000000000"
        );

        let bytes = serde_json::to_vec(&manifest).unwrap();
        let again = WillowManifest::from_bytes(&bytes).unwrap();
        assert_eq!(manifest, again);
    }

    #[test]
    fn round_trip_mixed_evm_and_solana() {
        let json = br#"{
            "spec_version": "1.0.0",
            "data_sources": [
                {
                    "name": "Pool",
                    "network": "mainnet",
                    "address": "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640",
                    "abi": "UniswapV3Pool",
                    "start_block": 12369621,
                    "events": ["Swap(address,address,int256,int256,uint160,uint128,int24)"]
                },
                {
                    "name": "Token",
                    "network": "solana-mainnet",
                    "program_id": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                    "start_slot": 200000000,
                    "instructions": ["0x0300000000000000"]
                }
            ]
        }"#;
        let manifest = WillowManifest::from_bytes(json).unwrap();
        assert_eq!(manifest.data_sources.len(), 2);
        assert!(matches!(manifest.data_sources[0], DataSource::Evm(_)));
        assert!(matches!(manifest.data_sources[1], DataSource::Solana(_)));

        let bytes = serde_json::to_vec(&manifest).unwrap();
        let again = WillowManifest::from_bytes(&bytes).unwrap();
        assert_eq!(manifest, again);
    }

    #[test]
    fn rejects_evm_fields_on_solana_network() {
        let json = br#"{
            "spec_version": "1.0.0",
            "data_sources": [{
                "name": "T",
                "network": "solana-mainnet",
                "address": "0x0000000000000000000000000000000000000000",
                "program_id": "11111111111111111111111111111111",
                "start_slot": 0,
                "instructions": ["0x0000000000000000"]
            }]
        }"#;
        let err = WillowManifest::from_bytes(json).unwrap_err();
        assert!(
            err.contains("address") || err.contains("unknown field"),
            "{err}"
        );
    }

    #[test]
    fn rejects_solana_fields_on_evm_network() {
        let json = br#"{
            "spec_version": "1.0.0",
            "data_sources": [{
                "name": "T",
                "network": "mainnet",
                "address": "0x0000000000000000000000000000000000000000",
                "abi": "ERC20", "start_block": 0,
                "events": ["Transfer(address,address,uint256)"],
                "program_id": "11111111111111111111111111111111"
            }]
        }"#;
        let err = WillowManifest::from_bytes(json).unwrap_err();
        assert!(
            err.contains("program_id") || err.contains("unknown field"),
            "{err}"
        );
    }

    #[test]
    fn rejects_bad_base58_pubkey() {
        let json = br#"{
            "spec_version": "1.0.0",
            "data_sources": [{
                "name": "T", "network": "solana-mainnet",
                "program_id": "not-base58-because-zero-O-I-l-are-illegal-0OIl",
                "start_slot": 0,
                "instructions": ["0x0000000000000000"]
            }]
        }"#;
        assert!(WillowManifest::from_bytes(json).is_err());
    }

    #[test]
    fn rejects_short_pubkey() {
        let json = br#"{
            "spec_version": "1.0.0",
            "data_sources": [{
                "name": "T", "network": "solana-mainnet",
                "program_id": "abc",
                "start_slot": 0,
                "instructions": ["0x0000000000000000"]
            }]
        }"#;
        let err = WillowManifest::from_bytes(json).unwrap_err();
        assert!(err.contains("32 bytes") || err.contains("decode"), "{err}");
    }

    #[test]
    fn rejects_short_discriminator() {
        let json = br#"{
            "spec_version": "1.0.0",
            "data_sources": [{
                "name": "T", "network": "solana-mainnet",
                "program_id": "11111111111111111111111111111111",
                "start_slot": 0,
                "instructions": ["0xabc"]
            }]
        }"#;
        let err = WillowManifest::from_bytes(json).unwrap_err();
        assert!(err.contains("hex"), "{err}");
    }

    #[test]
    fn rejects_discriminator_without_0x() {
        let json = br#"{
            "spec_version": "1.0.0",
            "data_sources": [{
                "name": "T", "network": "solana-mainnet",
                "program_id": "11111111111111111111111111111111",
                "start_slot": 0,
                "instructions": ["abcdef0123456789"]
            }]
        }"#;
        let err = WillowManifest::from_bytes(json).unwrap_err();
        assert!(err.contains("0x"), "{err}");
    }

    #[test]
    fn rejects_empty_instructions() {
        let json = br#"{
            "spec_version": "1.0.0",
            "data_sources": [{
                "name": "T", "network": "solana-mainnet",
                "program_id": "11111111111111111111111111111111",
                "start_slot": 0,
                "instructions": []
            }]
        }"#;
        let err = WillowManifest::from_bytes(json).unwrap_err();
        assert!(err.contains("at least one instruction"), "{err}");
    }

    #[test]
    fn solana_pubkey_round_trip() {
        let s = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        let pubkey = SolanaPubkey::parse(s).unwrap();
        assert_eq!(pubkey.to_canonical_string(), s);
    }

    #[test]
    fn solana_pubkey_system_program_is_all_zeros() {
        // The Solana System Program is the canonical all-zeros pubkey,
        // which in base58 is exactly 32 '1' characters.
        let pubkey = SolanaPubkey::parse("11111111111111111111111111111111").unwrap();
        assert_eq!(pubkey.0, [0u8; 32]);
        assert_eq!(
            pubkey.to_canonical_string(),
            "11111111111111111111111111111111"
        );
    }

    #[test]
    fn instruction_discriminator_round_trip() {
        let disc = InstructionDiscriminator::parse("0xabcdef0123456789").unwrap();
        assert_eq!(disc.to_canonical_string(), "0xabcdef0123456789");
    }

    #[test]
    fn instruction_discriminator_uppercase_normalises_to_lower() {
        let disc = InstructionDiscriminator::parse("0xABCDEF0123456789").unwrap();
        assert_eq!(disc.to_canonical_string(), "0xabcdef0123456789");
    }

    #[test]
    fn instruction_discriminator_single_byte_spl_tag() {
        let disc = InstructionDiscriminator::parse("0x03").unwrap();
        assert_eq!(disc.0, vec![0x03]);
        assert_eq!(disc.to_canonical_string(), "0x03");
    }

    #[test]
    fn instruction_discriminator_four_byte_system_tag() {
        let disc = InstructionDiscriminator::parse("0x02000000").unwrap();
        assert_eq!(disc.0, vec![0x02, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn instruction_discriminator_rejects_odd_hex() {
        assert!(InstructionDiscriminator::parse("0x123").is_err());
    }

    #[test]
    fn instruction_discriminator_rejects_empty() {
        assert!(InstructionDiscriminator::parse("0x").is_err());
    }
}
