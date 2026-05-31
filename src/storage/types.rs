use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Index definition for subgrove data.
///
/// Defines a database index to optimize queries on specific fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexDefinition {
    /// Name of the index.
    pub name: String,
    /// Fields included in the index.
    pub fields: Vec<String>,
    /// Whether values must be unique.
    pub unique: bool,
}

/// Schema definition for subgrove documents.
///
/// Defines the structure and validation rules for documents in a subgrove.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDefinition {
    /// Schema version for migrations.
    #[serde(default = "default_schema_version")]
    pub version: u32,
    /// Field name to type mapping. Empty means schemaless (any JSON object accepted).
    #[serde(default)]
    pub fields: BTreeMap<String, FieldType>,
    /// Indexes for query optimization. Empty means key-based lookup only.
    #[serde(default)]
    pub indexes: Vec<IndexDefinition>,
    /// Fields that must be present in documents. Empty means no required fields.
    #[serde(default)]
    pub required_fields: Vec<String>,
}

fn default_schema_version() -> u32 {
    1
}

/// Supported field types for schema definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    /// UTF-8 string.
    String,
    /// Numeric value (integer or float).
    Number,
    /// Boolean true/false.
    Boolean,
    /// Array of values.
    Array,
    /// Nested object.
    Object,
    /// Raw byte array.
    Bytes,
}

/// Subgrove registration metadata.
///
/// A subgrove is a data collection with its own schema, access controls,
/// indexes, and funding balance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubgroveRegistration {
    /// Unique subgrove identifier.
    pub subgrove_id: String,
    /// Human-readable subgrove name.
    pub name: String,
    /// Subgrove description.
    #[serde(default)]
    pub description: String,
    /// DIDs with admin privileges.
    #[serde(default)]
    pub admins: Vec<String>,
    /// Document schema definition.
    pub schema: SchemaDefinition,
    /// DID of the subgrove owner.
    pub owner_did: String,
    /// DIDs with write access.
    pub writers: Vec<String>,
    /// DIDs with free read access (no payment required).
    /// Use `#[serde(alias = "readers")]` for backward compatibility with existing data.
    #[serde(alias = "readers")]
    pub free_readers: Vec<String>,
    /// Pricing configuration for paid reads.
    /// When enabled, users not on the `free_readers` list must pay per query.
    #[serde(default)]
    pub read_pricing: Option<crate::token::ReadPricing>,
    /// Checkpoint verification configuration.
    /// Optionally requires TEE attestation for checkpoint submissions.
    #[serde(default)]
    pub checkpoint_verification:
        crate::consensus::indexing_transactions::CheckpointVerificationConfig,
    /// Optional template configuration for GKR-provable indexing.
    /// Present when the subgrove was registered using a template.
    #[serde(default)]
    pub template_config: Option<TemplateSubgroveConfig>,
    /// Optional privacy configuration for private subgroves.
    /// When present, data stays with the provider and only state root
    /// commitments go on-chain.
    #[serde(default)]
    pub privacy: Option<PrivacyConfig>,
    /// Retention window for real-time indexed data on consensus nodes.
    /// Only meaningful for BlockchainIndexing subgroves.
    #[serde(default)]
    pub retention_window: crate::consensus::indexing_transactions::RetentionWindow,
    /// Blocks held in the chain-tip buffer before submissions fire.
    /// 0 = head-tier only (subsecond, reorg-supersedable); higher
    /// values trade latency for reorg safety. Owner-configurable.
    #[serde(default)]
    pub confirmation_depth: u32,
    /// Opt-in flag for browser-trustless completeness via the GF2
    /// receipts-trie WARP-folded proof carried on
    /// `EvmIndexedBlockSubmissionTx.receipts_root_proof`.
    ///
    /// When `true`, the indexer is expected to prove + fold + ship
    /// the receipts-trie proof for every block submission, and
    /// validators verify it against the trusted `receipts_root`
    /// (replacing #486's native-trie reconstruction for this
    /// subgrove). When `false` (the default), submissions take the
    /// validator-trust path from #486 unchanged — the indexer can
    /// leave `receipts_root_proof = None` and validators rebuild
    /// the trie natively.
    ///
    /// Opt-in is a deliberate choice because the per-block prove
    /// cost (~5-10 s after the compile cache from #498) is meaningful;
    /// subgroves that prioritize latency over browser-trustless
    /// soundness stay on the cheap path. See
    /// `docs/todo/proposal-receipts-trie-completeness.md` for the
    /// soundness story.
    #[serde(default)]
    pub cryptographic_completeness: bool,
    /// Unix timestamp of creation.
    pub created_at: u64,
    /// Unix timestamp of last update.
    pub updated_at: u64,
}

/// Upper bounds enforced by the consensus validator on
/// `TemplateSubgroveConfig` fields. Same rationale as the
/// `MAX_SUBGROVE_*` constants alongside `RegisterSubgroveTx`: keep
/// per-subgrove state bounded and the per-tx validation work cheap.
pub const MAX_TEMPLATE_ID_LEN: usize = 64;
pub const MAX_VARIANT_ID_LEN: usize = 64;
pub const MAX_TEMPLATE_PARAMETERS_BYTES: usize = 65_536;
pub const MAX_TEMPLATE_CONTRACTS: usize = 64;
pub const MAX_TEMPLATE_EVENT_SIGNATURES: usize = 64;
pub const MAX_TEMPLATE_CHAIN_LEN: usize = 32;

/// Configuration for template-based subgroves that use GKR proofs.
///
/// When a subgrove is registered with a template, this configuration
/// stores the template parameters and generated handler configuration
/// for indexer nodes to use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateSubgroveConfig {
    /// The template ID used to create this subgrove (e.g., "erc20-balance-tracker-v1").
    pub template_id: String,
    /// The template version at time of registration.
    pub template_version: u32,
    /// The selected circuit variant (e.g., "fixed8", "fixed64", "sparse").
    pub variant_id: String,
    /// JSON-encoded parameter values used for this instance.
    /// Stored as bytes so the struct roundtrips through bincode
    /// (`serde_json::Value::deserialize` calls `deserialize_any`, which
    /// bincode — a non-self-describing format — does not support).
    /// Consumers parse to `HashMap<String, serde_json::Value>` on demand.
    pub parameters: Vec<u8>,
    /// Contracts to index (ethereum addresses as hex strings).
    pub contracts: Vec<String>,
    /// Event signatures to filter (keccak256 hashes as hex strings).
    pub event_signatures: Vec<String>,
    /// Optional canonical chain identifier (e.g., "mainnet", "polygon").
    /// Must round-trip through [`SupportedChain`](crate::consensus::SupportedChain).
    pub chain: Option<String>,
}

impl TemplateSubgroveConfig {
    /// Validate length / count / charset bounds on every field.
    ///
    /// The consensus validator calls this for every `RegisterSubgrove`
    /// whose `template_config` is `Some(...)`; in-flight registrations
    /// with malformed bounds are rejected at the mempool boundary.
    pub fn validate(&self) -> Result<(), String> {
        validate_id(&self.template_id, "template_id", MAX_TEMPLATE_ID_LEN)?;
        validate_id(&self.variant_id, "variant_id", MAX_VARIANT_ID_LEN)?;

        if self.parameters.len() > MAX_TEMPLATE_PARAMETERS_BYTES {
            return Err(format!(
                "template_config.parameters size {} exceeds maximum {}",
                self.parameters.len(),
                MAX_TEMPLATE_PARAMETERS_BYTES
            ));
        }

        if self.contracts.len() > MAX_TEMPLATE_CONTRACTS {
            return Err(format!(
                "template_config.contracts has {} entries (maximum {})",
                self.contracts.len(),
                MAX_TEMPLATE_CONTRACTS
            ));
        }
        for (idx, addr) in self.contracts.iter().enumerate() {
            if !is_hex_with_prefix(addr, 40) {
                return Err(format!(
                    "template_config.contracts[{}] {:?} is not a 0x-prefixed 40-hex-char address",
                    idx, addr
                ));
            }
        }

        if self.event_signatures.len() > MAX_TEMPLATE_EVENT_SIGNATURES {
            return Err(format!(
                "template_config.event_signatures has {} entries (maximum {})",
                self.event_signatures.len(),
                MAX_TEMPLATE_EVENT_SIGNATURES
            ));
        }
        for (idx, sig) in self.event_signatures.iter().enumerate() {
            if !is_hex_with_prefix(sig, 64) {
                return Err(format!(
                    "template_config.event_signatures[{}] {:?} is not a 0x-prefixed 64-hex-char digest",
                    idx, sig
                ));
            }
        }

        if let Some(chain) = &self.chain {
            if chain.is_empty() {
                return Err("template_config.chain must not be empty when set".to_string());
            }
            if chain.len() > MAX_TEMPLATE_CHAIN_LEN {
                return Err(format!(
                    "template_config.chain length {} exceeds maximum {}",
                    chain.len(),
                    MAX_TEMPLATE_CHAIN_LEN
                ));
            }
            if crate::consensus::SupportedChain::from_canonical_id(chain).is_none() {
                return Err(format!(
                    "template_config.chain {:?} is not a canonical SupportedChain id",
                    chain
                ));
            }
        }

        Ok(())
    }
}

fn validate_id(value: &str, field: &str, max_len: usize) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("template_config.{} must not be empty", field));
    }
    if value.len() > max_len {
        return Err(format!(
            "template_config.{} length {} exceeds maximum {}",
            field,
            value.len(),
            max_len
        ));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(format!(
            "template_config.{} {:?} must be ASCII alphanumeric, '-', or '_'",
            field, value
        ));
    }
    Ok(())
}

fn is_hex_with_prefix(s: &str, hex_len: usize) -> bool {
    s.strip_prefix("0x")
        .map(|rest| rest.len() == hex_len && rest.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or(false)
}

#[cfg(test)]
mod template_subgrove_config_tests {
    use super::*;

    fn good_config() -> TemplateSubgroveConfig {
        TemplateSubgroveConfig {
            template_id: "balance-aggregator-v2".to_string(),
            template_version: 1,
            variant_id: "balance-aggregator-v2-fixed64".to_string(),
            parameters: b"{}".to_vec(),
            contracts: vec!["0x7159cc276d7d17ab4b3beb19959e1f39368a45ba".to_string()],
            event_signatures: vec![
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef".to_string(),
            ],
            chain: Some("mainnet".to_string()),
        }
    }

    #[test]
    fn known_good_passes() {
        good_config().validate().unwrap();
    }

    #[test]
    fn rejects_empty_template_id() {
        let mut c = good_config();
        c.template_id = String::new();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_empty_variant_id() {
        let mut c = good_config();
        c.variant_id = String::new();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_template_id_with_invalid_chars() {
        let mut c = good_config();
        c.template_id = "has space".to_string();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_template_id_too_long() {
        let mut c = good_config();
        c.template_id = "a".repeat(MAX_TEMPLATE_ID_LEN + 1);
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_parameters_too_large() {
        let mut c = good_config();
        c.parameters = vec![0u8; MAX_TEMPLATE_PARAMETERS_BYTES + 1];
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_too_many_contracts() {
        let mut c = good_config();
        c.contracts = (0..MAX_TEMPLATE_CONTRACTS + 1)
            .map(|_| "0x0000000000000000000000000000000000000000".to_string())
            .collect();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_malformed_contract_address() {
        for bad in [
            "0x123",                                       // too short
            "not-an-address",                              // no prefix
            "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",  // non-hex
            "0x00000000000000000000000000000000000000000", // 41 hex chars
        ] {
            let mut c = good_config();
            c.contracts = vec![bad.to_string()];
            assert!(c.validate().is_err(), "should reject contract {:?}", bad);
        }
    }

    #[test]
    fn rejects_too_many_event_signatures() {
        let mut c = good_config();
        c.event_signatures = (0..MAX_TEMPLATE_EVENT_SIGNATURES + 1)
            .map(|_| {
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef".to_string()
            })
            .collect();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_malformed_event_signature() {
        for bad in [
            "0xddf252ad", // 8 hex chars, not 64
            "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", // no 0x prefix
            "Transfer(address,address,uint256)", // human-readable, not keccak digest
        ] {
            let mut c = good_config();
            c.event_signatures = vec![bad.to_string()];
            assert!(
                c.validate().is_err(),
                "should reject event signature {:?}",
                bad
            );
        }
    }

    #[test]
    fn rejects_empty_chain_when_set() {
        let mut c = good_config();
        c.chain = Some(String::new());
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_chain_too_long() {
        let mut c = good_config();
        c.chain = Some("x".repeat(MAX_TEMPLATE_CHAIN_LEN + 1));
        assert!(c.validate().is_err());
    }

    #[test]
    fn accepts_no_chain() {
        let mut c = good_config();
        c.chain = None;
        c.validate().unwrap();
    }

    #[test]
    fn accepts_values_at_caps() {
        let mut c = good_config();
        c.template_id = "a".repeat(MAX_TEMPLATE_ID_LEN);
        c.variant_id = "a".repeat(MAX_VARIANT_ID_LEN);
        c.parameters = vec![0u8; MAX_TEMPLATE_PARAMETERS_BYTES];
        c.contracts = (0..MAX_TEMPLATE_CONTRACTS)
            .map(|_| "0x0000000000000000000000000000000000000000".to_string())
            .collect();
        c.event_signatures = (0..MAX_TEMPLATE_EVENT_SIGNATURES)
            .map(|_| {
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef".to_string()
            })
            .collect();
        // chain must be a canonical SupportedChain id; "arbitrum-one" is
        // the longest canonical id at 12 chars — well under the length cap.
        c.chain = Some("arbitrum-one".to_string());
        c.validate().unwrap();
    }

    #[test]
    fn rejects_non_canonical_chain() {
        let mut c = good_config();
        c.chain = Some("ethereum".to_string());
        let err = c
            .validate()
            .expect_err("non-canonical chain must be rejected");
        assert!(err.contains("canonical SupportedChain"), "{err}");
    }

    #[test]
    fn accepts_every_canonical_chain() {
        for chain in crate::consensus::SupportedChain::ALL {
            let mut c = good_config();
            c.chain = Some(chain.canonical_id().to_string());
            c.validate().unwrap_or_else(|e| panic!("{}: {}", chain, e));
        }
    }
}

/// Phase of indexing for a subgrove.
///
/// Tracks whether a subgrove is still in historical sync or has transitioned
/// to realtime indexing after a checkpoint is verified.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum IndexingPhase {
    /// No indexing has started yet for this subgrove.
    #[default]
    NotStarted,
    /// Historical indexing is in progress but no trusted checkpoint exists yet.
    HistoricalSync,
    /// A trusted checkpoint exists and realtime indexing can proceed.
    Realtime,
}

/// Current indexing state for a subgrove.
///
/// Tracks the trusted checkpoint (if any) and the block from which realtime
/// indexing should proceed. This state is updated when a checkpoint reaches
/// the required verification threshold.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubgroveIndexingState {
    /// The trusted checkpoint ID (if one exists).
    /// Set when a checkpoint's challenge window expires without dispute.
    pub trusted_checkpoint_id: Option<[u8; 32]>,
    /// The block number from which realtime indexing should proceed.
    /// This is set to checkpoint.end_block + 1 when a checkpoint becomes trusted.
    pub realtime_start_block: Option<u64>,
    /// Current indexing phase for this subgrove.
    pub phase: IndexingPhase,
    /// Unix timestamp when the checkpoint became trusted.
    pub trusted_at: Option<u64>,
    /// The state root from the trusted checkpoint.
    /// New nodes can sync state from this root.
    pub trusted_state_root: Option<[u8; 32]>,
    /// Highest block number that has been pruned from consensus.
    /// Blocks <= this are only available from indexer nodes.
    #[serde(default)]
    pub pruned_up_to_block: Option<u64>,
}

impl SubgroveIndexingState {
    /// Create a new state indicating a checkpoint just became trusted.
    pub fn from_trusted_checkpoint(
        checkpoint_id: [u8; 32],
        state_root: [u8; 32],
        realtime_start_block: u64,
        trusted_at: u64,
    ) -> Self {
        Self {
            trusted_checkpoint_id: Some(checkpoint_id),
            realtime_start_block: Some(realtime_start_block),
            phase: IndexingPhase::Realtime,
            trusted_at: Some(trusted_at),
            trusted_state_root: Some(state_root),
            pruned_up_to_block: None,
        }
    }

    /// Returns true if this subgrove has a trusted checkpoint.
    pub fn is_trusted(&self) -> bool {
        self.trusted_checkpoint_id.is_some()
    }

    /// Returns true if realtime indexing has started.
    pub fn is_realtime(&self) -> bool {
        self.phase == IndexingPhase::Realtime
    }
}

/// Configuration for a private subgrove.
/// Presence of this on a SubgroveRegistration means data stays with the provider,
/// only state root commitments go on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Optional whitelist of indexer DIDs allowed to index this subgrove.
    /// When Some, only these DIDs can submit IndexedBlockSubmissionTx / HistoricalCheckpointTx.
    /// When None, open marketplace (existing behavior).
    #[serde(default)]
    pub allowed_indexers: Option<Vec<String>>,
    /// How often the provider must commit state roots to consensus.
    pub commitment_frequency: CommitmentFrequency,
}

/// Upper bounds for `PrivacyConfig`.
pub const MAX_ALLOWED_INDEXERS: usize = 64;
pub const MAX_COMMITMENT_BLOCKS: u64 = 15_768_000;
pub const MAX_COMMITMENT_SECONDS: u64 = 31_536_000;

impl PrivacyConfig {
    /// Validate length / count / charset bounds.
    pub fn validate(&self) -> Result<(), String> {
        use crate::consensus::transactions::validate_did;
        if let Some(allowed) = &self.allowed_indexers {
            if allowed.len() > MAX_ALLOWED_INDEXERS {
                return Err(format!(
                    "privacy.allowed_indexers has {} entries (maximum {})",
                    allowed.len(),
                    MAX_ALLOWED_INDEXERS
                ));
            }
            for (idx, did) in allowed.iter().enumerate() {
                validate_did(did, &format!("privacy.allowed_indexers[{}]", idx))?;
            }
        }
        self.commitment_frequency.validate()?;
        Ok(())
    }
}

/// How often the provider must publish state root commitments on-chain.
/// Default: EveryUpdate (strongest freshness guarantee).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub enum CommitmentFrequency {
    /// Commit after every write/block update (default, strongest freshness).
    #[default]
    EveryUpdate,
    /// Commit every N blocks processed.
    EveryNBlocks(u64),
    /// Commit at least every N seconds.
    EveryNSeconds(u64),
    /// No on-chain commitments. Provider serves data without consensus anchoring.
    ///
    /// **Security note**: This means zero on-chain accountability — the provider
    /// can silently modify or delete data without detection. Should only be used
    /// for trusted internal providers where the subgrove owner has a separate
    /// out-of-band trust relationship with the provider (e.g., the owner IS the
    /// provider, or they share the same organizational control).
    Never,
}

impl CommitmentFrequency {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            CommitmentFrequency::EveryUpdate | CommitmentFrequency::Never => Ok(()),
            CommitmentFrequency::EveryNBlocks(n) => {
                if *n == 0 {
                    return Err("commitment_frequency.EveryNBlocks must be > 0".to_string());
                }
                if *n > MAX_COMMITMENT_BLOCKS {
                    return Err(format!(
                        "commitment_frequency.EveryNBlocks {} exceeds maximum {}",
                        n, MAX_COMMITMENT_BLOCKS
                    ));
                }
                Ok(())
            }
            CommitmentFrequency::EveryNSeconds(n) => {
                if *n == 0 {
                    return Err("commitment_frequency.EveryNSeconds must be > 0".to_string());
                }
                if *n > MAX_COMMITMENT_SECONDS {
                    return Err(format!(
                        "commitment_frequency.EveryNSeconds {} exceeds maximum {}",
                        n, MAX_COMMITMENT_SECONDS
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Encrypted copy of a subgrove's symmetric key, wrapped for a specific reader DID.
/// Used for access control — owner wraps the subgrove key for each authorized reader.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeyGrant {
    /// DID of the grantee receiving access.
    pub grantee_did: String,
    /// Key epoch this grant belongs to.
    pub key_epoch: u32,
    /// ID of the grantee's public key used for ECDH.
    pub grantee_public_key_id: String,
    /// Ephemeral public key for ECDH (32 bytes X25519).
    pub ephemeral_public_key: Vec<u8>,
    /// nonce (24 bytes) || ciphertext || auth_tag (16 bytes).
    pub encrypted_key: Vec<u8>,
    /// DID that granted this key.
    pub granted_by: String,
    /// Unix timestamp when granted.
    pub granted_at: u64,
}

/// X25519 ephemeral public key size in bytes.
pub const X25519_PUBKEY_LEN: usize = 32;

/// XChaCha20-Poly1305 nonce (24 bytes) + auth tag (16 bytes); a valid
/// `encrypted_key` is at least this long even for a zero-byte plaintext.
pub const MIN_ENCRYPTED_KEY_LEN: usize = 24 + 16;

/// Upper bound on `encrypted_key`. The wrapped payload is a single 32-byte
/// subgrove key, so anything larger than ~1 KiB is structurally suspect.
pub const MAX_ENCRYPTED_KEY_LEN: usize = 1024;

impl EncryptedKeyGrant {
    /// Validate length / charset / DID-format bounds on every field.
    pub fn validate(&self) -> Result<(), String> {
        use crate::consensus::transactions::{validate_did, validate_public_key_id};
        validate_did(&self.grantee_did, "grantee_did")?;
        validate_did(&self.granted_by, "granted_by")?;
        validate_public_key_id(&self.grantee_public_key_id, "grantee_public_key_id")?;
        if self.ephemeral_public_key.len() != X25519_PUBKEY_LEN {
            return Err(format!(
                "ephemeral_public_key must be {} bytes (got {})",
                X25519_PUBKEY_LEN,
                self.ephemeral_public_key.len()
            ));
        }
        if self.encrypted_key.len() < MIN_ENCRYPTED_KEY_LEN {
            return Err(format!(
                "encrypted_key length {} is below minimum {}",
                self.encrypted_key.len(),
                MIN_ENCRYPTED_KEY_LEN
            ));
        }
        if self.encrypted_key.len() > MAX_ENCRYPTED_KEY_LEN {
            return Err(format!(
                "encrypted_key length {} exceeds maximum {}",
                self.encrypted_key.len(),
                MAX_ENCRYPTED_KEY_LEN
            ));
        }
        Ok(())
    }
}

/// Algorithm used for key wrapping in EncryptedKeyGrant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EncryptionAlgorithm {
    /// XChaCha20-Poly1305 authenticated encryption.
    XChaCha20Poly1305,
}

/// Permission grant for access control.
///
/// Records a permission granted to a DID for a subgrove.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    /// DID receiving the permission.
    pub did: String,
    /// Subgrove the permission applies to.
    pub subgrove_id: String,
    /// Role level granted.
    pub role: PermissionRole,
    /// DID that granted this permission.
    pub granted_by: String,
    /// Unix timestamp when granted.
    pub granted_at: u64,
}

/// Permission role levels for access control.
///
/// Roles form a hierarchy where higher roles include lower role permissions:
/// Owner > Admin > Writer > Reader
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PermissionRole {
    /// Full control including deletion and permission management.
    Owner,
    /// Can manage permissions but not delete the resource.
    Admin,
    /// Can create and modify data.
    Writer,
    /// Can only read data.
    Reader,
}

#[cfg(test)]
mod privacy_config_tests {
    use super::*;

    fn good() -> PrivacyConfig {
        PrivacyConfig {
            allowed_indexers: None,
            commitment_frequency: CommitmentFrequency::EveryUpdate,
        }
    }

    #[test]
    fn default_passes() {
        good().validate().unwrap();
    }

    #[test]
    fn accepts_allowed_indexers_at_cap() {
        let mut c = good();
        c.allowed_indexers = Some(
            (0..MAX_ALLOWED_INDEXERS)
                .map(|i| format!("did:willow:indexer{i}"))
                .collect(),
        );
        c.validate().unwrap();
    }

    #[test]
    fn rejects_too_many_allowed_indexers() {
        let mut c = good();
        c.allowed_indexers = Some(
            (0..MAX_ALLOWED_INDEXERS + 1)
                .map(|i| format!("did:willow:indexer{i}"))
                .collect(),
        );
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_allowed_indexer_with_bad_did() {
        let mut c = good();
        c.allowed_indexers = Some(vec![
            "did:willow:ok".to_string(),
            "did:other:nope".to_string(),
        ]);
        let err = c.validate().expect_err("non-willow DID must be rejected");
        assert!(err.contains("allowed_indexers[1]"), "{err}");
    }

    #[test]
    fn rejects_every_n_blocks_zero() {
        let mut c = good();
        c.commitment_frequency = CommitmentFrequency::EveryNBlocks(0);
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_every_n_blocks_too_large() {
        let mut c = good();
        c.commitment_frequency = CommitmentFrequency::EveryNBlocks(MAX_COMMITMENT_BLOCKS + 1);
        assert!(c.validate().is_err());
    }

    #[test]
    fn accepts_every_n_blocks_at_cap() {
        let mut c = good();
        c.commitment_frequency = CommitmentFrequency::EveryNBlocks(MAX_COMMITMENT_BLOCKS);
        c.validate().unwrap();
    }

    #[test]
    fn rejects_every_n_seconds_zero() {
        let mut c = good();
        c.commitment_frequency = CommitmentFrequency::EveryNSeconds(0);
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_every_n_seconds_too_large() {
        let mut c = good();
        c.commitment_frequency = CommitmentFrequency::EveryNSeconds(MAX_COMMITMENT_SECONDS + 1);
        assert!(c.validate().is_err());
    }

    #[test]
    fn accepts_every_n_seconds_at_cap() {
        let mut c = good();
        c.commitment_frequency = CommitmentFrequency::EveryNSeconds(MAX_COMMITMENT_SECONDS);
        c.validate().unwrap();
    }

    #[test]
    fn accepts_never() {
        let mut c = good();
        c.commitment_frequency = CommitmentFrequency::Never;
        c.validate().unwrap();
    }
}

#[cfg(test)]
mod encrypted_key_grant_tests {
    use super::*;

    fn good() -> EncryptedKeyGrant {
        EncryptedKeyGrant {
            grantee_did: "did:willow:grantee".to_string(),
            key_epoch: 1,
            grantee_public_key_id: "did:willow:grantee#key-1".to_string(),
            ephemeral_public_key: vec![0u8; X25519_PUBKEY_LEN],
            encrypted_key: vec![0u8; MIN_ENCRYPTED_KEY_LEN],
            granted_by: "did:willow:owner".to_string(),
            granted_at: 1_700_000_000,
        }
    }

    #[test]
    fn known_good_passes() {
        good().validate().unwrap();
    }

    #[test]
    fn accepts_encrypted_key_at_caps() {
        let mut g = good();
        g.encrypted_key = vec![0u8; MAX_ENCRYPTED_KEY_LEN];
        g.validate().unwrap();
    }

    #[test]
    fn rejects_grantee_did_bad_format() {
        let mut g = good();
        g.grantee_did = "did:other:nope".to_string();
        assert!(g.validate().is_err());
    }

    #[test]
    fn rejects_granted_by_bad_format() {
        let mut g = good();
        g.granted_by = "did:other:nope".to_string();
        assert!(g.validate().is_err());
    }

    #[test]
    fn rejects_grantee_public_key_id_without_hash() {
        let mut g = good();
        g.grantee_public_key_id = "did:willow:grantee".to_string();
        assert!(g.validate().is_err());
    }

    #[test]
    fn rejects_ephemeral_public_key_too_short() {
        let mut g = good();
        g.ephemeral_public_key = vec![0u8; X25519_PUBKEY_LEN - 1];
        let err = g
            .validate()
            .expect_err("short X25519 pubkey must be rejected");
        assert!(err.contains("ephemeral_public_key"), "{err}");
    }

    #[test]
    fn rejects_ephemeral_public_key_too_long() {
        let mut g = good();
        g.ephemeral_public_key = vec![0u8; X25519_PUBKEY_LEN + 1];
        assert!(g.validate().is_err());
    }

    #[test]
    fn rejects_encrypted_key_too_short() {
        let mut g = good();
        g.encrypted_key = vec![0u8; MIN_ENCRYPTED_KEY_LEN - 1];
        let err = g
            .validate()
            .expect_err("encrypted_key shorter than nonce+auth_tag must be rejected");
        assert!(err.contains("encrypted_key"), "{err}");
    }

    #[test]
    fn rejects_encrypted_key_too_long() {
        let mut g = good();
        g.encrypted_key = vec![0u8; MAX_ENCRYPTED_KEY_LEN + 1];
        assert!(g.validate().is_err());
    }
}
