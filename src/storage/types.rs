use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_config: Option<TemplateSubgroveConfig>,
    /// Optional privacy configuration for private subgroves.
    /// When present, data stays with the provider and only state root
    /// commitments go on-chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy: Option<PrivacyConfig>,
    /// Retention window for real-time indexed data on consensus nodes.
    /// Only meaningful for BlockchainIndexing subgroves.
    #[serde(default)]
    pub retention_window:
        crate::consensus::indexing_transactions::RetentionWindow,
    /// Unix timestamp of creation.
    pub created_at: u64,
    /// Unix timestamp of last update.
    pub updated_at: u64,
}

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
    /// Serialized parameter values used for this instance.
    /// These are the validated parameters that were used to configure the template.
    pub parameters: HashMap<String, serde_json::Value>,
    /// Contracts to index (ethereum addresses as hex strings).
    pub contracts: Vec<String>,
    /// Event signatures to filter (keccak256 hashes as hex strings).
    pub event_signatures: Vec<String>,
    /// Optional blockchain chain identifier (e.g., "ethereum", "polygon").
    pub chain: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_indexers: Option<Vec<String>>,
    /// How often the provider must commit state roots to consensus.
    pub commitment_frequency: CommitmentFrequency,
}

/// How often the provider must publish state root commitments on-chain.
/// Default: EveryUpdate (strongest freshness guarantee).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CommitmentFrequency {
    /// Commit after every write/block update (default, strongest freshness).
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

impl Default for CommitmentFrequency {
    fn default() -> Self {
        CommitmentFrequency::EveryUpdate
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
