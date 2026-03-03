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
    pub version: u32,
    /// Field name to type mapping.
    pub fields: BTreeMap<String, FieldType>,
    /// Indexes for query optimization.
    pub indexes: Vec<IndexDefinition>,
    /// Fields that must be present in documents.
    pub required_fields: Vec<String>,
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

/// Application registration metadata.
///
/// Stores information about a registered application in the Willow network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRegistration {
    /// Unique application identifier.
    pub app_id: String,
    /// Human-readable application name.
    pub name: String,
    /// Application description.
    pub description: String,
    /// Application category (e.g., "social-media", "defi").
    pub app_type: String,
    /// DID of the application owner.
    pub owner_did: String,
    /// DIDs with admin privileges.
    pub admins: Vec<String>,
    /// Unix timestamp of creation.
    pub created_at: u64,
    /// Unix timestamp of last update.
    pub updated_at: u64,
}

/// Subgrove registration metadata.
///
/// A subgrove is a data collection within an application with its own
/// schema, access controls, and indexes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubgroveRegistration {
    /// Unique identifier within the app.
    pub subgrove_id: String,
    /// Parent application identifier.
    pub app_id: String,
    /// Human-readable subgrove name.
    pub name: String,
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

/// Permission grant for access control.
///
/// Records a permission granted to a DID for an app or subgrove.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    /// DID receiving the permission.
    pub did: String,
    /// Application the permission applies to.
    pub app_id: String,
    /// Optional subgrove scope (None = app-wide).
    pub subgrove_id: Option<String>,
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
