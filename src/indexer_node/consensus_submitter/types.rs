use crate::consensus::indexing_transactions::{
    EventInclusionProof, GkrProofData, TransactionInclusionProof,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// DID type alias
pub type DID = String;

// ============================================================================
// Indexer Attestation - Cryptographic attestation that indexing was performed
// correctly according to the subgrove specification
// ============================================================================

/// Current version of the Indexer Attestation format.
///
/// Incremented when the attestation structure changes to maintain compatibility.
pub const ATTESTATION_VERSION: u8 = 1;

/// Cryptographic Indexer Attestation.
///
/// Commits to the indexed data, source blockchain headers, and subgrove
/// configuration, signed by the indexer's Ed25519 key.
///
/// # Verification
///
/// Validators verify attestations by:
/// 1. Checking the signature against the indexer's registered public key
/// 2. Verifying the data merkle root matches submitted data
/// 3. Optionally re-executing WASM handlers to verify transformation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexingAttestation {
    /// Version of the attestation format
    pub version: u8,

    /// The indexer's DID
    pub indexer_did: DID,

    /// Subgrove ID this proof is for
    pub subgrove_id: String,

    /// Merkle root of all indexed data batches
    pub data_merkle_root: [u8; 32],

    /// Block range covered by this proof
    pub block_range: (u64, u64),

    /// Commitment to source blockchain headers
    /// SHA256(block_number || block_hash) for each block in range
    pub block_headers_commitment: [u8; 32],

    /// Hash of the subgrove configuration that was followed
    /// This proves the indexer used the correct schema/transform rules
    pub subgrove_config_hash: [u8; 32],

    /// Individual batch proofs for granular verification
    pub batch_proofs: Vec<BatchProof>,

    /// Timestamp when the attestation was generated (Unix timestamp)
    pub timestamp: u64,

    /// Nonce for replay protection
    pub nonce: u64,

    /// The message that was signed (for verification)
    pub signed_message: Vec<u8>,

    /// Ed25519 signature over the attestation contents (64 bytes)
    /// Signs: SHA256(version || indexer_did || subgrove_id || data_merkle_root ||
    ///               block_range || block_headers_commitment || subgrove_config_hash ||
    ///               timestamp || nonce)
    pub signature: Vec<u8>,

    /// Public key ID from the DID document used for signing
    pub public_key_id: String,
}

/// Proof for an individual batch within an Indexer Attestation.
///
/// Enables granular verification of specific block ranges without
/// re-verifying the entire submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProof {
    /// Index of this batch in the submission
    pub batch_index: u32,

    /// Block range for this specific batch
    pub block_range: (u64, u64),

    /// SHA256 hash of the batch data
    pub data_hash: [u8; 32],

    /// Number of entities/events in this batch
    pub entity_count: u64,

    /// Merkle proof path from this batch to the root
    pub merkle_proof: Vec<[u8; 32]>,

    /// Position in the Merkle tree (for verification)
    pub merkle_position: u32,
}

/// Commitment to a source blockchain block header.
///
/// Used to bind indexed data to specific L1 blocks for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeaderCommitment {
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub timestamp: u64,
}

/// Subgrove configuration data used for hash computation.
///
/// The hash of this configuration is included in the attestation to prove
/// the indexer followed the correct schema and transformation rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubgroveConfigForHashing {
    pub subgrove_id: String,
    pub chain: String,
    pub contracts: Vec<String>,
    pub event_signatures: Vec<String>,
    pub schema_hash: [u8; 32],
    pub transform_rules_hash: [u8; 32],
}

impl SubgroveConfigForHashing {
    /// Compute a hash of the subgrove configuration.
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"SUBGROVE_CONFIG:");
        hasher.update(self.subgrove_id.as_bytes());
        hasher.update(self.chain.as_bytes());
        for contract in &self.contracts {
            hasher.update(contract.as_bytes());
        }
        for sig in &self.event_signatures {
            hasher.update(sig.as_bytes());
        }
        hasher.update(self.schema_hash);
        hasher.update(self.transform_rules_hash);
        hasher.finalize().into()
    }
}

// ============================================================================
// Response types for ABCI queries
// ============================================================================

/// Response from querying subgrove registration status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubgroveRegistrationResponse {
    pub subgrove_id: String,
    pub name: String,
    pub owner_did: String,
    pub writers: Vec<String>,
    #[serde(alias = "readers")]
    pub free_readers: Vec<String>,
    pub read_pricing: Option<crate::token::ReadPricing>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Response from querying a subgrove's funding balance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubgroveFundingResponse {
    pub subgrove_id: String,
    pub balance: u128,
    pub total_spent: u128,
    pub last_funded: u64,
}

// ============================================================================
// Transaction types for indexed data submission
// ============================================================================

/// Type of transaction being submitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionType {
    /// Historical checkpoint (single submission after full sync, verified via MultiIndexer or TEE)
    HistoricalCheckpoint,
    /// Single block update at chain tip (with optional GKR proof)
    IndexedBlockSubmission,
    SubgroveRegistration,
    IndexerRegistration,
    Other(String),
}

/// Transaction for submitting a single block update at chain-tip.
///
/// Used for real-time indexing of new blocks. Supports two verification modes:
///
/// ## With GKR Proof (`gkr_proof` is `Some`)
///
/// Cryptographic verification via GKR proof:
/// 1. **Event Inclusion**: Each `event_proof` is verified against `block_header.receipts_root`
///    using MPT proof verification. This proves events actually occurred on Ethereum.
/// 2. **Input Binding**: The hash of events must match `gkr_proof.public_inputs.input_commitment`.
/// 3. **Transformation**: The GKR proof cryptographically guarantees correct transformation.
///
/// Fee split: 85% indexer, 5% validators, 10% treasury.
///
/// ## Without GKR Proof (`gkr_proof` is `None`)
///
/// Re-execution verification at the subgrove's configured sampling rate:
/// - **ConsensusExecution**: 100% execution by validators
/// - **IndexerExecution**: Sampling-based (e.g., 5%)
///
/// Fee split varies by execution mode (see `get_fee_distribution_percentages`).
///
/// ## Event Proofs
///
/// `event_proofs` can be included regardless of whether a GKR proof is present.
/// When the subgrove requires event inclusion verification, consensus verifies
/// each proof against `block_header.receipts_root`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedBlockSubmissionTx {
    pub transaction_type: TransactionType,
    /// The indexer's DID
    pub indexer_did: DID,
    /// Subgrove this update is for
    pub subgrove_id: String,
    /// Block number that was indexed
    pub block_number: u64,
    /// Block hash (for reorg detection)
    pub block_hash: [u8; 32],
    /// Parent block hash (for chain continuity verification)
    pub parent_hash: [u8; 32],
    /// Hash of the indexed data
    pub data_hash: [u8; 32],
    /// The actual indexed data (serialized). Base64-encoded on the JSON
    /// wire — this is a bincode-serialized IndexedBlock and can be ~1–2MB
    /// for a busy Ethereum block, so default number-array encoding bloats
    /// it ~4x.
    #[serde(with = "base64_bytes")]
    pub indexed_data: Vec<u8>,
    /// Block header commitment for L1 verification
    pub block_header: BlockHeaderCommitment,
    /// Optional GKR proof of correct transformation.
    /// When present, consensus verifies the proof cryptographically.
    /// When absent, consensus uses direct execution or sampling-based re-execution
    /// (depending on the subgrove's execution mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gkr_proof: Option<GkrProofData>,
    /// MPT proofs proving each input event exists in the block's receipts.
    /// Verified against `block_header.receipts_root`.
    /// Included when the subgrove requires event inclusion verification.
    #[serde(default)]
    pub event_proofs: Vec<EventInclusionProof>,
    /// MPT proofs proving each tx exists in the block's transactions trie.
    /// Required alongside `completeness_proof` for tx authentication.
    #[serde(default)]
    pub transaction_proofs: Vec<TransactionInclusionProof>,
    /// Bincode-serialized `Vec<IndexedLog>` covering every log in the
    /// block (not just matched). Kept as opaque bytes so willow-types
    /// stays a leaf crate; consensus deserializes via willow-network.
    #[serde(default)]
    pub block_logs_bincode: Vec<u8>,
    /// Bincode-serialized `Vec<IndexedTransaction>` covering every tx
    /// in the block.
    #[serde(default)]
    pub block_transactions_bincode: Vec<u8>,
    /// Serialized `ChunkedBlockCompletenessProof` (from `willow-indexing`'s
    /// completeness_prover). Carries one GKR proof per fixed-size log /
    /// tx chunk, so blocks with more than a single circuit batch's worth
    /// of logs or txs can still be proven. When present, consensus runs
    /// the completeness-proof verification path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completeness_proof: Option<Vec<u8>>,
    /// Optional TEE attestation for TeeExecution mode.
    /// When present, consensus verifies the attestation instead of re-executing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee_attestation: Option<crate::tee::TeeAttestation>,
    /// Storage cost for this data
    pub storage_cost: u128,
    /// Timestamp when update was created
    pub timestamp: u64,
    /// Ed25519 signature over all fields
    pub signature: Vec<u8>,
    /// Nonce for replay protection
    pub nonce: u64,
}

mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        STANDARD.encode(bytes).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}
