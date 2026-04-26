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

/// Cryptographic proof that a `BlockHeaderCommitment` is the canonical
/// post-Capella Ethereum header for its slot, anchored against an
/// EIP-4788 beacon-block-root reading on the EL.
///
/// At chain tip the validator authenticates via Helios's sync-committee
/// path. For arbitrary historical post-Capella blocks Helios doesn't
/// reach, and we fall back to verifying:
///
/// ```text
/// EIP-4788 storage at `anchor_el_block`  →  anchor_beacon_root
///        ↓ (anchor_eip4788_proof: EIP-1186 storage proof)
/// recent beacon state root (derived from anchor_beacon_root)
///        ↓ (state → historical_summaries[i] SSZ Merkle branch)
/// historical_summaries[i].block_summary_root
///        ↓ (block_summary_root[k] SSZ Merkle branch)
/// past_beacon_block_root  (= the slot containing our target EL block)
///        ↓ (block.body.execution_payload.receipts_root SSZ branch)
/// receipts_root  ←  matches BlockHeaderCommitment.receipts_root
/// ```
///
/// The validator side runs all three Merkle verifications; only the
/// EIP-4788 read requires interaction with an EL endpoint, and that
/// reading is itself authenticated by the storage proof so the
/// validator only trusts its own EL endpoint as far as state-root
/// availability.
///
/// Optional on `IndexedBlockSubmissionTx` — chain-tip submissions can
/// continue to omit it and rely on the existing Helios path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalHeaderProof {
    /// EL block number at which the indexer read EIP-4788 storage to
    /// obtain `anchor_beacon_root`. Must be recent enough that the
    /// validator's own EL endpoint can return its state root.
    pub anchor_el_block: u64,
    /// Beacon block root of the slot at `anchor_el_block` (the value
    /// stored in EIP-4788 contract storage at that EL block).
    pub anchor_beacon_root: [u8; 32],
    /// EIP-1186-format storage proof anchoring `anchor_beacon_root` to
    /// the EL state at `anchor_el_block`. Bincode-serialized to keep
    /// `willow-types` light; consensus deserializes via willow-network.
    pub anchor_eip4788_proof: Vec<u8>,
    /// Slot of the historical block being authenticated. Drives
    /// fork-version dispatch on the verifier side (Capella vs Deneb vs
    /// Electra change SSZ generalized indices for the chain below).
    pub past_beacon_slot: u64,
    /// Beacon block root for `past_beacon_slot`. Intermediate value;
    /// the verifier reproduces it from `state_to_block_root_branch` and
    /// confirms `block_to_receipts_root_branch` resolves under it.
    pub past_beacon_block_root: [u8; 32],
    /// SSZ Merkle branch from the recent beacon state root
    /// (derived from `anchor_beacon_root`'s state_root field) all the
    /// way through `historical_summaries[i].block_summary_root[k]`
    /// down to `past_beacon_block_root`. Decoded shape: bincode of
    /// `Vec<[u8; 32]>` carrying every sibling hash along the path,
    /// in leaf-to-root order. Verifier reconstructs the path indices
    /// from `past_beacon_slot` plus the active fork's generalized
    /// indices.
    pub state_to_block_root_branch: Vec<u8>,
    /// SSZ Merkle branch from `past_beacon_block_root` down to the
    /// `execution_payload.receipts_root` field of the historical
    /// beacon block. Same encoding as above. Verifier confirms
    /// the resolved value equals `BlockHeaderCommitment.receipts_root`.
    pub block_to_receipts_root_branch: Vec<u8>,
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
    /// The actual indexed data (bincode-serialized IndexedBlock).
    pub indexed_data: Vec<u8>,
    /// Block header commitment for L1 verification
    pub block_header: BlockHeaderCommitment,
    /// GKR proofs of correct transformation, one per chunk.
    ///
    /// Empty `Vec` = no transformation proof; consensus falls back to
    /// direct execution or sampling-based re-execution per the
    /// subgrove's execution mode.
    ///
    /// Length 1 = single-chunk submission (the common case: matched
    /// events fit into one circuit batch).
    ///
    /// Length > 1 = chunked: the indexer generated `ceil(N / BATCH_8)`
    /// transformation proofs over consecutive chunks of filter-matched
    /// events. Chunk i's `starting_state_root` chains to chunk i-1's
    /// `output_root` (intra-block continuity), and consensus chain-
    /// links each chunk to its slice of the authenticated `block_logs`.
    #[serde(default)]
    pub gkr_proofs: Vec<GkrProofData>,
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
    #[serde(default)]
    pub completeness_proof: Option<Vec<u8>>,
    /// Optional TEE attestation for TeeExecution mode.
    /// When present, consensus verifies the attestation instead of re-executing.
    #[serde(default)]
    pub tee_attestation: Option<crate::tee::TeeAttestation>,
    /// Optional cryptographic authentication of `block_header` for
    /// historical post-Capella submissions where Helios's sync-committee
    /// path doesn't reach. When present, the validator verifies the
    /// EIP-4788 → beacon `historical_summaries` → execution payload
    /// chain (see [`HistoricalHeaderProof`]) and uses the resulting
    /// `receipts_root` to verify the inclusion proofs. When `None`,
    /// the validator falls back to Helios for header authentication
    /// (the existing chain-tip path).
    #[serde(default)]
    pub historical_header_proof: Option<HistoricalHeaderProof>,
    /// Storage cost for this data
    pub storage_cost: u128,
    /// Timestamp when update was created
    pub timestamp: u64,
    /// Ed25519 signature over all fields
    pub signature: Vec<u8>,
    /// Nonce for replay protection
    pub nonce: u64,
}
