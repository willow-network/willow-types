use serde::{Deserialize, Serialize};

use super::gkr_proof_types::GkrPublicInputs;

/// Transaction to submit indexed data for a range of blocks.
///
/// This is the primary transaction type for indexers submitting their work.
/// It includes compressed state changes and cryptographic proofs that
/// enable verification without re-indexing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubgroveUpdateTx {
    /// DID of the indexer submitting this update.
    pub indexer_did: String,
    /// The subgrove this update applies to.
    pub subgrove_id: String,
    /// Range of Ethereum blocks covered (inclusive).
    pub block_range: (u64, u64),
    /// Compressed state changes (entities created/updated/deleted).
    pub state_diff: CompressedStateDiff,
    /// Cryptographic proofs for trustless verification.
    pub proofs: UpdateProofs,
    /// Time taken to index this range (for performance tracking).
    pub indexing_time_ms: u64,
    /// Cryptographic signature from the indexer (Ed25519, 64 bytes).
    pub signature: Vec<u8>,
    /// ID of the public key used for signing (e.g., "did:willow:indexer#key-1").
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Compressed representation of state changes from indexing.
///
/// Contains the delta of entities that were created, updated, or deleted
/// while processing the specified block range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedStateDiff {
    /// Compression algorithm used.
    pub compression: CompressionType,
    /// Compressed state diff data.
    pub data: Vec<u8>,
    /// Size of data before compression (for validation).
    pub uncompressed_size: u64,
    /// Number of entities affected by this update.
    pub entity_count: u64,
    /// Merkle root of the subgrove state before this update.
    pub root_before: [u8; 32],
    /// Merkle root of the subgrove state after this update.
    pub root_after: [u8; 32],
}

/// Compression algorithm for state diffs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompressionType {
    /// No compression.
    None,
    /// Zstandard compression (recommended for best ratio).
    Zstd,
    /// Gzip compression.
    Gzip,
}

/// Collection of proofs accompanying an indexer update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProofs {
    /// Proofs that events exist in the specified Ethereum blocks.
    pub event_proofs: Vec<EventInclusionProof>,
    /// Proof of correct transformation execution.
    pub execution_proof: ExecutionProof,
}

/// Proof that an Ethereum event exists in a specific block.
///
/// Uses Merkle Patricia Trie (MPT) proofs to cryptographically prove
/// that a log/event was included in a transaction receipt, which was
/// included in a block with a known receipts root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventInclusionProof {
    /// Ethereum block number containing this event.
    pub block_number: u64,
    /// Hash of the Ethereum block.
    pub block_hash: [u8; 32],
    /// RLP-encoded block header.
    pub block_header: Vec<u8>,
    /// Hash of the transaction emitting the event.
    pub tx_hash: [u8; 32],
    /// Index of the transaction within the block.
    pub tx_index: u64,
    /// RLP-encoded transaction receipt.
    pub receipt: Vec<u8>,
    /// Merkle Patricia Trie proof of receipt inclusion.
    pub receipt_proof: MptProof,
    /// Index of the log within the receipt.
    pub log_index: u64,
    /// Address of the contract that emitted the event.
    pub contract_address: [u8; 20],
    /// Event topics (first topic is usually the event signature).
    pub topics: Vec<[u8; 32]>,
    /// ABI-encoded event data.
    pub data: Vec<u8>,
}

/// Merkle Patricia Trie proof for Ethereum state/receipt verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MptProof {
    /// Key in the trie (e.g., RLP-encoded transaction index).
    pub key: Vec<u8>,
    /// Value being proven (e.g., RLP-encoded receipt).
    pub value: Vec<u8>,
    /// Proof nodes from root to the leaf.
    pub proof_nodes: Vec<Vec<u8>>,
}

/// Proof that a transaction exists in a specific block.
///
/// Mirrors `EventInclusionProof` but for the transactions MPT (root
/// = `transactions_root`) instead of the receipts MPT. Used by
/// completeness-proof verification to authenticate every tx in a
/// block against the light-client-verified header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInclusionProof {
    /// Index of the transaction within the block.
    pub tx_index: u64,
    /// Raw RLP-encoded transaction as stored in the MPT leaf.
    /// For EIP-2718 typed txs this includes the leading type byte.
    pub raw_rlp: Vec<u8>,
    /// Merkle Patricia Trie proof of tx inclusion at `tx_index`.
    pub mpt_proof: MptProof,
}

/// Proof that transformation logic was executed correctly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionProof {
    /// Phase 1: Deterministic re-execution proof.
    ///
    /// Allows validators to re-run the same WASM with the same inputs
    /// to verify the output matches.
    Reproducible {
        /// SHA256 hash of the WASM module used.
        wasm_hash: [u8; 32],
        /// Name of the handler function called (e.g., "handleTransfer").
        handler_name: String,
        /// Deterministic seed for reproducible execution.
        random_seed: [u8; 32],
    },

    /// GKR cryptographic proof of correct transformation.
    ///
    /// Uses the GKR (Goldwasser-Kalai-Rothblum) protocol to prove that
    /// the indexer correctly executed the transformation without needing
    /// to re-execute. Verification is fast (logarithmic in computation size).
    GkrProof {
        /// The serialized GKR proof bytes.
        proof: Vec<u8>,
        /// Public inputs binding the proof to specific input/output data.
        public_inputs: GkrPublicInputs,
        /// Hash of the verification key used.
        verification_key_hash: [u8; 32],
        /// Whether GPU acceleration was used for proving.
        gpu_accelerated: bool,
    },

    /// Generic zero-knowledge proof (for future proof systems).
    ///
    /// Cryptographic proof that transformation was correct without
    /// needing to re-execute. Kept for forward compatibility.
    ZkSnark {
        /// The zero-knowledge proof bytes.
        proof: Vec<u8>,
        /// Public inputs for verification.
        public_inputs: Vec<u8>,
        /// Hash of the verification key.
        verification_key_hash: [u8; 32],
    },

    /// WARP fold-step proof of correct transformation (folding scheme).
    ///
    /// Cryptographic proof produced by `willow-folding` (eprint 2025/753).
    /// Each submission carries a one-step fold message linking the new
    /// per-block claims to the running accumulator. The decider runs
    /// rarely (e.g., per epoch) to settle the accumulated claim.
    WarpProof {
        /// The serialized WARP fold-step proof bytes.
        proof: Vec<u8>,
        /// Public inputs binding the proof to specific output data and
        /// to the prior/next accumulator state.
        public_inputs: super::warp_proof_types::WarpPublicInputs,
        /// Codeword `log_n` used by this proof. Must match the subgrove's
        /// `WarpExecution.codeword_log_n` declared at registration.
        codeword_log_n: u8,
        /// Construction 7.2 OOD sample count used by this proof.
        n_ood: u8,
        /// Construction 7.2 shift-query count used by this proof.
        n_shifts: u8,
        /// Whether GPU acceleration was used for proving.
        gpu_accelerated: bool,
    },
}
