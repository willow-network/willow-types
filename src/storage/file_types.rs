//! Types for file storage in Willow.
//!
//! File storage uses a two-layer verification model:
//! - Layer 1 (Consensus): FileManifest metadata stored in GroveDB with Merkle proofs
//! - Layer 2 (Content): Chunk Merkle tree for verifying downloaded data
//!
//! Actual file data lives on dedicated storage nodes, not on validators.

use serde::{Deserialize, Serialize};

/// Default chunk size for file splitting (256 KB).
pub const DEFAULT_CHUNK_SIZE: u32 = 262_144;

/// Maximum file size (1 GB).
pub const MAX_FILE_SIZE: u64 = 1_073_741_824;

/// Maximum filename length in bytes.
pub const MAX_FILENAME_LENGTH: usize = 255;

/// Estimated bytes for a file manifest stored in GroveDB.
pub const FILE_MANIFEST_ESTIMATED_BYTES: u64 = 500;

/// Minimum stake required to register as a storage node (10,000 WILL).
pub const MIN_STORAGE_NODE_STAKE: u128 = 10_000 * 10u128.pow(18);

/// File manifest stored on-chain in GroveDB.
///
/// Contains metadata and cryptographic commitments for a file stored off-chain
/// on storage nodes. The `content_hash` and `chunk_merkle_root` allow clients
/// to verify downloaded data without trusting the storage node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    /// Unique key for this file within the subgrove.
    pub file_key: String,
    /// Original filename.
    pub filename: String,
    /// MIME type (e.g., "image/png", "application/pdf").
    pub content_type: String,
    /// Total file size in bytes.
    pub total_size: u64,
    /// SHA-256 hash of the complete file.
    pub content_hash: [u8; 32],
    /// Number of chunks the file is split into.
    pub chunk_count: u32,
    /// Size of each chunk in bytes (last chunk may be smaller).
    pub chunk_size: u32,
    /// Merkle root of the chunk hashes (SHA-256 tree).
    pub chunk_merkle_root: [u8; 32],
    /// DID of the file owner.
    pub owner_did: String,
    /// Unix timestamp when the file was stored.
    pub created_at: u64,
    /// Unix timestamp of last metadata update.
    pub updated_at: u64,
    /// Optional encryption metadata (for private file subgroves).
    #[serde(default)]
    pub encryption: Option<FileEncryption>,
}

/// Encryption metadata for a file in a private subgrove.
///
/// Reuses the existing private subgrove key infrastructure (XChaCha20-Poly1305).
/// The file is encrypted before chunking, so storage nodes hold only ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEncryption {
    /// Key epoch from the subgrove's key grant system.
    pub key_epoch: u64,
    /// XChaCha20-Poly1305 nonce (24 bytes).
    pub nonce: [u8; 24],
}

/// Storage node registration stored in GroveDB.
///
/// Storage nodes are a separate node type that stores file chunks and serves
/// them to clients. They stake WILL tokens and earn rewards from file subgroves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageNodeRegistration {
    /// DID of the storage node operator.
    pub node_did: String,
    /// HTTP endpoint for uploads/downloads (e.g., "https://storage.example.com:8080").
    pub endpoint: String,
    /// Advertised storage capacity in bytes.
    pub capacity_bytes: u64,
    /// Amount of WILL tokens staked.
    pub stake_amount: u128,
    /// Unix timestamp when registered.
    pub registered_at: u64,
}

/// Content blocklist entry for moderation.
///
/// Managed by governance (admin DIDs). Files with blocklisted content hashes
/// are rejected at manifest submission and removed from storage nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentBlocklistEntry {
    /// SHA-256 content hash that is blocklisted.
    pub content_hash: [u8; 32],
    /// DID of the admin who added this entry.
    pub blocked_by: String,
    /// Reason for blocking.
    pub reason: String,
    /// Unix timestamp when blocked.
    pub blocked_at: u64,
}

/// Content report submitted by any DID for governance review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentReport {
    /// SHA-256 content hash being reported.
    pub content_hash: [u8; 32],
    /// DID of the reporter.
    pub reporter_did: String,
    /// Reason for the report.
    pub reason: String,
    /// Unix timestamp of the report.
    pub reported_at: u64,
}

/// Tracks which storage nodes hold which files.
///
/// Created when a storage node submits a successful availability proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeFileAssignment {
    /// DID of the storage node.
    pub node_did: String,
    /// Subgrove ID.
    pub subgrove_id: String,
    /// File key.
    pub file_key: String,
    /// Unix timestamp when the assignment was recorded.
    pub assigned_at: u64,
}

/// Result of a storage availability proof challenge-response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageAvailabilityProof {
    /// DID of the storage node.
    pub node_did: String,
    /// File key being proven.
    pub file_key: String,
    /// Subgrove ID containing the file.
    pub subgrove_id: String,
    /// Index of the challenged chunk.
    pub chunk_index: u32,
    /// SHA-256 hash of the challenged chunk (proves possession).
    pub chunk_hash: [u8; 32],
    /// Merkle proof path from chunk to chunk_merkle_root.
    pub merkle_proof: Vec<[u8; 32]>,
    /// Unix timestamp of the proof.
    pub timestamp: u64,
}

/// Default reward per epoch for file storage (100 WILL in smallest unit).
pub const DEFAULT_STORAGE_REWARD_PER_EPOCH: u128 = 100 * 10u128.pow(18);

/// Default epoch length for storage rewards (every 100 blocks).
pub const DEFAULT_STORAGE_EPOCH_LENGTH: u64 = 100;

/// Number of blocks a storage node has to respond to a challenge.
pub const CHALLENGE_RESPONSE_WINDOW: u64 = 50;

/// Amount slashed for missing a challenge (100 WILL).
pub const CHALLENGE_SLASH_AMOUNT: u128 = 100 * 10u128.pow(18);

/// Number of challenges issued per block.
pub const CHALLENGES_PER_BLOCK: u32 = 3;

/// A storage challenge issued to a node to prove it still holds a file chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageChallenge {
    /// Unique challenge identifier (SHA-256 hash).
    pub challenge_id: [u8; 32],
    /// DID of the challenged storage node.
    pub node_did: String,
    /// Subgrove ID of the file.
    pub subgrove_id: String,
    /// File key being challenged.
    pub file_key: String,
    /// Index of the chunk to prove.
    pub chunk_index: u32,
    /// Block height when the challenge was issued.
    pub issued_at_block: u64,
    /// Block height by which the node must respond.
    pub deadline_block: u64,
    /// Whether the node has responded with a valid proof.
    pub responded: bool,
}
