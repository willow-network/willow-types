//! Type definitions for state synchronization.
//!
//! Contains all the data types used for state sync including sync info,
//! snapshot chunks, metadata, configuration, and messages.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;

/// Enhanced state sync information with verification data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSyncInfo {
    /// Current block height
    pub current_height: u64,
    /// Latest state root hash (GroveDB root)
    pub state_root: Vec<u8>,
    /// Snapshot height for state sync
    pub snapshot_height: u64,
    /// Merkle root of the snapshot (GroveDB root)
    pub snapshot_root: Vec<u8>,
    /// Merkle root of all chunk hashes (for verifying individual chunks)
    pub chunks_merkle_root: Vec<u8>,
    /// Number of chunks in the snapshot
    pub total_chunks: u32,
    /// Chunk size in bytes
    pub chunk_size: u32,
    /// Snapshot creation timestamp
    pub snapshot_timestamp: u64,
    /// Validator signatures on snapshot
    pub validator_signatures: Vec<ValidatorSignature>,
}

/// Validator signature on snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSignature {
    pub validator_id: String,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

/// Snapshot chunk with verification data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotChunk {
    pub height: u64,
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub data: Vec<u8>,
    pub hash: Vec<u8>,
    pub merkle_proof: Vec<Vec<u8>>,
}

/// Snapshot metadata for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    pub height: u64,
    pub state_root: Vec<u8>,
    /// Merkle root of all chunk hashes (for verifying individual chunks)
    pub chunks_merkle_root: Vec<u8>,
    pub chunk_count: u32,
    pub chunk_size: u32,
    pub created_at: u64,
    pub chunks_stored: HashSet<u32>,
    pub verification_status: VerificationStatus,
}

/// Verification status of snapshot
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VerificationStatus {
    Pending,
    Verified,
    Failed(String),
}

/// State sync configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSyncConfig {
    /// Maximum chunk size in bytes
    pub max_chunk_size: u32,
    /// Minimum number of validator signatures required
    pub min_validator_signatures: u32,
    /// Maximum age of snapshot in seconds
    pub max_snapshot_age_secs: u64,
    /// Maximum number of parallel chunk downloads
    pub max_parallel_downloads: u32,
    /// Timeout for chunk requests in seconds
    pub chunk_request_timeout_secs: u64,
    /// Maximum retries for failed chunks
    pub max_chunk_retries: u32,
    /// Interval between sync attempts in seconds
    pub sync_attempt_interval_secs: u64,
    /// Enable incremental sync
    pub enable_incremental_sync: bool,
}

impl Default for StateSyncConfig {
    fn default() -> Self {
        Self {
            max_chunk_size: 1024 * 1024, // 1MB
            min_validator_signatures: 3,
            max_snapshot_age_secs: 3600, // 1 hour
            max_parallel_downloads: 10,
            chunk_request_timeout_secs: 30,
            max_chunk_retries: 3,
            sync_attempt_interval_secs: 60,
            enable_incremental_sync: true,
        }
    }
}

/// Current sync status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    pub is_syncing: bool,
    pub current_height: u64,
    pub target_height: u64,
    pub chunks_downloaded: u32,
    pub total_chunks: u32,
    pub sync_start_time: Option<u64>, // Unix timestamp
    pub last_chunk_time: Option<u64>, // Unix timestamp
    pub failed_chunks: HashSet<u32>,
}

/// Peer scoring for sync reliability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerScore {
    pub peer_id: String,
    pub successful_chunks: u32,
    pub failed_chunks: u32,
    pub average_response_time: Duration,
    pub last_seen: u64, // Unix timestamp
}

/// State sync protocol messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateSyncMessage {
    /// Request state sync info
    RequestSyncInfo,
    /// Response with sync info
    SyncInfoResponse(StateSyncInfo),
    /// Request state snapshot chunk
    RequestChunk { height: u64, chunk_index: u32 },
    /// State snapshot chunk response
    ChunkResponse(SnapshotChunk),
    /// Request snapshot metadata
    RequestSnapshotMetadata { height: u64 },
    /// Snapshot metadata response
    SnapshotMetadataResponse(SnapshotMetadata),
    /// Error response
    ErrorResponse { message: String },
}

impl StateSyncMessage {
    /// Convert to bytes for transmission
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::WillowError> {
        serde_json::to_vec(self).map_err(|e| {
            crate::error::WillowError::StateSyncError(format!("Serialization error: {}", e))
        })
    }

    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, crate::error::WillowError> {
        serde_json::from_slice(data).map_err(|e| {
            crate::error::WillowError::StateSyncError(format!("Deserialization error: {}", e))
        })
    }
}
