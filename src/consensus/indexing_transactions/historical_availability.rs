// ============================================================================
// Historical Data Availability Management
// ============================================================================

use serde::{Deserialize, Serialize};

/// Transaction for an indexer to gracefully withdraw from serving historical data.
///
/// Indexers should submit this transaction BEFORE stopping service to avoid
/// being slashed for unavailability. This allows:
/// - Planned maintenance/shutdown
/// - Storage pruning when limits are reached
/// - Economic decisions to stop serving unprofitable data
///
/// After withdrawal, the indexer is removed from the checkpoint's provider list
/// and will not receive queries or be subject to availability checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawHistoricalAvailabilityTx {
    /// DID of the indexer withdrawing availability.
    pub indexer_did: String,
    /// The checkpoint to withdraw from.
    pub checkpoint_id: [u8; 32],
    /// Optional reason for withdrawal (for transparency).
    pub reason: Option<String>,
    /// Cryptographic signature from the indexer.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction for an indexer to prove they still have historical data available.
///
/// Indexers must submit these proofs periodically to remain eligible for query
/// routing. The proof contains a response to a deterministic challenge query
/// derived from the current block, proving they have the actual data.
///
/// # Proof Requirements
///
/// - Must be submitted at least once per `proof_interval_seconds` (default: 1 hour)
/// - Challenge query is deterministic: `hash(block_hash, checkpoint_id, proof_round)`
/// - Response must include valid Merkle proof against checkpoint's state_root
///
/// # Consequences of Not Proving
///
/// - No proof for `proof_interval`: Stop receiving query routing (soft penalty)
/// - No proof for `days_until_slash` days: Start getting slashed daily (hard penalty)
/// - Can always recover by submitting a valid proof (unless fully slashed)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailabilityProofTx {
    /// DID of the indexer submitting the proof.
    pub indexer_did: String,
    /// The checkpoint being proven.
    pub checkpoint_id: [u8; 32],
    /// The challenge query path (derived from block hash).
    pub challenge_path: Vec<Vec<u8>>,
    /// The challenge key.
    pub challenge_key: Vec<u8>,
    /// The response value.
    pub response_value: Vec<u8>,
    /// Merkle proof that the response is correct against the checkpoint state_root.
    pub merkle_proof: Vec<u8>,
    /// Cryptographic signature from the indexer.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Configuration for the periodic proof system.
///
/// This Filecoin-inspired approach uses proactive proofs rather than
/// reactive complaints to ensure data availability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalAvailabilityConfig {
    /// How often indexers must submit availability proofs (in seconds).
    /// Default: 1 hour (3600 seconds).
    #[serde(default = "default_proof_interval_seconds")]
    pub proof_interval_seconds: u64,

    /// Grace period after checkpoint submission before proofs are required.
    /// Allows indexer time to sync and start serving.
    /// Default: 1 hour (3600 seconds).
    #[serde(default = "default_proof_grace_period")]
    pub proof_grace_period_seconds: u64,

    /// Number of days without proofs before slashing begins.
    /// During this period, indexer just stops receiving queries (soft penalty).
    /// Default: 3 days.
    #[serde(default = "default_days_until_slash")]
    pub days_until_slash: u32,

    /// Percentage of stake to slash per day once slashing begins.
    /// Default: 1% (100 basis points) per day.
    #[serde(default = "default_daily_slash_percent")]
    pub daily_slash_percent: u32,

    /// Maximum percentage of stake that can be slashed for unavailability.
    /// After this, indexer is just removed. Default: 10% (1000 basis points).
    #[serde(default = "default_max_slash_percent")]
    pub max_slash_percent: u32,
}

fn default_proof_interval_seconds() -> u64 {
    3600 // 1 hour
}

fn default_proof_grace_period() -> u64 {
    3600 // 1 hour
}

fn default_days_until_slash() -> u32 {
    3 // 3 days of no proofs before slashing starts
}

fn default_daily_slash_percent() -> u32 {
    100 // 1% per day = 100 basis points
}

fn default_max_slash_percent() -> u32 {
    1000 // 10% max = 1000 basis points
}

impl Default for HistoricalAvailabilityConfig {
    fn default() -> Self {
        Self {
            proof_interval_seconds: default_proof_interval_seconds(),
            proof_grace_period_seconds: default_proof_grace_period(),
            days_until_slash: default_days_until_slash(),
            daily_slash_percent: default_daily_slash_percent(),
            max_slash_percent: default_max_slash_percent(),
        }
    }
}

/// Status of an indexer's availability proofs for a checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AvailabilityStatus {
    /// Within grace period after initial declaration, no proofs required yet.
    GracePeriod {
        /// When the grace period ends (Unix timestamp).
        ends_at: u64,
    },
    /// Actively proving, eligible for query routing.
    Active {
        /// Timestamp of the last valid proof.
        last_proof_at: u64,
    },
    /// Proofs are stale, not receiving queries but not yet slashing.
    Stale {
        /// Timestamp of the last valid proof.
        last_proof_at: u64,
        /// When slashing will begin if no proof is submitted.
        slash_begins_at: u64,
    },
    /// Being slashed daily for extended unavailability.
    Slashing {
        /// Timestamp of the last valid proof.
        last_proof_at: u64,
        /// Total amount slashed so far (in basis points of original stake).
        total_slashed_bps: u32,
        /// Timestamp of the last slash event.
        last_slash_at: u64,
    },
    /// Gracefully withdrawn by the indexer.
    Withdrawn {
        /// When the withdrawal was processed.
        withdrawn_at: u64,
    },
}

impl AvailabilityStatus {
    /// Returns true if this provider should receive query routing.
    pub fn is_routable(&self) -> bool {
        matches!(
            self,
            AvailabilityStatus::GracePeriod { .. } | AvailabilityStatus::Active { .. }
        )
    }

    /// Returns true if this provider is being slashed.
    pub fn is_slashing(&self) -> bool {
        matches!(self, AvailabilityStatus::Slashing { .. })
    }

    /// Returns the last proof timestamp, if any.
    pub fn last_proof_at(&self) -> Option<u64> {
        match self {
            AvailabilityStatus::GracePeriod { .. } => None,
            AvailabilityStatus::Active { last_proof_at } => Some(*last_proof_at),
            AvailabilityStatus::Stale { last_proof_at, .. } => Some(*last_proof_at),
            AvailabilityStatus::Slashing { last_proof_at, .. } => Some(*last_proof_at),
            AvailabilityStatus::Withdrawn { .. } => None,
        }
    }

    /// Update status based on a new valid proof submission.
    pub fn record_proof(&mut self, timestamp: u64) {
        *self = AvailabilityStatus::Active {
            last_proof_at: timestamp,
        };
    }

    /// Update status based on current time and config.
    /// Returns the amount to slash (in basis points) if slashing should occur.
    pub fn update_status(&mut self, now: u64, config: &HistoricalAvailabilityConfig) -> u32 {
        match self {
            AvailabilityStatus::GracePeriod { ends_at } => {
                if now >= *ends_at {
                    // Grace period ended without any proof - go to stale
                    let slash_begins_at = *ends_at + (config.days_until_slash as u64 * 86400);
                    *self = AvailabilityStatus::Stale {
                        last_proof_at: *ends_at,
                        slash_begins_at,
                    };
                }
                0
            }
            AvailabilityStatus::Active { last_proof_at } => {
                let proof_age = now.saturating_sub(*last_proof_at);
                if proof_age > config.proof_interval_seconds {
                    // Proof is stale
                    let slash_begins_at = *last_proof_at + (config.days_until_slash as u64 * 86400);
                    *self = AvailabilityStatus::Stale {
                        last_proof_at: *last_proof_at,
                        slash_begins_at,
                    };
                }
                0
            }
            AvailabilityStatus::Stale {
                last_proof_at,
                slash_begins_at,
            } => {
                if now >= *slash_begins_at {
                    // Time to start slashing
                    *self = AvailabilityStatus::Slashing {
                        last_proof_at: *last_proof_at,
                        total_slashed_bps: config.daily_slash_percent,
                        last_slash_at: now,
                    };
                    config.daily_slash_percent
                } else {
                    0
                }
            }
            AvailabilityStatus::Slashing {
                last_proof_at: _,
                total_slashed_bps,
                last_slash_at,
            } => {
                // Check if a day has passed since last slash
                let day_seconds = 86400u64;
                if now >= *last_slash_at + day_seconds {
                    let days_since_slash = (now - *last_slash_at) / day_seconds;
                    let slash_amount = (days_since_slash as u32) * config.daily_slash_percent;
                    let new_total = (*total_slashed_bps).saturating_add(slash_amount);

                    if new_total >= config.max_slash_percent {
                        // Max slash reached - could transition to removed state
                        *total_slashed_bps = config.max_slash_percent;
                    } else {
                        *total_slashed_bps = new_total;
                    }
                    *last_slash_at = now;
                    slash_amount.min(config.max_slash_percent - (*total_slashed_bps - slash_amount))
                } else {
                    0
                }
            }
            AvailabilityStatus::Withdrawn { .. } => 0,
        }
    }
}

impl Default for AvailabilityStatus {
    fn default() -> Self {
        AvailabilityStatus::GracePeriod {
            ends_at: 0, // Will be set properly on creation
        }
    }
}

/// Helper to generate a deterministic challenge for availability proofs.
///
/// The challenge is derived from the block hash and checkpoint ID, ensuring
/// that indexers can't predict future challenges and must actually have the data.
///
/// # Returns
///
/// A tuple of (path_segments, key) where:
/// - `path_segments`: Vec of path segments (e.g., `[b"blocks"]`)
/// - `key`: The key to query at that path (the block number as little-endian bytes)
///
/// The proof must be generated from the subgrove's data subtree at
/// `subgrove_data/{subgrove_id}/` and the path is relative to that subtree.
pub fn generate_availability_challenge(
    block_hash: &[u8; 32],
    checkpoint_id: &[u8; 32],
    checkpoint_block_range: (u64, u64),
) -> (Vec<Vec<u8>>, Vec<u8>) {
    use sha2::{Digest, Sha256};

    // Combine inputs to create deterministic seed
    let mut hasher = Sha256::new();
    hasher.update(block_hash);
    hasher.update(checkpoint_id);
    hasher.update(checkpoint_block_range.0.to_le_bytes());
    hasher.update(checkpoint_block_range.1.to_le_bytes());
    let seed: [u8; 32] = hasher.finalize().into();

    // Use seed to derive a block number within the checkpoint range
    let range_size = checkpoint_block_range.1 - checkpoint_block_range.0 + 1;
    let block_offset = u64::from_le_bytes(seed[0..8].try_into().unwrap()) % range_size;
    let challenge_block = checkpoint_block_range.0 + block_offset;

    // The path is ["blocks"] relative to the subgrove's data root
    // The key is the block number (as little-endian bytes, matching storage format)
    let path_segments = vec![b"blocks".to_vec()];
    let key = challenge_block.to_le_bytes().to_vec();

    (path_segments, key)
}
