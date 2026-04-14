// ============================================================================
// Historical Indexing - Checkpoint-based bootstrapping for large datasets
// ============================================================================

use serde::{Deserialize, Serialize};

use super::historical_availability::{AvailabilityStatus, HistoricalAvailabilityConfig};

/// Default challenge window in blocks for standard checkpoints.
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 1000;

/// Shorter challenge window in blocks for TEE-attested checkpoints.
pub const TEE_CHALLENGE_WINDOW_BLOCKS: u64 = 500;

/// Transaction to submit a historical indexing checkpoint.
///
/// Used when an indexer completes historical indexing of a subgrove.
/// Instead of sending all historical data through consensus (which would
/// be impractical for large datasets), the indexer submits only a checkpoint
/// containing the final state root and an intermediate hashes commitment.
///
/// The checkpoint enters a challenge window (optimistic acceptance).
/// If unchallenged, it becomes trusted. If challenged, a bisection dispute
/// narrows to a single block for cheap adjudication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalCheckpointTx {
    /// DID of the indexer submitting this checkpoint.
    pub indexer_did: String,
    /// The subgrove this checkpoint applies to.
    pub subgrove_id: String,
    /// Block range covered by this checkpoint (start_block, end_block inclusive).
    /// start_block is typically the subgrove's configured start block.
    /// end_block is the last block processed in historical sync.
    pub block_range: (u64, u64),
    /// Merkle root of the GroveDB state after processing all historical data.
    /// This commits to all indexed entities and aggregated state.
    pub state_root: [u8; 32],
    /// Commitment to intermediate accumulated transformation hashes.
    ///
    /// This is the Merkle root of a binary SHA256 tree built over H_0..H_N where:
    /// - H_0 = [0; 32]
    /// - H_B = SHA256(H_{B-1} || SHA256(canonical_transform_output(block_B_events)))
    ///
    /// This enables bisection disputes to cheaply prove disagreement at any block.
    pub intermediate_hashes_commitment: [u8; 32],
    /// Hash of the subgrove configuration used for indexing.
    /// Ensures all indexers used the same transformation rules.
    pub subgrove_config_hash: [u8; 32],
    /// Commitment to the L1 block headers processed.
    /// SHA256(concat(block_number || block_hash for each block)).
    pub block_headers_commitment: [u8; 32],
    /// Total number of events/entities indexed.
    pub total_entities: u64,
    /// Total storage size of the indexed data in bytes.
    pub storage_size: u64,
    /// Timestamp when the checkpoint was created.
    pub timestamp: u64,
    /// Optional TEE attestation proving the checkpoint was computed in a TEE.
    ///
    /// When present and valid, consensus can give the checkpoint a shorter challenge
    /// window. The attestation must be from an approved enclave and include a
    /// data_hash matching the state_root.
    ///
    /// Only used when the subgrove's `checkpoint_verification` has `required_tee` set.
    #[serde(default)]
    pub tee_attestation: Option<crate::tee::TeeAttestation>,
    /// HTTP endpoint where this indexer will serve historical queries for this checkpoint.
    ///
    /// When provided, the indexer declares availability to serve historical queries
    /// with proofs against this checkpoint's state_root. The endpoint should be
    /// reachable by validators for query routing.
    ///
    /// Format: "http://host:port" or "https://host:port"
    #[serde(default)]
    pub historical_query_endpoint: Option<String>,
    /// Cryptographic signature from the indexer.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Verification status of a historical checkpoint.
///
/// Uses optimistic acceptance: checkpoints enter a challenge window and become
/// trusted if unchallenged. TEE-attested checkpoints get a shorter window.
/// Checkpoints can be challenged via bisection disputes at any time during
/// the challenge window.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CheckpointVerification {
    /// Checkpoint is in its challenge window, awaiting potential disputes.
    PendingChallenge {
        /// Block height at which the challenge window expires.
        challenge_deadline: u64,
    },
    /// Checkpoint has passed its challenge window and is trusted.
    Trusted,
    /// Checkpoint is under active bisection dispute.
    Disputed {
        /// ID of the active dispute.
        dispute_id: [u8; 32],
    },
    /// Checkpoint was invalidated by a dispute resolution.
    Invalidated {
        /// ID of the dispute that invalidated it.
        dispute_id: [u8; 32],
    },
    /// Checkpoint was verified via TEE hardware attestation (shorter challenge window).
    TeeAttested {
        /// The TEE type that provided the attestation.
        tee_type: crate::tee::TeeType,
        /// The enclave identifier (PCR0 for Nitro, MRENCLAVE for SGX).
        enclave_hash: Vec<u8>,
        /// Block height when the TEE verification was performed.
        verified_at: u64,
        /// Block height at which the challenge window expires.
        challenge_deadline: u64,
    },
}

impl Default for CheckpointVerification {
    fn default() -> Self {
        CheckpointVerification::PendingChallenge {
            challenge_deadline: 0,
        }
    }
}

impl CheckpointVerification {
    /// Returns true if the checkpoint is trusted at the given block height.
    ///
    /// A checkpoint is trusted if:
    /// - It is `Trusted`
    /// - It is `PendingChallenge` and the deadline has passed
    /// - It is `TeeAttested` and the deadline has passed
    pub fn is_trusted_at(&self, current_block: u64) -> bool {
        match self {
            CheckpointVerification::Trusted => true,
            CheckpointVerification::PendingChallenge { challenge_deadline } => {
                current_block >= *challenge_deadline
            }
            CheckpointVerification::TeeAttested {
                challenge_deadline, ..
            } => current_block >= *challenge_deadline,
            CheckpointVerification::Disputed { .. } => false,
            CheckpointVerification::Invalidated { .. } => false,
        }
    }

    /// Returns true if the checkpoint can be challenged at the given block height.
    pub fn is_challengeable(&self, current_block: u64) -> bool {
        match self {
            CheckpointVerification::PendingChallenge { challenge_deadline } => {
                current_block < *challenge_deadline
            }
            CheckpointVerification::TeeAttested {
                challenge_deadline, ..
            } => current_block < *challenge_deadline,
            _ => false,
        }
    }

    /// Returns true if this is a TEE-verified checkpoint.
    pub fn is_tee_verified(&self) -> bool {
        matches!(self, CheckpointVerification::TeeAttested { .. })
    }

    /// Get the TEE type if this is TEE verified.
    pub fn tee_type(&self) -> Option<crate::tee::TeeType> {
        match self {
            CheckpointVerification::TeeAttested { tee_type, .. } => Some(*tee_type),
            _ => None,
        }
    }

    /// Get the enclave hash if this is TEE verified.
    pub fn enclave_hash(&self) -> Option<&[u8]> {
        match self {
            CheckpointVerification::TeeAttested { enclave_hash, .. } => Some(enclave_hash),
            _ => None,
        }
    }
}

/// Information about an indexer that serves historical data for a checkpoint.
///
/// Validators use this to route historical queries to available indexers.
/// The provider's availability status is tracked based on periodic proof submissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalDataProvider {
    /// DID of the indexer providing this data.
    pub indexer_did: String,
    /// HTTP endpoint for querying this data.
    pub endpoint: String,
    /// Block height when this availability was declared.
    pub declared_at: u64,
    /// Current availability status based on proof submissions.
    pub status: AvailabilityStatus,
    /// Number of successful queries served.
    #[serde(default)]
    pub successful_queries: u64,
    /// Number of failed queries.
    #[serde(default)]
    pub failed_queries: u64,
}

impl HistoricalDataProvider {
    /// Creates a new provider record in GracePeriod status.
    pub fn new(
        indexer_did: String,
        endpoint: String,
        declared_at: u64,
        grace_period_seconds: u64,
    ) -> Self {
        Self {
            indexer_did,
            endpoint,
            declared_at,
            status: AvailabilityStatus::GracePeriod {
                ends_at: declared_at + grace_period_seconds,
            },
            successful_queries: 0,
            failed_queries: 0,
        }
    }

    /// Returns true if this provider should receive query routing.
    pub fn is_routable(&self) -> bool {
        self.status.is_routable()
    }

    /// Records a successful query to this provider.
    pub fn record_success(&mut self) {
        self.successful_queries = self.successful_queries.saturating_add(1);
    }

    /// Records a failed query to this provider.
    pub fn record_failure(&mut self) {
        self.failed_queries = self.failed_queries.saturating_add(1);
    }

    /// Updates status when a valid availability proof is received.
    pub fn record_proof(&mut self, proof_timestamp: u64) {
        self.status = AvailabilityStatus::Active {
            last_proof_at: proof_timestamp,
        };
    }

    /// Updates status when the provider withdraws.
    pub fn withdraw(&mut self, withdrawn_at: u64) {
        self.status = AvailabilityStatus::Withdrawn { withdrawn_at };
    }

    /// Checks and updates status based on current time and config.
    /// Returns the amount to slash (in basis points) if slashing should occur.
    pub fn update_status(
        &mut self,
        current_time: u64,
        config: &HistoricalAvailabilityConfig,
    ) -> u32 {
        let seconds_per_day = 86400u64;

        // Clone the status to avoid borrow issues
        let current_status = self.status.clone();

        match current_status {
            AvailabilityStatus::GracePeriod { ends_at } => {
                if current_time >= ends_at {
                    // Grace period ended without any proof - mark as stale
                    let slash_begins_at =
                        current_time + (config.days_until_slash as u64 * seconds_per_day);
                    self.status = AvailabilityStatus::Stale {
                        last_proof_at: self.declared_at,
                        slash_begins_at,
                    };
                }
                0
            }
            AvailabilityStatus::Active { last_proof_at } => {
                if current_time > last_proof_at + config.proof_interval_seconds {
                    // Proof is stale
                    let slash_begins_at =
                        last_proof_at + (config.days_until_slash as u64 * seconds_per_day);
                    self.status = AvailabilityStatus::Stale {
                        last_proof_at,
                        slash_begins_at,
                    };
                }
                0
            }
            AvailabilityStatus::Stale {
                last_proof_at,
                slash_begins_at,
            } => {
                if current_time >= slash_begins_at {
                    // Begin slashing
                    self.status = AvailabilityStatus::Slashing {
                        last_proof_at,
                        total_slashed_bps: config.daily_slash_percent,
                        last_slash_at: current_time,
                    };
                    config.daily_slash_percent
                } else {
                    0
                }
            }
            AvailabilityStatus::Slashing {
                last_proof_at,
                total_slashed_bps,
                last_slash_at,
            } => {
                // Check if a day has passed since last slash
                if current_time >= last_slash_at + seconds_per_day {
                    let new_total = total_slashed_bps.saturating_add(config.daily_slash_percent);
                    if new_total >= config.max_slash_percent {
                        // Max slashing reached - mark as withdrawn (forced)
                        self.status = AvailabilityStatus::Withdrawn {
                            withdrawn_at: current_time,
                        };
                        config.max_slash_percent.saturating_sub(total_slashed_bps)
                    } else {
                        self.status = AvailabilityStatus::Slashing {
                            last_proof_at,
                            total_slashed_bps: new_total,
                            last_slash_at: current_time,
                        };
                        config.daily_slash_percent
                    }
                } else {
                    0
                }
            }
            AvailabilityStatus::Withdrawn { .. } => 0,
        }
    }
}

/// Stored checkpoint record with verification status.
///
/// This is what gets stored in consensus state after a checkpoint is submitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCheckpoint {
    /// The original checkpoint transaction data.
    pub checkpoint: HistoricalCheckpointTx,
    /// Unique ID for this checkpoint (hash of the transaction).
    pub checkpoint_id: [u8; 32],
    /// Current verification status.
    pub verification: CheckpointVerification,
    /// Block height when the checkpoint was submitted.
    pub submitted_at_block: u64,
    /// Block height when real-time indexing can begin (checkpoint end_block + 1).
    pub realtime_start_block: u64,
    /// Indexers who serve historical data for this checkpoint.
    ///
    /// When a checkpoint is submitted with a `historical_query_endpoint`, the
    /// submitting indexer is automatically added. Additional indexers can
    /// declare availability by submitting their own checkpoints for the same
    /// block range with matching state roots.
    #[serde(default)]
    pub historical_data_providers: Vec<HistoricalDataProvider>,
}

impl StoredCheckpoint {
    /// Returns true if this checkpoint is trusted at the given block height.
    ///
    /// A checkpoint is trusted if its challenge window has expired without
    /// a dispute, or if it has been through a successful dispute resolution.
    pub fn is_trusted_at(&self, current_block: u64) -> bool {
        self.verification.is_trusted_at(current_block)
    }

    /// Returns true if this checkpoint was verified via TEE attestation.
    pub fn is_tee_verified(&self) -> bool {
        self.verification.is_tee_verified()
    }

    /// Returns the list of routable historical data providers.
    /// Only providers in GracePeriod or Active status are routable.
    pub fn available_providers(&self) -> Vec<&HistoricalDataProvider> {
        self.historical_data_providers
            .iter()
            .filter(|p| p.is_routable())
            .collect()
    }

    /// Returns true if any provider is available to serve historical queries.
    pub fn has_historical_data_available(&self) -> bool {
        self.historical_data_providers
            .iter()
            .any(|p| p.is_routable())
    }

    /// Adds or updates a historical data provider.
    pub fn upsert_provider(
        &mut self,
        indexer_did: &str,
        endpoint: &str,
        block_height: u64,
        grace_period_seconds: u64,
    ) {
        if let Some(existing) = self
            .historical_data_providers
            .iter_mut()
            .find(|p| p.indexer_did == indexer_did)
        {
            // Update existing provider's endpoint
            existing.endpoint = endpoint.to_string();
            // If they were withdrawn or stale, give them a new grace period
            if !existing.is_routable() {
                existing.status = AvailabilityStatus::GracePeriod {
                    ends_at: block_height + grace_period_seconds,
                };
            }
        } else {
            // Add new provider
            self.historical_data_providers
                .push(HistoricalDataProvider::new(
                    indexer_did.to_string(),
                    endpoint.to_string(),
                    block_height,
                    grace_period_seconds,
                ));
        }
    }

    /// Selects the best provider for serving a query.
    ///
    /// Prioritizes by:
    /// 1. Routability (must be in GracePeriod or Active status)
    /// 2. Success ratio (fewer failures is better)
    pub fn select_provider(&self) -> Option<&HistoricalDataProvider> {
        self.historical_data_providers
            .iter()
            .filter(|p| p.is_routable())
            .max_by_key(|p| {
                (p.successful_queries * 100)
                    .checked_div(p.successful_queries + p.failed_queries)
                    .unwrap_or(50) // Neutral for new providers
            })
    }

    /// Find a provider by their DID.
    pub fn find_provider(&self, indexer_did: &str) -> Option<&HistoricalDataProvider> {
        self.historical_data_providers
            .iter()
            .find(|p| p.indexer_did == indexer_did)
    }

    /// Find a provider by their DID (mutable).
    pub fn find_provider_mut(&mut self, indexer_did: &str) -> Option<&mut HistoricalDataProvider> {
        self.historical_data_providers
            .iter_mut()
            .find(|p| p.indexer_did == indexer_did)
    }

    /// Updates all provider statuses based on current time.
    /// Returns the total amount to slash across all providers (in basis points per provider).
    pub fn update_provider_statuses(
        &mut self,
        current_time: u64,
        config: &HistoricalAvailabilityConfig,
    ) -> Vec<(String, u32)> {
        let mut slashing_amounts = Vec::new();
        for provider in &mut self.historical_data_providers {
            let slash_bps = provider.update_status(current_time, config);
            if slash_bps > 0 {
                slashing_amounts.push((provider.indexer_did.clone(), slash_bps));
            }
        }
        slashing_amounts
    }

    /// Create a new StoredCheckpoint from a HistoricalCheckpointTx.
    pub fn from_checkpoint(
        checkpoint: HistoricalCheckpointTx,
        checkpoint_id: [u8; 32],
        submitted_at_block: u64,
        verification: CheckpointVerification,
    ) -> Self {
        let realtime_start_block = checkpoint.block_range.1 + 1;

        Self {
            checkpoint,
            checkpoint_id,
            verification,
            submitted_at_block,
            realtime_start_block,
            historical_data_providers: vec![],
        }
    }
}

/// Record of a checkpoint dispute when verification fails.
///
/// When a challenger opens a bisection dispute against a checkpoint,
/// this record tracks the original claim vs the challenger's claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointDispute {
    /// The checkpoint being disputed.
    pub checkpoint_id: [u8; 32],
    /// DID of the original indexer who submitted the checkpoint.
    pub original_indexer: String,
    /// State root claimed by the original indexer.
    pub original_state_root: [u8; 32],
    /// DID of the challenger who found a discrepancy.
    pub disputer_did: String,
    /// State root computed by the challenger.
    pub disputer_state_root: [u8; 32],
    /// Reason for the dispute (if provided).
    pub failure_reason: Option<String>,
    /// Block height when the dispute was recorded.
    pub block_height: u64,
    /// True if this dispute is against a TEE-verified checkpoint.
    ///
    /// TEE disputes are significant because they indicate either:
    /// - A bug in the TEE enclave code, OR
    /// - A TEE hardware/attestation vulnerability, OR
    /// - An error by the challenger
    #[serde(default)]
    pub disputed_tee_attestation: bool,
    /// Original indexer's intermediate hashes commitment.
    #[serde(default)]
    pub original_intermediate_commitment: [u8; 32],
    /// Challenger's intermediate hashes commitment.
    #[serde(default)]
    pub challenger_intermediate_commitment: [u8; 32],
}
