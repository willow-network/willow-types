//! Indexer reputation and profile types.
//!
//! This module defines the system-level data contract for tracking indexer
//! reputation and profiles. All data is stored in GroveDB and is queryable
//! with cryptographic Merkle proofs.
//!
//! # Overview
//!
//! The reputation system tracks:
//! - **Performance metrics**: Detailed statistics about indexer behavior
//! - **Profiles**: Identity and infrastructure information
//! - **Operator entities**: Voluntary grouping of indexers under one operator
//! - **Correlation flags**: Detected similarities between indexers
//!
//! Consumers of reputation data query the raw metrics directly rather than
//! relying on a derived composite score. This avoids opinionated scoring
//! formulas and lets each consumer weight metrics as they see fit.
//!
//! # Sybil Resistance
//!
//! Rather than trying to prevent Sybil indexers, this system makes
//! same-entity indexers **visible** so apps and users can make informed
//! decisions about indexer diversity.

use serde::{Deserialize, Serialize};

// ============================================================================
// Reputation Types
// ============================================================================

/// System-level indexer reputation stored in GroveDB.
///
/// This is the authoritative reputation record, verified by consensus
/// and queryable with cryptographic proofs. Raw metrics are stored
/// directly; consumers derive their own scoring from the metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexerReputation {
    /// The indexer's DID (e.g., "did:willow:abc123")
    pub indexer_did: String,

    /// Detailed performance metrics
    pub metrics: ReputationMetrics,

    /// When the indexer first registered (Unix timestamp)
    pub registered_at: u64,

    /// Last time reputation was updated (Unix timestamp)
    pub last_updated: u64,

    /// Block height of last update
    pub last_updated_block: u64,
}

impl IndexerReputation {
    /// Creates a new reputation record for a newly registered indexer.
    pub fn new(indexer_did: String, registered_at: u64, block_height: u64) -> Self {
        Self {
            indexer_did,
            metrics: ReputationMetrics::default(),
            registered_at,
            last_updated: registered_at,
            last_updated_block: block_height,
        }
    }
}

/// Detailed performance metrics tracked on-chain.
///
/// These metrics are updated by consensus when relevant events occur
/// (checkpoint submissions, verifications, slashing, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReputationMetrics {
    // === Indexing Performance ===
    /// Total blocks successfully indexed across all subgroves
    pub total_blocks_indexed: u64,
    /// Total data bytes indexed
    pub total_bytes_indexed: u64,

    // === Checkpoint Submissions ===
    /// Checkpoints submitted by this indexer
    pub checkpoints_submitted: u64,
    /// Checkpoints that passed verification
    pub checkpoints_verified: u64,
    /// Checkpoints that failed verification (disputed & lost)
    pub checkpoints_failed: u64,

    // === Verification Work (as a verifier) ===
    /// How many checkpoints this indexer verified for others
    pub verifications_performed: u64,
    /// Correct verifications (matched final consensus)
    pub verifications_correct: u64,
    /// Incorrect verifications (disagreed with consensus)
    pub verifications_incorrect: u64,

    // === Data Availability ===
    /// Availability proofs submitted on time
    pub availability_proofs_submitted: u64,
    /// Missed availability proof deadlines
    pub availability_proofs_missed: u64,
    /// Historical queries successfully served (reported by users)
    pub historical_queries_served: u64,

    // === Economic History ===
    /// Total WILL earned from indexing rewards (in wei)
    pub total_rewards_earned: u128,
    /// Total WILL slashed (in wei)
    pub total_slashed: u128,
    /// Number of slashing events
    pub slashing_count: u32,

    // === Uptime & Reliability ===
    /// Consecutive successful submissions (resets on failure)
    pub current_streak: u64,
    /// Longest streak ever achieved
    pub best_streak: u64,
    /// Days with at least one successful action
    pub active_days: u32,

    // === Dispute Resolution (as recruited verifier) ===
    /// Number of times selected for dispute resolution
    #[serde(default)]
    pub dispute_assignments: u64,
    /// Dispute assignments completed on time
    #[serde(default)]
    pub dispute_assignments_completed: u64,
    /// Dispute assignments missed (didn't respond in time)
    #[serde(default)]
    pub dispute_assignments_missed: u64,
}

impl ReputationMetrics {
    /// Returns the checkpoint success rate as a percentage (0.0 - 100.0).
    pub fn checkpoint_success_rate(&self) -> f64 {
        if self.checkpoints_submitted == 0 {
            return 0.0;
        }
        (self.checkpoints_verified as f64 / self.checkpoints_submitted as f64) * 100.0
    }

    /// Returns the verification accuracy as a percentage (0.0 - 100.0).
    pub fn verification_accuracy(&self) -> f64 {
        if self.verifications_performed == 0 {
            return 0.0;
        }
        (self.verifications_correct as f64 / self.verifications_performed as f64) * 100.0
    }
}

// ============================================================================
// Reputation Events (History Tracking)
// ============================================================================

/// Events that affect reputation, stored for auditability.
///
/// A rolling window of recent events is kept in storage for transparency
/// and dispute resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationEvent {
    /// Unique event ID (block_height:event_index)
    pub event_id: String,
    /// The indexer affected
    pub indexer_did: String,
    /// Type of event
    pub event_type: ReputationEventType,
    /// Block height when this occurred
    pub block_height: u64,
    /// Timestamp (Unix seconds)
    pub timestamp: u64,
    /// Optional reference (e.g., checkpoint ID, subgrove ID)
    pub reference: Option<String>,
}

/// Types of events that affect reputation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReputationEventType {
    // === Positive Events ===
    /// Checkpoint was verified successfully
    CheckpointVerified { checkpoint_id: [u8; 32] },
    /// Verification of another indexer's checkpoint was correct
    VerificationCorrect { checkpoint_id: [u8; 32] },
    /// Availability proof submitted on time
    AvailabilityProofSubmitted,
    /// Reached a streak milestone (100, 500, 1000, etc.)
    StreakMilestone { streak: u64 },

    // === Negative Events ===
    /// Checkpoint was disputed and failed
    CheckpointDisputed { checkpoint_id: [u8; 32] },
    /// Checkpoint failed verification
    CheckpointFailed {
        checkpoint_id: [u8; 32],
        reason: String,
    },
    /// Verification of another indexer was incorrect
    VerificationIncorrect { checkpoint_id: [u8; 32] },
    /// Missed an availability proof deadline
    AvailabilityProofMissed,
    /// Stake was slashed
    Slashed { amount: u128, violation: String },

    // === Neutral/Administrative ===
    /// Indexer first registered
    Registered,

    // === Dispute Resolution Events ===
    /// Selected for dispute verification but failed to respond in time
    DisputeAssignmentMissed { dispute_id: [u8; 32] },
    /// Successfully completed a dispute verification assignment
    DisputeAssignmentCompleted { dispute_id: [u8; 32] },
    /// Won a dispute (either as original indexer defending or as disputer proving error)
    DisputeWon {
        dispute_id: [u8; 32],
        /// True if won as original indexer, false if won as disputer
        as_original_indexer: bool,
    },
}

// ============================================================================
// Indexer Profile Types
// ============================================================================

/// Observable characteristics of an indexer for profile matching.
///
/// Profiles help identify whether multiple indexers might be operated
/// by the same entity, enabling apps to make diversity decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexerProfile {
    /// The indexer's DID
    pub indexer_did: String,

    // === Identity Signals ===
    /// Optional human-readable name
    pub display_name: Option<String>,
    /// Optional description/bio
    pub description: Option<String>,
    /// Optional website URL
    pub website: Option<String>,
    /// Optional logo/avatar IPFS hash
    pub logo_ipfs: Option<String>,

    // === Funding Source Tracking ===
    /// Addresses that funded this indexer's stake
    pub funding_sources: Vec<FundingSource>,
    /// Hash of all funding sources (for quick comparison)
    pub funding_fingerprint: [u8; 32],

    // === Infrastructure Signals ===
    /// Declared geographic region
    pub declared_region: Option<String>,
    /// Type of infrastructure (cloud provider, self-hosted, etc.)
    pub infrastructure_type: Option<InfrastructureType>,
    /// TEE hardware fingerprint (if TEE-enabled)
    /// This is derived from PCR0 (Nitro) or MRENCLAVE (SGX)
    pub tee_hardware_id: Option<String>,

    // === Entity Linking (Voluntary) ===
    /// Optional link to an operator entity that runs multiple indexers
    pub operator_entity_id: Option<String>,

    // === Dispute Resolution Availability ===
    /// Whether this indexer is available to be selected for dispute resolution.
    /// Indexers should set this to true when they have capacity for extra work.
    /// Default is false - indexers must explicitly opt-in.
    #[serde(default)]
    pub available_for_disputes: bool,

    // === Correlation Flags (set by consensus) ===
    /// Detected correlations with other indexers
    pub correlation_flags: Vec<CorrelationFlag>,

    /// When the profile was created
    pub created_at: u64,
    /// Last profile update
    pub updated_at: u64,
}

impl IndexerProfile {
    /// Creates a new empty profile for an indexer.
    pub fn new(indexer_did: String, timestamp: u64) -> Self {
        Self {
            indexer_did,
            display_name: None,
            description: None,
            website: None,
            logo_ipfs: None,
            funding_sources: Vec::new(),
            funding_fingerprint: [0u8; 32],
            declared_region: None,
            infrastructure_type: None,
            tee_hardware_id: None,
            operator_entity_id: None,
            available_for_disputes: false, // Opt-in only
            correlation_flags: Vec::new(),
            created_at: timestamp,
            updated_at: timestamp,
        }
    }

    /// Recalculates the funding fingerprint from funding sources.
    pub fn update_funding_fingerprint(&mut self) {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        for source in &self.funding_sources {
            hasher.update(source.address.as_bytes());
            hasher.update(source.chain.as_bytes());
        }
        self.funding_fingerprint = hasher.finalize().into();
    }

    /// Checks if this profile shares any funding sources with another.
    pub fn shares_funding_source_with(&self, other: &IndexerProfile) -> bool {
        for my_source in &self.funding_sources {
            for their_source in &other.funding_sources {
                if my_source.address == their_source.address
                    && my_source.chain == their_source.chain
                {
                    return true;
                }
            }
        }
        false
    }

    /// Checks if this profile shares TEE hardware with another.
    pub fn shares_hardware_with(&self, other: &IndexerProfile) -> bool {
        match (&self.tee_hardware_id, &other.tee_hardware_id) {
            (Some(my_id), Some(their_id)) => my_id == their_id,
            _ => false,
        }
    }
}

/// A funding source that contributed stake to an indexer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundingSource {
    /// The address that sent stake funds
    pub address: String,
    /// Chain identifier (e.g., "ethereum", "willow")
    pub chain: String,
    /// Transaction hash of the funding
    pub tx_hash: String,
    /// Amount funded (in wei)
    pub amount: u128,
    /// When funded (Unix timestamp)
    pub timestamp: u64,
}

/// Type of infrastructure the indexer runs on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum InfrastructureType {
    /// Self-hosted hardware
    SelfHosted,
    /// Amazon Web Services
    Aws,
    /// Google Cloud Platform
    Gcp,
    /// Microsoft Azure
    Azure,
    /// DigitalOcean
    DigitalOcean,
    /// Hetzner
    Hetzner,
    /// Other cloud provider
    OtherCloud(String),
    /// Unknown/not disclosed
    #[default]
    Unknown,
}

/// A correlation flag indicating detected similarity with another indexer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationFlag {
    /// Type of correlation detected
    pub flag_type: CorrelationFlagType,
    /// The other indexer(s) correlated with
    pub correlated_indexers: Vec<String>,
    /// Confidence level (0-100)
    pub confidence: u8,
    /// When this flag was set (Unix timestamp)
    pub detected_at: u64,
    /// Block height when detected
    pub detected_at_block: u64,
    /// Evidence summary (human-readable)
    pub evidence: String,
}

/// Types of correlations that can be detected between indexers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CorrelationFlagType {
    /// Same wallet address funded both indexers
    SharedFundingSource,
    /// Same TEE hardware (PCR0 or MRENCLAVE match)
    SharedHardware,
    /// Statistically correlated uptime/downtime patterns
    UptimeCorrelation,
    /// Observed from same IP range
    SameIpRange,
    /// Suspiciously synchronized checkpoint submissions
    SynchronizedBehavior,
    /// Voluntarily declared same operator
    SameOperator,
}

// ============================================================================
// Operator Entity Types
// ============================================================================

/// An operator entity that may run multiple indexers.
///
/// This is opt-in transparency - operators who want to build
/// a brand/reputation across multiple indexers can link them
/// under a single entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorEntity {
    /// Unique entity ID (derived from admin DID)
    pub entity_id: String,
    /// Human-readable name (e.g., "Acme Indexing Co")
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// Website URL
    pub website: Option<String>,
    /// Logo IPFS hash
    pub logo_ipfs: Option<String>,

    /// All indexers operated by this entity
    pub indexer_dids: Vec<String>,

    /// Aggregate reputation across all indexers
    pub aggregate_reputation: AggregateReputation,

    /// DID that controls this entity (can add/remove indexers)
    pub admin_did: String,

    /// When entity was created (Unix timestamp)
    pub created_at: u64,
    /// Last update timestamp
    pub updated_at: u64,
}

impl OperatorEntity {
    /// Creates a new operator entity.
    pub fn new(entity_id: String, name: String, admin_did: String, timestamp: u64) -> Self {
        Self {
            entity_id,
            name,
            description: None,
            website: None,
            logo_ipfs: None,
            indexer_dids: Vec::new(),
            aggregate_reputation: AggregateReputation::default(),
            admin_did,
            created_at: timestamp,
            updated_at: timestamp,
        }
    }

    /// Adds an indexer to this entity.
    pub fn add_indexer(&mut self, indexer_did: String) {
        if !self.indexer_dids.contains(&indexer_did) {
            self.indexer_dids.push(indexer_did);
        }
    }

    /// Removes an indexer from this entity.
    pub fn remove_indexer(&mut self, indexer_did: &str) {
        self.indexer_dids.retain(|did| did != indexer_did);
    }
}

/// Aggregate reputation across all indexers in an operator entity.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AggregateReputation {
    /// Number of indexers in this entity
    pub indexer_count: u32,
    /// Total blocks indexed by all indexers
    pub total_blocks_indexed: u64,
    /// Combined slashing events across all indexers
    pub total_slashing_events: u32,
    /// Oldest indexer registration date
    pub operating_since: u64,
}

impl AggregateReputation {
    /// Recalculates aggregate stats from a list of indexer reputations.
    pub fn calculate(reputations: &[IndexerReputation]) -> Self {
        if reputations.is_empty() {
            return Self::default();
        }

        Self {
            indexer_count: reputations.len() as u32,
            total_blocks_indexed: reputations
                .iter()
                .map(|r| r.metrics.total_blocks_indexed)
                .sum(),
            total_slashing_events: reputations.iter().map(|r| r.metrics.slashing_count).sum(),
            operating_since: reputations
                .iter()
                .map(|r| r.registered_at)
                .min()
                .unwrap_or(0),
        }
    }
}

// ============================================================================
// Query/Filter Types
// ============================================================================

/// Filter criteria for querying indexers by reputation.
#[derive(Debug, Clone, Default)]
pub struct ReputationFilter {
    /// Exclude indexers with these correlation flags
    pub exclude_correlations: Vec<CorrelationFlagType>,
    /// Exclude indexers from these operator entities
    pub exclude_entities: Vec<String>,
    /// Only include indexers from these regions
    pub regions: Vec<String>,
    /// Maximum slashing events allowed
    pub max_slashing_events: Option<u32>,
}

impl ReputationFilter {
    /// Checks if an indexer passes this filter.
    pub fn matches(&self, reputation: &IndexerReputation, profile: &IndexerProfile) -> bool {
        // Correlation exclusions
        for exclude_type in &self.exclude_correlations {
            for flag in &profile.correlation_flags {
                if &flag.flag_type == exclude_type {
                    return false;
                }
            }
        }

        // Entity exclusions
        if let Some(entity_id) = &profile.operator_entity_id {
            if self.exclude_entities.contains(entity_id) {
                return false;
            }
        }

        // Region filter
        if !self.regions.is_empty() {
            match &profile.declared_region {
                Some(region) if self.regions.contains(region) => {}
                _ => return false,
            }
        }

        // Slashing limit
        if let Some(max_slash) = self.max_slashing_events {
            if reputation.metrics.slashing_count > max_slash {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_indexer_default_metrics() {
        let reputation = IndexerReputation::new("did:willow:test".to_string(), 1000, 1);
        assert_eq!(reputation.metrics.total_blocks_indexed, 0);
        assert_eq!(reputation.metrics.slashing_count, 0);
        assert_eq!(reputation.registered_at, 1000);
        assert_eq!(reputation.last_updated_block, 1);
    }

    #[test]
    fn test_funding_fingerprint() {
        let mut profile1 = IndexerProfile::new("did:willow:1".to_string(), 1000);
        profile1.funding_sources.push(FundingSource {
            address: "0xabc123".to_string(),
            chain: "ethereum".to_string(),
            tx_hash: "0x111".to_string(),
            amount: 1000,
            timestamp: 1000,
        });
        profile1.update_funding_fingerprint();

        let mut profile2 = IndexerProfile::new("did:willow:2".to_string(), 1000);
        profile2.funding_sources.push(FundingSource {
            address: "0xabc123".to_string(),
            chain: "ethereum".to_string(),
            tx_hash: "0x222".to_string(),
            amount: 2000,
            timestamp: 2000,
        });
        profile2.update_funding_fingerprint();

        // Same funding source address should produce same fingerprint
        assert_eq!(profile1.funding_fingerprint, profile2.funding_fingerprint);
        assert!(profile1.shares_funding_source_with(&profile2));
    }

    #[test]
    fn test_aggregate_reputation() {
        let rep1 = IndexerReputation {
            indexer_did: "did:willow:1".to_string(),
            metrics: ReputationMetrics {
                total_blocks_indexed: 1000,
                slashing_count: 0,
                ..Default::default()
            },
            registered_at: 1000,
            last_updated: 2000,
            last_updated_block: 100,
        };

        let rep2 = IndexerReputation {
            indexer_did: "did:willow:2".to_string(),
            metrics: ReputationMetrics {
                total_blocks_indexed: 500,
                slashing_count: 1,
                ..Default::default()
            },
            registered_at: 1500,
            last_updated: 2000,
            last_updated_block: 100,
        };

        let aggregate = AggregateReputation::calculate(&[rep1, rep2]);

        assert_eq!(aggregate.indexer_count, 2);
        assert_eq!(aggregate.total_blocks_indexed, 1500);
        assert_eq!(aggregate.total_slashing_events, 1);
        assert_eq!(aggregate.operating_since, 1000);
    }

    #[test]
    fn test_metrics_rates() {
        let mut metrics = ReputationMetrics::default();
        metrics.checkpoints_submitted = 100;
        metrics.checkpoints_verified = 80;
        assert!((metrics.checkpoint_success_rate() - 80.0).abs() < f64::EPSILON);

        metrics.verifications_performed = 50;
        metrics.verifications_correct = 45;
        assert!((metrics.verification_accuracy() - 90.0).abs() < f64::EPSILON);
    }
}
