use serde::{Deserialize, Serialize};

use super::data_updates::EventInclusionProof;
use crate::token::units::ONE_WILL;

/// Minimum bond required when proposing a slash. Forfeited if evidence is invalid.
/// Set lower than the dispute bond (100 WILL) since evidence verification is
/// deterministic, not a multi-round interactive protocol.
pub const SLASH_PROPOSAL_BOND: u128 = 50 * ONE_WILL;

/// Types of violations that can result in slashing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashingViolation {
    /// Indexer submitted a fake or invalid Ethereum event proof.
    InvalidEventProof,
    /// Indexer computed incorrect state (failed re-execution verification).
    IncorrectStateComputation,
    /// Indexer failed to keep up with assigned subgrove.
    Unavailability,
    /// Other malicious behavior (requires detailed evidence).
    MaliciousBehavior,
    /// Provider failed to submit required commitments for a private subgrove.
    CommitmentLivenessViolation,
    /// Provider's committed state_root was proven inconsistent via commitment dispute.
    CommitmentIntegrityViolation,
}

/// Transaction for an indexer to collect accumulated query fees.
///
/// Indexers earn fees when users query their indexed data. This transaction
/// allows them to claim those fees for a specific period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectQueryFeesTx {
    /// DID of the indexer claiming fees.
    pub indexer_did: String,
    /// Start of the claim period (block number).
    pub period_start: u64,
    /// End of the claim period (block number).
    pub period_end: u64,
    /// Number of queries served in this period.
    pub query_count: u64,
    /// Total fees earned in WILL tokens.
    pub total_fees: u128,
    /// Cryptographic signature from the indexer.
    pub signature: Vec<u8>,
}

// ============================================================================
// Slashing - Consensus-based punishment for indexer misbehavior
// ============================================================================

/// Transaction to propose slashing an indexer for misbehavior.
///
/// This transaction goes through consensus - all validators independently verify
/// the evidence before the slash is executed. This prevents a single malicious
/// or buggy node from unilaterally slashing honest indexers.
///
/// ## Workflow
///
/// 1. Validator detects potential fraud (e.g., invalid Ethereum proof, failed verification)
/// 2. Validator creates `SlashIndexerTx` with evidence
/// 3. Transaction is broadcast and included in a block proposal
/// 4. All validators verify the evidence during consensus
/// 5. If 2/3+ validators accept the block, the slash is executed
///
/// ## Evidence Requirements
///
/// The evidence must be self-contained and deterministically verifiable:
/// - For invalid proofs: Include the original submission with the bad proof
/// - For re-execution failures: Include the submission + expected vs actual output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashIndexerTx {
    /// DID of the indexer to be slashed.
    pub indexer_did: String,
    /// Subgrove where the violation occurred.
    pub subgrove_id: String,
    /// Type of violation being reported.
    pub violation_type: SlashingViolation,
    /// Human-readable description of the violation.
    pub reason: String,
    /// The evidence proving the violation. This must be self-contained
    /// so all validators can independently verify it.
    pub evidence: SlashingEvidence,
    /// DID of the validator/entity proposing this slash.
    pub proposer_did: String,
    /// Bond amount posted by the proposer (must be >= SLASH_PROPOSAL_BOND).
    /// Forfeited to the accused indexer if evidence is invalid.
    pub bond_amount: u128,
    /// Cryptographic signature from the proposer.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Evidence supporting a slashing proposal.
///
/// Contains all data needed for validators to independently verify
/// that the indexer committed the claimed violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashingEvidence {
    /// Evidence for invalid Ethereum proof submission.
    InvalidEthereumProof {
        /// The block number where the invalid proof was claimed.
        block_number: u64,
        /// The event inclusion proof that failed verification.
        event_proof: EventInclusionProof,
        /// The receipts root from the canonical Ethereum block.
        /// Validators verify this against their light client.
        canonical_receipts_root: [u8; 32],
        /// Description of why the proof is invalid.
        failure_reason: String,
    },

    /// Evidence for incorrect state computation (re-execution mismatch).
    ///
    /// Contains all data needed for validators to independently re-execute
    /// the transformation and verify that the indexer's output was incorrect.
    ReexecutionMismatch {
        /// Block range that was incorrectly indexed.
        block_range: (u64, u64),
        /// Hash of the data the indexer submitted.
        submitted_data_hash: [u8; 32],
        /// Hash of the correctly re-executed data.
        expected_data_hash: [u8; 32],
        /// The original indexed data submission (serialized).
        original_submission: Vec<u8>,
        /// Event inclusion proofs for all events in the block range.
        /// These allow validators to independently verify the source data
        /// and re-execute the transformation.
        event_proofs: Vec<EventInclusionProof>,
        /// Hash of the subgrove configuration used for transformation.
        /// Validators look up the config by this hash to ensure they use
        /// the same transformation rules.
        subgrove_config_hash: [u8; 32],
        /// Detailed description of the mismatch.
        mismatch_description: String,
    },

    /// Evidence for extended unavailability.
    Unavailability {
        /// Number of consecutive blocks the indexer was unavailable.
        missed_blocks: u64,
        /// Block range during which the indexer was unavailable.
        unavailable_range: (u64, u64),
        /// Timestamps of failed health checks.
        failed_health_checks: Vec<u64>,
    },

    /// Generic evidence for other violations.
    Other {
        /// Serialized evidence data.
        data: Vec<u8>,
        /// Description of the evidence format.
        format_description: String,
    },
}
