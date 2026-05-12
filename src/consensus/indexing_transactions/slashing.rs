use serde::{Deserialize, Serialize};

use super::data_updates::EventInclusionProof;
use crate::token::units::{
    ONE_WILL, SLASH_COMMITMENT_INTEGRITY, SLASH_COMMITMENT_LIVENESS, SLASH_INCORRECT_STATE,
    SLASH_INVALID_EVENT_PROOF, SLASH_MALICIOUS_BEHAVIOR, SLASH_UNAVAILABILITY,
};

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

impl SlashingViolation {
    /// Returns the fixed slash amount for this violation type.
    pub fn slash_amount(&self) -> u128 {
        match self {
            SlashingViolation::Unavailability => SLASH_UNAVAILABILITY,
            SlashingViolation::CommitmentLivenessViolation => SLASH_COMMITMENT_LIVENESS,
            SlashingViolation::InvalidEventProof => SLASH_INVALID_EVENT_PROOF,
            SlashingViolation::IncorrectStateComputation => SLASH_INCORRECT_STATE,
            SlashingViolation::CommitmentIntegrityViolation => SLASH_COMMITMENT_INTEGRITY,
            SlashingViolation::MaliciousBehavior => SLASH_MALICIOUS_BEHAVIOR,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::units::*;

    #[test]
    fn test_each_violation_returns_correct_fixed_amount() {
        assert_eq!(
            SlashingViolation::Unavailability.slash_amount(),
            SLASH_UNAVAILABILITY
        );
        assert_eq!(
            SlashingViolation::CommitmentLivenessViolation.slash_amount(),
            SLASH_COMMITMENT_LIVENESS
        );
        assert_eq!(
            SlashingViolation::InvalidEventProof.slash_amount(),
            SLASH_INVALID_EVENT_PROOF
        );
        assert_eq!(
            SlashingViolation::IncorrectStateComputation.slash_amount(),
            SLASH_INCORRECT_STATE
        );
        assert_eq!(
            SlashingViolation::CommitmentIntegrityViolation.slash_amount(),
            SLASH_COMMITMENT_INTEGRITY
        );
        assert_eq!(
            SlashingViolation::MaliciousBehavior.slash_amount(),
            SLASH_MALICIOUS_BEHAVIOR
        );
    }

    #[test]
    fn test_operational_violations_are_small() {
        // Operational violations should be 500 WILL each
        assert_eq!(
            SlashingViolation::Unavailability.slash_amount(),
            500 * ONE_WILL
        );
        assert_eq!(
            SlashingViolation::CommitmentLivenessViolation.slash_amount(),
            500 * ONE_WILL
        );
    }

    #[test]
    fn test_fraud_violations_are_severe() {
        // Fraud violations should be 5,000-10,000 WILL
        let fraud_violations = [
            SlashingViolation::InvalidEventProof,
            SlashingViolation::IncorrectStateComputation,
            SlashingViolation::CommitmentIntegrityViolation,
        ];
        for v in &fraud_violations {
            assert_eq!(v.slash_amount(), 5 * ONE_KILO_WILL);
        }
        assert_eq!(
            SlashingViolation::MaliciousBehavior.slash_amount(),
            10 * ONE_KILO_WILL
        );
    }

    #[test]
    fn test_malicious_behavior_equals_min_indexer_stake() {
        // A single MaliciousBehavior slash should wipe out exactly the minimum stake
        assert_eq!(
            SlashingViolation::MaliciousBehavior.slash_amount(),
            MIN_INDEXER_STAKE
        );
    }

    #[test]
    fn test_twenty_unavailability_incidents_equal_min_stake() {
        // 20 × 500 WILL = 10,000 WILL = MIN_INDEXER_STAKE
        let total = 20 * SlashingViolation::Unavailability.slash_amount();
        assert_eq!(total, MIN_INDEXER_STAKE);
    }
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
    #[serde(with = "crate::serde_helpers::u128_flexible")]
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
    #[serde(with = "crate::serde_helpers::u128_flexible")]
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

#[cfg(test)]
mod bincode_tests {
    //! Per-file regression guard for the `u128_flexible` helper attached to
    //! tx u128 fields in this module. Consensus deserializes `Transaction`
    //! via `bincode::deserialize`, so any helper attached to a tx field
    //! must round-trip through bincode unchanged.
    use super::*;

    #[test]
    fn slash_indexer_tx_bincode_round_trip() {
        let tx = SlashIndexerTx {
            indexer_did: "did:willow:indexer1".to_string(),
            subgrove_id: "sg-1".to_string(),
            violation_type: SlashingViolation::Unavailability,
            reason: "missed availability proofs".to_string(),
            evidence: SlashingEvidence::Other {
                data: vec![1, 2, 3],
                format_description: "test".to_string(),
            },
            proposer_did: "did:willow:proposer1".to_string(),
            bond_amount: 100_000_000_000_000_000_000_000,
            signature: vec![1, 2, 3],
            public_key_id: "did:willow:proposer1#key-1".to_string(),
            nonce: 1,
        };
        let bytes = bincode::serialize(&tx).expect("bincode serialize");
        let got: SlashIndexerTx = bincode::deserialize(&bytes).expect("bincode deserialize");
        assert_eq!(got.bond_amount, tx.bond_amount);
    }

    #[test]
    fn collect_query_fees_tx_bincode_round_trip() {
        let tx = CollectQueryFeesTx {
            indexer_did: "did:willow:indexer1".to_string(),
            period_start: 100,
            period_end: 200,
            query_count: 1234,
            total_fees: 100_000_000_000_000_000_000_000,
            signature: vec![1, 2, 3],
        };
        let bytes = bincode::serialize(&tx).expect("bincode serialize");
        let got: CollectQueryFeesTx = bincode::deserialize(&bytes).expect("bincode deserialize");
        assert_eq!(got.total_fees, tx.total_fees);
    }
}
