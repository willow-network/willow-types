use crate::consensus::indexing_transactions::CheckpointDispute;
use crate::token::units::ONE_WILL;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Bond required from the challenger to open a bisection dispute (prevents frivolous disputes).
/// This is returned if the challenger wins, forfeited if they lose.
pub const DISPUTE_BOND: u128 = 100 * ONE_WILL;

/// Number of blocks allowed per bisection round response.
pub const BISECTION_RESPONSE_DEADLINE_BLOCKS: u64 = 200;

/// Number of blocks to wait before auto-adjudicating a ready dispute.
/// Must be long enough for the challenger to submit an AdjudicateBisectionTx
/// with evidence after bisection completes (~12 rounds × 10 blocks per round).
pub const ADJUDICATION_TIMEOUT_BLOCKS: u64 = 500;

// ============================================================================
// Commitment Dispute Constants (for private subgrove challenge-response)
// ============================================================================

/// Bond required from the challenger to open a commitment dispute.
pub const COMMITMENT_DISPUTE_BOND: u128 = 100 * ONE_WILL;

/// Number of blocks the provider has to respond with a GroveDB proof.
pub const COMMITMENT_DISPUTE_RESPONSE_BLOCKS: u64 = 200;

/// The winner of a dispute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisputeWinner {
    /// Original indexer's checkpoint was correct.
    OriginalIndexer,
    /// Challenger's claim was correct (original checkpoint was wrong).
    Challenger,
}

/// A bisection dispute that narrows disagreement to a single block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BisectionDispute {
    /// Unique dispute ID (derived from checkpoint_id + challenger_did).
    pub dispute_id: [u8; 32],
    /// The original dispute record.
    pub dispute: CheckpointDispute,
    /// Checkpoint ID being disputed.
    pub checkpoint_id: [u8; 32],
    /// DID of the original indexer (checkpoint submitter).
    pub original_indexer_did: String,
    /// DID of the challenger.
    pub challenger_did: String,
    /// Original indexer's intermediate hashes commitment (Merkle root).
    pub original_intermediate_commitment: [u8; 32],
    /// Challenger's intermediate hashes commitment (Merkle root).
    pub challenger_intermediate_commitment: [u8; 32],
    /// Bond amount held from the challenger.
    pub bond: u128,
    /// Current status of the bisection process.
    pub status: BisectionStatus,
    /// Block height when the dispute was opened.
    pub opened_at_block: u64,
    /// Full block range of the checkpoint (start, end inclusive).
    pub full_block_range: (u64, u64),
    /// The subgrove being disputed.
    pub subgrove_id: String,
}

impl BisectionDispute {
    /// Computes a unique dispute ID from checkpoint and challenger DID.
    pub fn compute_dispute_id(checkpoint_id: &[u8; 32], challenger_did: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(checkpoint_id);
        hasher.update(challenger_did.as_bytes());
        hasher.finalize().into()
    }

    /// Returns true if the given DID is a party to this dispute.
    pub fn is_party(&self, did: &str) -> bool {
        self.original_indexer_did == did || self.challenger_did == did
    }

    /// Returns true if the dispute is resolved.
    pub fn is_resolved(&self) -> bool {
        matches!(self.status, BisectionStatus::Resolved { .. })
    }

    /// Returns the total number of blocks in the disputed range.
    pub fn total_blocks(&self) -> u64 {
        self.full_block_range.1 - self.full_block_range.0 + 1
    }
}

/// Status of a bisection dispute, tracking the binary search process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BisectionStatus {
    /// Waiting for both parties to reveal their accumulated hash at the query block.
    AwaitingResponses {
        /// The block number being queried (midpoint of search range).
        query_block: u64,
        /// Current search range (start, end) — narrows each round.
        search_range: (u64, u64),
        /// Original indexer's response for this round (if submitted).
        original_response: Option<BisectionResponse>,
        /// Challenger's response for this round (if submitted).
        challenger_response: Option<BisectionResponse>,
        /// Deadline block for this round's responses.
        round_deadline: u64,
        /// The most recently observed agreed accumulated hash from prior rounds.
        /// When both parties agree at a midpoint, this is set to that agreed hash.
        /// Used as `agreed_hash_before` when the dispute reaches adjudication.
        #[serde(default)]
        last_agreed_hash: Option<[u8; 32]>,
    },
    /// Bisection complete — narrowed to a single block ready for adjudication.
    ReadyForAdjudication {
        /// The single disputed block.
        disputed_block: u64,
        /// The agreed-upon accumulated hash at (disputed_block - 1).
        agreed_hash_before: [u8; 32],
        /// Original indexer's accumulated hash at disputed_block.
        original_hash_after: [u8; 32],
        /// Challenger's accumulated hash at disputed_block.
        challenger_hash_after: [u8; 32],
        /// Block height when adjudication became possible.
        reached_at_block: u64,
    },
    /// Dispute has been resolved.
    Resolved {
        /// The winning party.
        winner: DisputeWinner,
        /// Block height when resolved.
        resolved_at_block: u64,
        /// Amount slashed from the loser.
        slash_amount: u128,
    },
}

/// A party's response in a bisection round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BisectionResponse {
    /// The accumulated hash at the queried block.
    pub accumulated_hash: [u8; 32],
    /// Merkle proof that this hash is part of the party's intermediate_hashes_commitment.
    pub merkle_proof: Vec<[u8; 32]>,
}

/// Entry in the checkpoint index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointIndexEntry {
    /// The subgrove this checkpoint belongs to.
    pub subgrove_id: String,
    /// The indexer who submitted this checkpoint.
    pub indexer_did: String,
    /// The state root claimed by this checkpoint.
    pub state_root: [u8; 32],
}

/// Statistics about an indexer's dispute participation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IndexerDisputeStats {
    /// Pending disputes where this indexer's checkpoints are being challenged.
    pub disputes_against_pending: u64,
    /// Disputes won when defending own checkpoints.
    pub disputes_won_as_defendant: u64,
    /// Disputes lost when defending own checkpoints.
    pub disputes_lost_as_defendant: u64,
    /// Pending disputes this indexer has filed against others.
    pub disputes_filed_pending: u64,
    /// Disputes won when challenging others' checkpoints.
    pub disputes_won_as_challenger: u64,
    /// Disputes lost when challenging others' checkpoints.
    pub disputes_lost_as_challenger: u64,
}

// ============================================================================
// Commitment Disputes (for private subgrove challenge-response)
// ============================================================================

/// A challenge-response dispute against a private subgrove commitment.
///
/// A key grantee challenges the provider to prove that their committed state_root
/// is backed by a real, consistent GroveDB tree. The provider must respond with
/// a valid GroveDB proof for the challenged path+key within the response deadline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentDispute {
    /// Unique dispute ID: SHA256(subgrove_id || challenger_did || block_height).
    pub dispute_id: [u8; 32],
    /// The subgrove being disputed.
    pub subgrove_id: String,
    /// DID of the provider whose commitment is disputed.
    pub provider_did: String,
    /// DID of the challenger (must be a current key grantee).
    pub challenger_did: String,
    /// The state_root being disputed (from the latest on-chain commitment).
    pub committed_state_root: [u8; 32],
    /// GroveDB path to prove (within the subgrove's data tree).
    pub challenge_path: Vec<Vec<u8>>,
    /// Specific key at that path to prove.
    pub challenge_key: Vec<u8>,
    /// Bond amount held from the challenger.
    pub bond: u128,
    /// Current status of the dispute.
    pub status: CommitmentDisputeStatus,
    /// Block height when the dispute was opened.
    pub opened_at_block: u64,
    /// Deadline block for the provider to respond.
    pub response_deadline: u64,
}

impl CommitmentDispute {
    /// Computes a unique dispute ID from subgrove ID, challenger DID, and block height.
    pub fn compute_dispute_id(
        subgrove_id: &str,
        challenger_did: &str,
        block_height: u64,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(subgrove_id.as_bytes());
        hasher.update(challenger_did.as_bytes());
        hasher.update(block_height.to_le_bytes());
        hasher.finalize().into()
    }

    /// Returns true if the dispute is resolved.
    pub fn is_resolved(&self) -> bool {
        matches!(self.status, CommitmentDisputeStatus::Resolved { .. })
    }
}

/// Status of a commitment dispute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommitmentDisputeStatus {
    /// Waiting for the provider to respond with a GroveDB proof.
    AwaitingResponse,
    /// Dispute has been resolved.
    Resolved {
        /// The winning party.
        winner: DisputeWinner,
        /// Block height when resolved.
        resolved_at_block: u64,
        /// Amount slashed from the provider (0 if challenger lost).
        slash_amount: u128,
    },
}
