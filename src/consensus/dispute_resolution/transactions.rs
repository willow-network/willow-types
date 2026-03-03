use serde::{Deserialize, Serialize};

use super::types::DISPUTE_BOND;

/// Transaction to open a bisection dispute against a checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenBisectionDisputeTx {
    /// The checkpoint being disputed.
    pub checkpoint_id: [u8; 32],
    /// DID of the challenger.
    pub challenger_did: String,
    /// Challenger's intermediate hashes commitment (Merkle root over accumulated hashes).
    pub challenger_intermediate_commitment: [u8; 32],
    /// Bond amount being posted (must be >= DISPUTE_BOND).
    pub bond_amount: u128,
    /// Reason for the dispute.
    pub reason: String,
    /// Cryptographic signature from the challenger.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction for a party to submit their bisection step response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BisectionStepTx {
    /// The dispute being responded to.
    pub dispute_id: [u8; 32],
    /// DID of the responder (must be a party to the dispute).
    pub responder_did: String,
    /// The accumulated hash at the queried block.
    pub accumulated_hash: [u8; 32],
    /// Merkle proof that this hash is in the responder's intermediate_hashes_commitment.
    pub merkle_proof: Vec<[u8; 32]>,
    /// Cryptographic signature from the responder.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to trigger adjudication of a bisection dispute that has
/// narrowed to a single block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdjudicateBisectionTx {
    /// The dispute to adjudicate.
    pub dispute_id: [u8; 32],
    /// DID of the submitter (anyone can trigger adjudication).
    pub submitter_did: String,
    /// Cryptographic signature from the submitter.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to set an indexer's availability for dispute resolution.
///
/// Indexers should set `available = true` when they have capacity for extra work
/// and want to act as natural watchtowers. Set `available = false` when busy
/// with other indexing work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetDisputeAvailabilityTx {
    /// DID of the indexer setting availability.
    pub indexer_did: String,
    /// Whether the indexer is available for dispute resolution.
    pub available: bool,
    /// Cryptographic signature from the indexer.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Validates an OpenBisectionDisputeTx.
pub fn validate_open_bisection_dispute(tx: &OpenBisectionDisputeTx) -> Result<(), String> {
    if tx.challenger_did.is_empty() {
        return Err("Challenger DID cannot be empty".to_string());
    }

    if tx.bond_amount < DISPUTE_BOND {
        return Err(format!(
            "Bond amount {} is less than required {}",
            tx.bond_amount, DISPUTE_BOND
        ));
    }

    if tx.reason.is_empty() {
        return Err("Dispute reason cannot be empty".to_string());
    }

    if tx.signature.is_empty() {
        return Err("Signature is required".to_string());
    }

    Ok(())
}

/// Validates a BisectionStepTx.
pub fn validate_bisection_step(tx: &BisectionStepTx) -> Result<(), String> {
    if tx.responder_did.is_empty() {
        return Err("Responder DID cannot be empty".to_string());
    }

    if tx.signature.is_empty() {
        return Err("Signature is required".to_string());
    }

    Ok(())
}

/// Validates an AdjudicateBisectionTx.
pub fn validate_adjudicate_bisection(tx: &AdjudicateBisectionTx) -> Result<(), String> {
    if tx.submitter_did.is_empty() {
        return Err("Submitter DID cannot be empty".to_string());
    }

    if tx.signature.is_empty() {
        return Err("Signature is required".to_string());
    }

    Ok(())
}

/// Validates a SetDisputeAvailabilityTx.
pub fn validate_set_dispute_availability(tx: &SetDisputeAvailabilityTx) -> Result<(), String> {
    if tx.indexer_did.is_empty() {
        return Err("Indexer DID cannot be empty".to_string());
    }

    if tx.signature.is_empty() {
        return Err("Signature is required".to_string());
    }

    Ok(())
}
