use serde::{Deserialize, Serialize};

use super::types::DISPUTE_BOND;
use crate::consensus::indexing_transactions::EventInclusionProof;
use crate::indexer_node::consensus_submitter::BlockHeaderCommitment;

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
    #[serde(with = "crate::serde_helpers::u128_flexible")]
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
///
/// Evidence is carried as cryptographically-verifiable `EventInclusionProof`
/// values, each proving that a specific event was emitted in the disputed
/// block's receipts trie. The submitted `block_header` is cross-checked
/// against the Ethereum light client to derive the canonical `receipts_root`
/// against which the MPT proofs are verified. Both checks run inside the
/// consensus handler before the adjudicator re-executes the transformation
/// pipeline — an attacker cannot steer adjudication with fabricated or empty
/// evidence.
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
    /// Block header commitment for the single disputed block. Consensus
    /// cross-checks `state_root` and `receipts_root` against the Ethereum
    /// light client; the verified `receipts_root` is the trust anchor for
    /// the MPT proofs in `evidence_proofs`.
    pub block_header: BlockHeaderCommitment,
    /// MPT-proven event inclusion proofs for every event emitted in the
    /// disputed block that matches the subgrove's watched contracts. Each
    /// proof is independently verified against the light-client-derived
    /// `receipts_root`; only verified events feed the canonical
    /// re-execution. Must be non-empty — empty evidence is rejected by
    /// `validate_adjudicate_bisection`.
    pub evidence_proofs: Vec<EventInclusionProof>,
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

/// Build the canonical signed-message bytes for an `AdjudicateBisectionTx`.
///
/// Both the signer (indexer DisputeService) and the verifier (consensus
/// `TransactionSignatureValidator`) must produce the exact same message,
/// so this helper lives in `willow-types` where both can reach it.
///
/// The message binds `(dispute_id, submitter_did, nonce, block_header,
/// evidence_proofs)` — an interceptor cannot replace `evidence_proofs` or
/// `block_header` and re-broadcast the signed tx. The evidence set is
/// hashed to keep the message length bounded regardless of proof count.
pub fn adjudicate_bisection_signing_message(
    dispute_id: &[u8; 32],
    submitter_did: &str,
    nonce: u64,
    block_header: &BlockHeaderCommitment,
    evidence_proofs: &[EventInclusionProof],
) -> String {
    use sha2::{Digest, Sha256};

    let mut header_hasher = Sha256::new();
    header_hasher.update(block_header.block_number.to_le_bytes());
    header_hasher.update(block_header.block_hash);
    header_hasher.update(block_header.parent_hash);
    header_hasher.update(block_header.state_root);
    header_hasher.update(block_header.receipts_root);
    header_hasher.update(block_header.timestamp.to_le_bytes());
    let header_commitment: [u8; 32] = header_hasher.finalize().into();

    let mut evidence_hasher = Sha256::new();
    evidence_hasher.update((evidence_proofs.len() as u64).to_le_bytes());
    for proof in evidence_proofs {
        evidence_hasher.update(proof.block_number.to_le_bytes());
        evidence_hasher.update(proof.tx_hash);
        evidence_hasher.update(proof.tx_index.to_le_bytes());
        evidence_hasher.update(proof.log_index.to_le_bytes());
        evidence_hasher.update(proof.contract_address);
        for topic in &proof.topics {
            evidence_hasher.update(topic);
        }
        evidence_hasher.update((proof.data.len() as u64).to_le_bytes());
        evidence_hasher.update(&proof.data);
        evidence_hasher.update((proof.receipt.len() as u64).to_le_bytes());
        evidence_hasher.update(&proof.receipt);
    }
    let evidence_commitment: [u8; 32] = evidence_hasher.finalize().into();

    format!(
        "AdjudicateBisection\nDispute: {}\nSubmitter: {}\nNonce: {}\nBlockHeader: {}\nEvidence: {}",
        hex::encode(dispute_id),
        submitter_did,
        nonce,
        hex::encode(header_commitment),
        hex::encode(evidence_commitment)
    )
}

/// Validates an AdjudicateBisectionTx.
///
/// Structural validation only — cryptographic verification (light-client
/// header check, MPT proof verification, block-number consistency with the
/// stored dispute) runs in `process_adjudicate_bisection` where the
/// `GroveDb` and the light client are available.
///
/// Empty evidence is rejected: the adjudication step requires cryptographic
/// proof that consensus can re-execute the disputed block's events. Empty
/// evidence cannot be verified and cannot distinguish an honest-but-blocked
/// challenger from a malicious no-op submission, so the safe default is to
/// refuse the transaction at validation time.
pub fn validate_adjudicate_bisection(tx: &AdjudicateBisectionTx) -> Result<(), String> {
    if tx.submitter_did.is_empty() {
        return Err("Submitter DID cannot be empty".to_string());
    }

    if tx.signature.is_empty() {
        return Err("Signature is required".to_string());
    }

    if tx.evidence_proofs.is_empty() {
        return Err(
            "evidence_proofs cannot be empty — adjudication requires MPT-verified events \
             from the disputed block"
                .to_string(),
        );
    }

    let header_block = tx.block_header.block_number;
    for (i, proof) in tx.evidence_proofs.iter().enumerate() {
        if proof.block_number != header_block {
            return Err(format!(
                "evidence_proofs[{}] block_number {} does not match block_header.block_number {}",
                i, proof.block_number, header_block
            ));
        }
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

// ============================================================================
// Commitment Dispute Transactions (for private subgrove challenge-response)
// ============================================================================

/// Transaction to open a commitment dispute against a private subgrove provider.
///
/// Only current key grantees can open commitment disputes. The challenger
/// specifies a GroveDB path+key and demands the provider prove their committed
/// state_root is backed by a real data tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenCommitmentDisputeTx {
    /// Subgrove being disputed.
    pub subgrove_id: String,
    /// DID of the challenger (must be a current key grantee).
    pub challenger_did: String,
    /// GroveDB path within the subgrove to challenge.
    pub challenge_path: Vec<Vec<u8>>,
    /// Specific key at that path to challenge.
    pub challenge_key: Vec<u8>,
    /// Bond amount being posted (must be >= COMMITMENT_DISPUTE_BOND).
    #[serde(with = "crate::serde_helpers::u128_flexible")]
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

/// Transaction for a provider to respond to a commitment dispute with a GroveDB proof.
///
/// The proof must verify against the committed state_root for the challenged path+key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespondCommitmentDisputeTx {
    /// The dispute being responded to.
    pub dispute_id: [u8; 32],
    /// DID of the provider responding.
    pub provider_did: String,
    /// Serialized GroveDB proof bytes for the challenged path+key.
    pub grovedb_proof: Vec<u8>,
    /// Cryptographic signature from the provider.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Validates an OpenCommitmentDisputeTx.
pub fn validate_open_commitment_dispute(tx: &OpenCommitmentDisputeTx) -> Result<(), String> {
    use super::types::COMMITMENT_DISPUTE_BOND;

    if tx.subgrove_id.is_empty() {
        return Err("Subgrove ID cannot be empty".to_string());
    }
    if tx.challenger_did.is_empty() {
        return Err("Challenger DID cannot be empty".to_string());
    }
    if tx.challenge_key.is_empty() {
        return Err("Challenge key cannot be empty".to_string());
    }
    if tx.bond_amount < COMMITMENT_DISPUTE_BOND {
        return Err(format!(
            "Bond amount {} is less than required {}",
            tx.bond_amount, COMMITMENT_DISPUTE_BOND
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

/// Validates a RespondCommitmentDisputeTx.
pub fn validate_respond_commitment_dispute(tx: &RespondCommitmentDisputeTx) -> Result<(), String> {
    if tx.provider_did.is_empty() {
        return Err("Provider DID cannot be empty".to_string());
    }
    if tx.grovedb_proof.is_empty() {
        return Err("GroveDB proof cannot be empty".to_string());
    }
    if tx.signature.is_empty() {
        return Err("Signature is required".to_string());
    }
    Ok(())
}
