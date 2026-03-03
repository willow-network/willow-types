//! Core types for the Ethereum bridge.
//!
//! This module defines all data structures used by the bridge including:
//!
//! - **Block Headers**: Ethereum block header representation
//! - **Proofs**: MPT proofs for receipts and finality verification
//! - **Events**: Parsed Ethereum events (StakeLocked)
//! - **Withdrawals**: Request, batch, and signature structures
//! - **State**: Bridge operational state and validator sets
//!
//! # Proof Types
//!
//! The bridge uses two types of cryptographic proofs:
//!
//! 1. **Receipt Proofs**: MPT proofs demonstrating a transaction receipt
//!    exists in a block's receipts trie
//! 2. **Finality Proofs**: Evidence that a block is finalized (32+ confirmations
//!    or sync committee signature)
//!
//! # Security Constants
//!
//! - `MIN_FINALITY_BLOCKS` (20): Minimum confirmations for deposit acceptance
//! - `MAX_FINALITY_BLOCKS` (1000): Upper bound to prevent overflow attacks

use serde::{Deserialize, Serialize};

// Security constants

/// Minimum required block confirmations for deposit acceptance.
/// Set to 20 to ensure sufficient protection against chain reorganizations.
const MIN_FINALITY_BLOCKS: u64 = 20;

/// Maximum allowed finality blocks to prevent overflow in calculations.
const MAX_FINALITY_BLOCKS: u64 = 1000;

/// Ethereum block header for proof verification.
///
/// Contains the essential fields needed to verify receipt proofs
/// and establish block finality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumBlockHeader {
    pub number: u64,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub timestamp: u64,
    pub state_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub gas_limit: u128,
    pub gas_used: u128,
    pub base_fee_per_gas: Option<u128>,
}

/// Merkle Patricia Trie proof for a transaction receipt.
///
/// Used to prove that a specific transaction receipt exists in
/// a block's receipts trie without downloading all receipts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptProof {
    pub transaction_hash: [u8; 32],
    pub receipt_index: u64,
    pub proof: Vec<Vec<u8>>,
    pub receipt_rlp: Vec<u8>,
}

/// Complete proof for a deposit (stake lock) event.
///
/// Combines block header, receipt proof, and finality evidence
/// to prove a deposit occurred on Ethereum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeProof {
    pub eth_block_header: EthereumBlockHeader,
    pub receipt_proof: ReceiptProof,
    pub log_index: u64,
    pub finality_proof: Option<FinalityProof>,
}

/// Proof of Ethereum block finality.
///
/// For post-merge Ethereum, this can include sync committee signatures.
/// For pre-merge or when signatures aren't available, confirmation
/// count is used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityProof {
    pub checkpoint_header: EthereumBlockHeader,
    pub finality_confirmations: u64,
    pub sync_committee_signature: Option<Vec<u8>>,
}

/// Parsed StakeLocked event from the Ethereum bridge contract.
///
/// Emitted when a user locks WILL tokens on Ethereum to receive
/// them on the Willow network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeLockEvent {
    pub user: [u8; 20],
    pub amount: u128,
    pub willow_recipient: Vec<u8>,
    pub block_number: u64,
    pub transaction_hash: [u8; 32],
    pub log_index: u64,
}

/// Request to withdraw tokens from Willow to Ethereum.
///
/// Created when a user burns tokens on Willow. The request enters
/// a pending queue until included in a signed withdrawal batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalRequest {
    pub willow_sender: String,
    pub eth_recipient: [u8; 20],
    pub amount: u128,
    pub nonce: u64,
    pub timestamp: u64,
    pub request_id: [u8; 32],
}

/// Batch of withdrawals ready for Ethereum submission.
///
/// Multiple withdrawal requests are batched together for efficiency.
/// The batch includes a merkle root of all requests and threshold
/// signatures from validators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalBatch {
    pub batch_id: [u8; 32],
    pub merkle_root: [u8; 32],
    pub requests: Vec<WithdrawalRequest>,
    pub block_height: u64,
    pub timestamp: u64,
    pub validator_signatures: Vec<ValidatorSignature>,
}

/// Cryptographic signature from a bridge validator.
///
/// Validators sign the merkle root of withdrawal batches. The bridge
/// requires threshold signatures before a batch can be submitted
/// to Ethereum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSignature {
    pub validator_did: String,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Global bridge operational state.
///
/// Tracks the current state of the bridge including processed blocks,
/// token totals, and configuration. Stored in GroveDB and updated
/// atomically with each bridge operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeState {
    pub eth_bridge_address: Option<[u8; 20]>,
    pub last_processed_eth_block: u64,
    pub total_locked_on_ethereum: u128,
    pub total_minted_on_willow: u128,
    pub withdrawal_nonce: u64,
    pub validator_set_epoch: u64,
    pub finality_delay_blocks: u64,
}

impl Default for BridgeState {
    fn default() -> Self {
        Self {
            eth_bridge_address: None,
            last_processed_eth_block: 0,
            total_locked_on_ethereum: 0,
            total_minted_on_willow: 0,
            withdrawal_nonce: 0,
            validator_set_epoch: 0,
            finality_delay_blocks: 32, // Ethereum finality delay
        }
    }
}

impl BridgeState {
    /// Sets the finality delay with security validation.
    ///
    /// The finality delay determines how many Ethereum blocks must pass
    /// before a deposit is considered final. This protects against
    /// chain reorganizations.
    ///
    /// # Limits
    ///
    /// - Minimum: 20 blocks (security requirement)
    /// - Maximum: 1000 blocks (overflow prevention)
    ///
    /// # Errors
    ///
    /// Returns an error if the delay is outside valid bounds.
    pub fn set_finality_delay(&mut self, delay: u64) -> Result<(), String> {
        if delay < MIN_FINALITY_BLOCKS {
            return Err(format!(
                "Finality delay must be at least {} blocks for security",
                MIN_FINALITY_BLOCKS
            ));
        }
        if delay > MAX_FINALITY_BLOCKS {
            return Err(format!(
                "Finality delay cannot exceed {} blocks",
                MAX_FINALITY_BLOCKS
            ));
        }
        self.finality_delay_blocks = delay;
        Ok(())
    }

    /// Validates that the current finality delay meets security requirements.
    ///
    /// Should be called before processing deposits to ensure the bridge
    /// hasn't been misconfigured.
    pub fn validate_finality_delay(&self) -> Result<(), String> {
        if self.finality_delay_blocks < MIN_FINALITY_BLOCKS {
            return Err(format!(
                "Current finality delay ({}) is below minimum required ({})",
                self.finality_delay_blocks, MIN_FINALITY_BLOCKS
            ));
        }
        Ok(())
    }
}

/// Set of validators authorized to sign bridge operations.
///
/// The validator set is versioned by epoch and requires threshold
/// signatures for withdrawal batches. Validator sets are rotated
/// periodically or when the consensus validator set changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeValidatorSet {
    pub epoch: u64,
    pub validators: Vec<BridgeValidator>,
    pub threshold: u64,
    pub created_at_height: u64,
}

/// Individual validator in the bridge validator set.
///
/// Each validator has a public key for signature verification and
/// voting power proportional to their stake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeValidator {
    pub did: String,
    pub public_key: Vec<u8>,
    pub voting_power: u128,
    pub is_active: bool,
}

/// Generic Ethereum Merkle Patricia Trie proof.
///
/// Used for verifying state, storage, or receipt proofs against
/// a known root hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumMPTProof {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub proof: Vec<Vec<u8>>,
    pub root: [u8; 32],
}

/// Record of a processed deposit from Ethereum.
///
/// Stored to prevent replay attacks (processing the same deposit twice).
/// Indexed by (tx_hash, block_number, log_index) for uniqueness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessedDeposit {
    pub eth_tx_hash: [u8; 32],
    pub eth_block_number: u64,
    pub eth_log_index: u64,
    pub willow_recipient: String,
    pub amount: u128,
    pub processed_at_height: u64,
    pub processed_at_timestamp: u64,
}

/// Withdrawal request awaiting batch inclusion.
///
/// Tokens have already been burned from the sender's balance.
/// The withdrawal waits in the pending queue until validators
/// batch it and sign for Ethereum release.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingWithdrawal {
    pub request_id: [u8; 32],
    pub willow_sender: String,
    pub eth_recipient: [u8; 20],
    pub amount: u128,
    pub nonce: u64,
    pub created_at_height: u64,
    pub created_at_timestamp: u64,
    pub included_in_batch: Option<[u8; 32]>,
}

// NOTE: BridgeOperations impl with proof verification, signature verification,
// and other heavy-dependency logic lives in the main willow crate's bridge module.
