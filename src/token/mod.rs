//! Core types for the WILL token system.
//!
//! Defines token state, balances, transfers, staking info, fee schedules,
//! and reward distribution structures.

pub mod units;

use serde::{Deserialize, Serialize};

/// Token name.
pub const TOKEN_NAME: &str = "Willow Token";
/// Token symbol.
pub const TOKEN_SYMBOL: &str = "WILL";
/// Number of decimal places (18, like Ethereum).
pub const TOKEN_DECIMALS: u8 = 18;
/// Genesis allocation (400 million WILL).
/// This is the pre-mined supply distributed at genesis (team, treasury, ecosystem).
pub const INITIAL_SUPPLY: u128 = 400_000_000 * 10u128.pow(TOKEN_DECIMALS as u32);
/// Hard cap on total WILL supply (1 billion WILL).
pub const MAX_SUPPLY: u128 = 1_000_000_000 * 10u128.pow(TOKEN_DECIMALS as u32);
/// Total tokens reserved for block reward emissions.
pub const EMISSION_SUPPLY: u128 = MAX_SUPPLY - INITIAL_SUPPLY;
/// Blocks between halvings (~4 years at 1 second block time).
pub const HALVING_INTERVAL: u64 = 126_144_000;
/// Number of halvings before block reward effectively reaches zero.
pub const MAX_HALVINGS: u32 = 64;
/// DID of the protocol treasury.
pub const TREASURY_DID: &str = "did:willow:treasury";

/// Global token state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenState {
    /// Token name.
    pub name: String,
    /// Token symbol.
    pub symbol: String,
    /// Decimal places.
    pub decimals: u8,
    /// Genesis allocation (pre-mined supply distributed at chain start).
    pub genesis_supply: u128,
    /// Cumulative tokens minted via block rewards.
    pub minted_supply: u128,
}

impl TokenState {
    /// Returns the circulating supply: genesis allocation + minted block rewards.
    pub fn circulating_supply(&self) -> u128 {
        self.genesis_supply + self.minted_supply
    }
}

/// Account balance with available, staked, and locked amounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balance {
    /// Account DID.
    pub did: String,
    /// Available (spendable) balance.
    pub available: u128,
    /// Amount staked with validators.
    pub staked: u128,
    /// Amount locked (unbonding).
    pub locked: u128,
}

/// Token transfer record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transfer {
    /// Sender DID.
    pub from: String,
    /// Recipient DID.
    pub to: String,
    /// Transfer amount.
    pub amount: u128,
    /// Transfer fee paid.
    pub fee: u128,
    /// Optional memo.
    pub memo: Option<String>,
    /// Unix timestamp.
    pub timestamp: u64,
}

/// Staking position information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeInfo {
    /// Validator receiving the stake.
    pub validator_did: String,
    /// Staked amount.
    pub amount: u128,
    /// When staking began.
    pub start_timestamp: u64,
    /// When unbonding started (if unbonding).
    pub unbonding_timestamp: Option<u64>,
    /// Total rewards earned.
    pub rewards_earned: u128,
}

/// Fee schedule defining costs for various operations.
///
/// Uses a cost-based model: `fee = base_tx_cost + (bytes_written × cost_per_byte)`
///
/// Parameters derived from: 30 validators, 10-year storage horizon, 10x profit margin, $0.10 WILL price.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeSchedule {
    /// Fee to register a DID (identity).
    pub did_registration: u128,
    /// Fee to register a subgrove.
    pub subgrove_registration: u128,
    /// Base cost per transaction (covers consensus overhead).
    pub base_tx_cost: u128,
    /// Cost per byte of data written to storage.
    pub cost_per_byte: u128,
    /// Fee per query after rate limit.
    pub query_fee: u128,
    /// Transfer fee in basis points (1/10000).
    pub transfer_fee_percentage: u32,
    /// Maximum transaction size in bytes.
    pub max_tx_size_bytes: u64,
    /// Maximum data payload size in bytes (for StoreData/UpdateData).
    pub max_data_payload_bytes: u64,
}

/// Estimated bytes written for a key grant operation.
pub const KEY_GRANT_ESTIMATED_BYTES: u64 = 250;
/// Estimated bytes written for a key revoke operation.
pub const KEY_REVOKE_ESTIMATED_BYTES: u64 = 250;
/// Base bytes for a key rotation operation (epoch update + grant deletion).
pub const KEY_ROTATE_BASE_BYTES: u64 = 100;
/// Estimated bytes per new grant in a key rotation.
pub const KEY_ROTATE_PER_GRANT_BYTES: u64 = 220;
/// Estimated bytes for a private subgrove commitment.
pub const COMMITMENT_ESTIMATED_BYTES: u64 = 200;
/// Estimated bytes for a re-execution verification.
pub const REEXECUTION_ESTIMATED_BYTES: u64 = 1200;
/// Estimated bytes for a file manifest stored on-chain.
pub const FILE_MANIFEST_ESTIMATED_BYTES: u64 = 500;

impl Default for FeeSchedule {
    fn default() -> Self {
        Self {
            did_registration: 10u128.pow(TOKEN_DECIMALS as u32), // 1 WILL
            subgrove_registration: 100 * 10u128.pow(TOKEN_DECIMALS as u32), // 100 WILL
            base_tx_cost: 24_000_000_000_000_000,                // 0.024 WILL
            cost_per_byte: 86_400_000_000_000,                   // 0.0000864 WILL
            query_fee: 4_000_000_000_000_000,                    // 0.004 WILL
            transfer_fee_percentage: 10,                         // 0.1%
            max_tx_size_bytes: 67_108_864,                       // 64 MB
            max_data_payload_bytes: 524_288,                     // 512 KB
        }
    }
}

/// Subgrove funding account for paying storage/query fees.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubgroveFunding {
    /// Subgrove ID.
    pub subgrove_id: String,
    /// Current balance available.
    pub balance: u128,
    /// Total amount spent.
    pub total_spent: u128,
    /// Last funding timestamp.
    pub last_funded: u64,
}

/// Query rate limit tracking per user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryRateLimit {
    /// User DID.
    pub did: String,
    /// Free queries remaining this period.
    pub free_queries_remaining: u32,
    /// Paid queries made this period.
    pub paid_queries_count: u32,
    /// When the rate limit resets.
    pub reset_timestamp: u64,
}

impl Default for QueryRateLimit {
    fn default() -> Self {
        Self {
            did: String::new(),
            free_queries_remaining: FREE_QUERIES_PER_DAY,
            paid_queries_count: 0,
            reset_timestamp: 0,
        }
    }
}

/// Token operation utilities.
pub struct TokenOperations;

impl TokenOperations {
    /// Calculates the transfer fee based on amount and fee schedule.
    /// Uses checked arithmetic to prevent overflow for large amounts.
    pub fn calculate_transfer_fee(amount: u128, fee_schedule: &FeeSchedule) -> u128 {
        let percentage = fee_schedule.transfer_fee_percentage as u128;
        // Use checked_mul to prevent overflow for large amounts.
        // If overflow would occur, compute using integer division first
        // to avoid losing precision only when necessary.
        match amount.checked_mul(percentage) {
            Some(product) => product / 10000,
            None => (amount / 10000) * percentage + (amount % 10000) * percentage / 10000,
        }
    }

    /// Calculates the write fee: base_tx_cost + bytes × cost_per_byte.
    pub fn calculate_write_fee(bytes: u64, fee_schedule: &FeeSchedule) -> u128 {
        fee_schedule.base_tx_cost + bytes as u128 * fee_schedule.cost_per_byte
    }

    /// Calculates the operation fee for non-data operations using estimated byte counts.
    pub fn calculate_operation_fee(estimated_bytes: u64, fee_schedule: &FeeSchedule) -> u128 {
        fee_schedule.base_tx_cost + estimated_bytes as u128 * fee_schedule.cost_per_byte
    }

    /// Calculates the write fee with retention-based storage cost discount.
    ///
    /// The per-byte component is scaled by the retention window's storage cost fraction.
    /// The base_tx_cost is always charged in full (covers consensus processing).
    pub fn calculate_write_fee_with_retention(
        bytes: u64,
        fee_schedule: &FeeSchedule,
        retention: &crate::consensus::indexing_transactions::RetentionWindow,
    ) -> u128 {
        let (num, den) = retention.storage_cost_fraction();
        let storage_cost = bytes as u128 * fee_schedule.cost_per_byte * num / den;
        fee_schedule.base_tx_cost + storage_cost
    }

    /// Validates that a balance has sufficient available funds.
    pub fn validate_balance(balance: &Balance, required_amount: u128) -> Result<(), String> {
        if balance.available < required_amount {
            return Err(format!(
                "Insufficient balance. Available: {}, Required: {}",
                balance.available, required_amount
            ));
        }
        Ok(())
    }

    /// Returns whether the balance has enough available to stake.
    pub fn can_stake(balance: &Balance, amount: u128) -> bool {
        balance.available >= amount
    }

    /// Moves tokens from available to staked.
    pub fn stake_tokens(balance: &mut Balance, amount: u128) -> Result<(), String> {
        if !Self::can_stake(balance, amount) {
            return Err("Insufficient available balance for staking".to_string());
        }
        balance.available -= amount;
        balance.staked += amount;
        Ok(())
    }

    /// Moves tokens from staked to available.
    pub fn unstake_tokens(balance: &mut Balance, amount: u128) -> Result<(), String> {
        if balance.staked < amount {
            return Err("Insufficient staked balance".to_string());
        }
        balance.staked -= amount;
        balance.available += amount;
        Ok(())
    }
}

/// Validator reward tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorRewards {
    /// Validator DID.
    pub validator_did: String,
    /// Total block rewards earned.
    pub block_rewards: u128,
    /// Total fee rewards earned.
    pub fee_rewards: u128,
    /// Total blocks validated.
    pub total_blocks_validated: u64,
    /// Last block where rewards were received.
    pub last_reward_block: u64,
}

/// Fee distribution configuration (how collected fees are split).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardDistribution {
    /// Validator share of fees in basis points (1/10000).
    pub validators_share: u32,
    /// Treasury share of fees in basis points.
    pub treasury_share: u32,
}

impl Default for RewardDistribution {
    fn default() -> Self {
        Self {
            validators_share: 9000, // 90%
            treasury_share: 1000,   // 10%
        }
    }
}

// ============================================================================
// Pay-Gated Reads / x402 Types
// ============================================================================

/// Pricing configuration for paid reads on a subgrove.
///
/// When enabled, users not on the `free_readers` list must pay per query.
/// Revenue is split between the subgrove owner and the protocol treasury.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadPricing {
    /// Whether paid reads are enabled for this subgrove.
    pub enabled: bool,
    /// Price per query in smallest WILL token units (10^-18 WILL).
    pub price_per_query: u128,
    /// Owner's share of revenue in basis points (0-10000, where 10000 = 100%).
    /// The remainder goes to the protocol treasury.
    pub owner_revenue_share_bps: u32,
}

impl Default for ReadPricing {
    fn default() -> Self {
        Self {
            enabled: false,
            price_per_query: 0,
            owner_revenue_share_bps: 8000, // 80% to owner, 20% to treasury
        }
    }
}

/// x402 Payment Required response following the x402 protocol.
///
/// Returned with HTTP 402 status when a read requires payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402PaymentRequired {
    /// Protocol version.
    pub version: String,
    /// List of accepted payment schemes.
    pub accepts: Vec<X402PaymentScheme>,
}

/// A single payment scheme accepted by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402PaymentScheme {
    /// Payment scheme type (e.g., "exact").
    pub scheme: String,
    /// Network identifier (e.g., "willow").
    pub network: String,
    /// Payment amount in smallest units as a string.
    pub amount: String,
    /// Recipient identifier (subgrove owner DID).
    pub recipient: String,
    /// Asset type ("WILL").
    pub asset: String,
    /// Human-readable description of what the payment is for.
    pub description: String,
    /// Unique payment request ID for idempotency.
    pub payment_id: String,
    /// Expiration timestamp (Unix seconds).
    pub expires_at: u64,
}

/// Client payment payload sent in X-PAYMENT header.
///
/// This is base64-encoded JSON included in the request header
/// when paying for a read operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402PaymentPayload {
    /// Payment request ID being fulfilled.
    pub payment_id: String,
    /// Payer DID.
    pub payer_did: String,
    /// Amount being paid as a string.
    pub amount: String,
    /// Cryptographic signature authorizing the payment.
    pub signature: Vec<u8>,
    /// Public key ID used for signing.
    pub public_key_id: String,
    /// Nonce for replay protection.
    pub nonce: u64,
    /// Timestamp when signed (Unix seconds).
    pub timestamp: u64,
}

/// Payment response included in successful read responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402PaymentResponse {
    /// Whether payment was successful.
    pub success: bool,
    /// Transaction ID for the payment.
    pub transaction_id: Option<String>,
    /// Amount actually charged as a string.
    pub amount_charged: Option<String>,
    /// Error message if payment failed.
    pub error: Option<String>,
}

/// Record of a completed read payment for auditing and analytics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadPaymentRecord {
    /// Unique payment ID.
    pub payment_id: String,
    /// Subgrove that was accessed.
    pub subgrove_id: String,
    /// DID that paid for the read.
    pub payer_did: String,
    /// Total amount paid.
    pub amount: u128,
    /// Amount distributed to the subgrove owner.
    pub owner_share: u128,
    /// Amount distributed to the protocol treasury.
    pub treasury_share: u128,
    /// Unix timestamp of the payment.
    pub timestamp: u64,
}

// ============================================================================
// Staking Types
// ============================================================================

/// Minimum stake required to become a validator (100,000 WILL).
pub const MIN_VALIDATOR_STAKE: u128 = 100_000 * 10u128.pow(18);
/// Unbonding period duration (7 days).
pub const UNBONDING_PERIOD_SECONDS: u64 = 7 * 24 * 3600;

/// Validator information and state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator DID.
    pub did: String,
    /// Total stake (equals self_stake).
    pub total_stake: u128,
    /// Validator's own stake.
    pub self_stake: u128,
    /// Whether the validator is active.
    pub active: bool,
    /// Whether the validator is jailed.
    pub jailed: bool,
    /// When the jail period ends (Unix timestamp).
    pub jail_end_time: Option<u64>,
    /// Consensus public key.
    pub consensus_pubkey: Option<String>,
}

/// Unbonding entry (validator self-unstaking in the unbonding period).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnbondingDelegation {
    /// Delegator DID.
    pub delegator_did: String,
    /// Validator DID.
    pub validator_did: String,
    /// Amount being unbonded.
    pub amount: u128,
    /// When unbonding completes (Unix timestamp).
    pub completion_time: u64,
}

// ============================================================================
// Fee Audit Types
// ============================================================================

/// Record of a collected fee.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeCollection {
    /// Type of fee collected.
    pub fee_type: FeeType,
    /// DID of the fee payer.
    pub payer_did: String,
    /// Fee amount.
    pub amount: u128,
    /// When the fee was collected (Unix timestamp).
    pub timestamp: u64,
    /// Associated transaction ID.
    pub transaction_id: String,
    /// Optional metadata.
    pub metadata: Option<String>,
    /// Optional memo.
    pub memo: Option<String>,
    /// How the fee was distributed.
    pub distribution: Option<FeeDistribution>,
}

/// How a fee was distributed among recipients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeDistribution {
    /// Amount distributed to validators.
    pub validators: u128,
    /// Amount distributed to treasury.
    pub treasury: u128,
}

/// Treasury's share of query fees, in percent.
pub const QUERY_FEE_TREASURY_PERCENT: u128 = 10;

/// Daily free query limit per DID.
pub const FREE_QUERIES_PER_DAY: u32 = 500;

/// Type of fee being collected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FeeType {
    /// DID registration fee.
    DidRegistration,
    /// Subgrove registration fee.
    SubgroveRegistration,
    /// Data storage fee based on size.
    DataStorage {
        /// Size in bytes.
        size_bytes: u64,
    },
    /// Query fee.
    Query,
    /// Transfer fee.
    Transfer,
    /// Private subgrove key grant fee.
    PrivateKeyGrant,
    /// Private subgrove key revoke fee.
    PrivateKeyRevoke,
    /// Private subgrove key rotation fee.
    PrivateKeyRotate,
    /// Private subgrove commitment fee.
    PrivateCommitment,
    /// File manifest storage fee.
    FileManifestStorage,
    /// Content moderation (block/unblock/report) fee.
    ContentModeration,
}

// ============================================================================
// Transformation / Slashing Types
// ============================================================================

/// Result of transformation execution or verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformationResult {
    /// Whether execution was performed.
    pub execution_performed: bool,
    /// Whether this was selected by sampling.
    pub was_sampling_selected: bool,
    /// Whether verification passed.
    pub verification_passed: bool,
    /// Expected hash from the indexer submission.
    pub expected_hash: Option<[u8; 32]>,
    /// Actual hash computed during verification.
    pub actual_hash: Option<[u8; 32]>,
    /// Details about what mismatched, if any.
    pub mismatch_details: Option<MismatchDetails>,
    /// Sampling seed used for selection.
    pub sampling_seed: [u8; 32],
    /// Block numbers that were processed.
    pub processed_blocks: Vec<u64>,
}

/// Details about what mismatched during verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MismatchDetails {
    /// Index of the batch where mismatch occurred.
    pub batch_index: u32,
    /// Block range of the mismatched batch.
    pub block_range: (u64, u64),
    /// Field that mismatched, if identifiable.
    pub field: Option<String>,
    /// Human-readable description of the mismatch.
    pub description: String,
}

/// Slashing action created when verification fails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingAction {
    /// DID of the indexer being slashed.
    pub indexer_did: String,
    /// Subgrove where the violation occurred.
    pub subgrove_id: String,
    /// Reason for slashing.
    pub reason: String,
    /// Evidence from the transformation verification.
    pub evidence: TransformationResult,
    /// Amount to slash.
    pub slash_amount: u128,
    /// When the slashing occurred (Unix timestamp).
    pub timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_fee_calculation() {
        let fee_schedule = FeeSchedule::default();
        let amount = 1000 * 10u128.pow(TOKEN_DECIMALS as u32);
        let fee = TokenOperations::calculate_transfer_fee(amount, &fee_schedule);
        assert_eq!(fee, 10u128.pow(TOKEN_DECIMALS as u32)); // 1 WILL fee
    }

    #[test]
    fn test_calculate_write_fee() {
        let schedule = FeeSchedule::default();

        // 0 bytes: just the base cost
        assert_eq!(
            TokenOperations::calculate_write_fee(0, &schedule),
            schedule.base_tx_cost
        );

        // 1024 bytes (1 KB)
        let fee_1kb = TokenOperations::calculate_write_fee(1024, &schedule);
        let expected_1kb = schedule.base_tx_cost + 1024 * schedule.cost_per_byte;
        assert_eq!(fee_1kb, expected_1kb);

        // 100 bytes (small write — should be cheaper than old 1KB minimum)
        let fee_100b = TokenOperations::calculate_write_fee(100, &schedule);
        assert_eq!(
            fee_100b,
            schedule.base_tx_cost + 100 * schedule.cost_per_byte
        );
    }

    #[test]
    fn test_calculate_operation_fee() {
        let schedule = FeeSchedule::default();

        let key_grant_fee =
            TokenOperations::calculate_operation_fee(KEY_GRANT_ESTIMATED_BYTES, &schedule);
        assert_eq!(
            key_grant_fee,
            schedule.base_tx_cost + KEY_GRANT_ESTIMATED_BYTES as u128 * schedule.cost_per_byte
        );

        // Key rotation scales with number of grants
        let rotate_5 = KEY_ROTATE_BASE_BYTES + KEY_ROTATE_PER_GRANT_BYTES * 5;
        let rotate_10 = KEY_ROTATE_BASE_BYTES + KEY_ROTATE_PER_GRANT_BYTES * 10;
        let fee_5 = TokenOperations::calculate_operation_fee(rotate_5, &schedule);
        let fee_10 = TokenOperations::calculate_operation_fee(rotate_10, &schedule);
        assert!(fee_10 > fee_5);
    }

    #[test]
    fn test_staking_operations() {
        let mut balance = Balance {
            did: "did:willow:test".to_string(),
            available: 1000 * 10u128.pow(TOKEN_DECIMALS as u32),
            staked: 0,
            locked: 0,
        };

        let stake_amount = 500 * 10u128.pow(TOKEN_DECIMALS as u32);
        assert!(TokenOperations::stake_tokens(&mut balance, stake_amount).is_ok());
        assert_eq!(balance.staked, stake_amount);
        assert_eq!(balance.available, stake_amount);

        assert!(TokenOperations::unstake_tokens(&mut balance, stake_amount).is_ok());
        assert_eq!(balance.staked, 0);
        assert_eq!(balance.available, 1000 * 10u128.pow(TOKEN_DECIMALS as u32));
    }
}
