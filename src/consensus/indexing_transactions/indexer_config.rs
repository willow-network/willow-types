use serde::{Deserialize, Serialize};

use super::execution_modes::ExecutionMode;

/// Transaction to register as a blockchain indexer.
///
/// Indexers must stake a minimum of 100,000 WILL tokens and specify which
/// subgroves they will index. The stake can be slashed if the indexer
/// submits incorrect data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterIndexerTx {
    /// The DID of the indexer (must start with "did:willow:").
    pub indexer_did: String,
    /// List of subgrove IDs this indexer will process.
    pub subgroves: Vec<String>,
    /// Amount of WILL tokens to stake (minimum 100,000 WILL).
    pub stake_amount: u128,
    /// HTTP endpoint for monitoring and health checks.
    pub endpoint: String,
    /// Ethereum RPC endpoint the indexer will use for fetching data.
    pub ethereum_rpc: String,
    /// Cryptographic signature over the transaction.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Configuration for indexer requirements and rewards.
///
/// Specifies how many indexers should process this subgrove and
/// what rewards they receive. Multiple indexers provide redundancy
/// and help ensure data completeness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexerConfig {
    /// Minimum number of indexers required (1-10). Default: 1.
    /// Multiple indexers provide redundancy and help detect omissions.
    pub min_indexers: u8,

    /// Maximum number of indexers allowed (1-10). Default: 3.
    /// More indexers increase redundancy but also cost.
    pub max_indexers: u8,

    /// Reward per block indexed in WILL (smallest unit).
    /// Higher rewards attract more indexers to bid on this subgrove.
    pub reward_per_block: u128,

    /// Minimum stake required from each indexer in WILL (smallest unit).
    /// Higher stake requirements increase indexer accountability.
    pub min_indexer_stake: u128,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            min_indexers: 1,
            max_indexers: 3,
            reward_per_block: 1_000_000_000_000_000, // 0.001 WILL
            min_indexer_stake: 100_000_000_000_000_000_000_000, // 100k WILL
        }
    }
}

impl IndexerConfig {
    /// Validate the indexer configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.min_indexers == 0 {
            return Err("min_indexers must be at least 1".to_string());
        }
        if self.max_indexers == 0 {
            return Err("max_indexers must be at least 1".to_string());
        }
        if self.min_indexers > self.max_indexers {
            return Err("min_indexers cannot exceed max_indexers".to_string());
        }
        if self.max_indexers > 10 {
            return Err("max_indexers cannot exceed 10".to_string());
        }
        if self.reward_per_block == 0 {
            return Err("reward_per_block must be greater than 0".to_string());
        }
        Ok(())
    }

    /// Get the recommended indexer configuration for a given execution mode.
    ///
    /// Different modes have different indexer requirements based on trust model:
    /// - ConsensusExecution: Validators do transformation work, fewer indexers needed
    /// - IndexerExecution: Sampling-based verification, more indexers for redundancy
    pub fn recommended_for_mode(mode: &ExecutionMode) -> Self {
        match mode {
            // Consensus execution: validators do the work
            ExecutionMode::ConsensusExecution => Self {
                min_indexers: 1,
                max_indexers: 2,
                reward_per_block: 800_000_000_000_000, // Lower since consensus does transformation
                min_indexer_stake: 100_000_000_000_000_000_000_000, // 100k WILL
            },
            // Indexer execution with sampling: multiple indexers for redundancy
            ExecutionMode::IndexerExecution {
                sampling_rate_percent,
            } => {
                let redundancy = if *sampling_rate_percent < 10 {
                    3 // Low sampling needs more redundancy
                } else if *sampling_rate_percent < 30 {
                    2
                } else {
                    1 // High sampling rate provides good verification
                };
                Self {
                    min_indexers: redundancy,
                    max_indexers: redundancy + 2,
                    reward_per_block: 1_000_000_000_000_000,
                    min_indexer_stake: 100_000_000_000_000_000_000_000,
                }
            }
            // TEE execution: hardware provides trust, fewer indexers needed
            ExecutionMode::TeeExecution { .. } => Self {
                min_indexers: 1,
                max_indexers: 2,
                reward_per_block: 600_000_000_000_000, // Lower since TEE provides instant trust
                min_indexer_stake: 100_000_000_000_000_000_000_000, // 100k WILL
            },
            // GKR execution: cryptographic proof, no redundancy needed
            ExecutionMode::GkrExecution => Self {
                min_indexers: 1,
                max_indexers: 1,
                reward_per_block: 1_200_000_000_000_000, // Higher to compensate proof generation cost
                min_indexer_stake: 100_000_000_000_000_000_000_000, // 100k WILL
            },
        }
    }
}

/// Fee distribution percentages for different execution modes.
///
/// The fee split varies based on how much work validators need to do:
/// - ConsensusExecution: Validators execute the transformation (expensive)
/// - IndexerExecution: Validators sample and verify (moderate)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FeeDistributionRates {
    /// Percentage of fees going to the indexer (0-100).
    pub indexer_percent: u8,
    /// Percentage of fees going to validators (0-100).
    pub validator_percent: u8,
    /// Percentage of fees going to the network treasury (0-100).
    pub treasury_percent: u8,
}

impl Default for FeeDistributionRates {
    fn default() -> Self {
        Self {
            indexer_percent: 70,
            validator_percent: 20,
            treasury_percent: 10,
        }
    }
}

impl FeeDistributionRates {
    /// Get the fee distribution rates for a given execution mode.
    ///
    /// For `ConsensusExecution`, validators get a higher share (30%) since they
    /// perform the actual transformation work.
    ///
    /// For `IndexerExecution`, indexers get a higher share (70%) since they do
    /// the transformation work and validators only sample-verify.
    pub fn for_mode(mode: &ExecutionMode) -> Self {
        match mode {
            // Consensus execution: validators do the transformation work
            // Indexer gets 60%, validators get 30% (for transformation), treasury 10%
            ExecutionMode::ConsensusExecution => Self {
                indexer_percent: 60,
                validator_percent: 30,
                treasury_percent: 10,
            },
            // Indexer execution with sampling: balanced distribution
            // Indexer gets 70%, validators get 20% (for sampling), treasury 10%
            ExecutionMode::IndexerExecution { .. } => Self {
                indexer_percent: 70,
                validator_percent: 20,
                treasury_percent: 10,
            },
            // TEE execution: hardware attestation provides trust
            // Indexer gets 75%, validators get 15% (minimal verification), treasury 10%
            ExecutionMode::TeeExecution { .. } => Self {
                indexer_percent: 75,
                validator_percent: 15,
                treasury_percent: 10,
            },
            // GKR execution: cryptographic proof provides trust
            // Indexer gets 85% (transformation + proof generation), validators get 5% (proof verification only), treasury 10%
            ExecutionMode::GkrExecution => Self {
                indexer_percent: 85,
                validator_percent: 5,
                treasury_percent: 10,
            },
        }
    }

    /// Calculate the actual fee amounts for a total fee.
    pub fn calculate(&self, total_fees: u128) -> (u128, u128, u128) {
        let indexer_amount = total_fees * self.indexer_percent as u128 / 100;
        let validator_amount = total_fees * self.validator_percent as u128 / 100;
        let treasury_amount = total_fees * self.treasury_percent as u128 / 100;
        (indexer_amount, validator_amount, treasury_amount)
    }

    /// Validate that percentages sum to 100.
    pub fn validate(&self) -> bool {
        self.indexer_percent + self.validator_percent + self.treasury_percent == 100
    }
}
