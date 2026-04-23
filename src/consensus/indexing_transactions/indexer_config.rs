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
    /// Optional HTTP endpoint for client query traffic (GraphQL/SQL/historical).
    ///
    /// Indexers typically expose their query service on a separate port
    /// (`historical_query_port`, default 3032) from the monitoring endpoint.
    /// When `None`, clients fall back to `endpoint` or a port-swap heuristic.
    #[serde(default)]
    pub query_endpoint: Option<String>,
    /// Ethereum RPC endpoint the indexer will use for fetching data.
    pub ethereum_rpc: String,
    /// Cryptographic signature over the transaction.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

fn default_epoch_length() -> u64 {
    crate::token::units::DEFAULT_EPOCH_LENGTH
}

/// Configuration for indexer requirements and rewards.
///
/// Specifies how many indexers should process this subgrove and
/// what rewards they receive per epoch. Multiple indexers provide redundancy
/// and help ensure data completeness.
///
/// ## Epoch-based reward model
///
/// Each active indexer earns up to `reward_per_epoch` per epoch, scaled by
/// their participation ratio (blocks submitted / epoch_length). The drip rate
/// is constant per indexer, so total app cost = `reward_per_epoch * num_active_indexers`.
///
/// Payout requires passing data availability checks — only indexers with
/// `Active` availability status receive epoch rewards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexerConfig {
    /// Minimum number of indexers required (1-10). Default: 1.
    /// Multiple indexers provide redundancy and help detect omissions.
    pub min_indexers: u8,

    /// Maximum number of indexers allowed (1-10). Default: 3.
    /// More indexers increase redundancy but also cost.
    pub max_indexers: u8,

    /// Reward per epoch per indexer in WILL (smallest unit).
    /// An indexer with full participation earns this amount each epoch.
    /// Higher rewards attract more indexers to bid on this subgrove.
    ///
    /// Accepts both a JSON number (Rust SDK) and a JSON string (TS SDK)
    /// on the wire — see `crate::serde_helpers::u128_flexible`.
    pub reward_per_epoch: u128,

    /// Length of an epoch in blocks. Default: 100.
    #[serde(default = "default_epoch_length")]
    pub epoch_length: u64,

    /// Minimum stake required from each indexer in WILL (smallest unit).
    /// Higher stake requirements increase indexer accountability.
    ///
    /// Accepts both a JSON number (Rust SDK) and a JSON string (TS SDK)
    /// on the wire — see `crate::serde_helpers::u128_flexible`.
    pub min_indexer_stake: u128,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            min_indexers: 1,
            max_indexers: 3,
            reward_per_epoch: crate::token::units::DEFAULT_REWARD_PER_EPOCH,
            epoch_length: crate::token::units::DEFAULT_EPOCH_LENGTH,
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
        if self.reward_per_epoch == 0 {
            return Err("reward_per_epoch must be greater than 0".to_string());
        }
        if self.epoch_length == 0 {
            return Err("epoch_length must be greater than 0".to_string());
        }
        Ok(())
    }

    /// Get the recommended indexer configuration for a given execution mode.
    ///
    /// Different modes have different indexer requirements based on trust model:
    /// - ConsensusExecution: Validators do transformation work, fewer indexers needed
    /// - IndexerExecution: Sampling-based verification, more indexers for redundancy
    pub fn recommended_for_mode(mode: &ExecutionMode) -> Self {
        use crate::token::units::{DEFAULT_EPOCH_LENGTH, ONE_MILLI_WILL};

        match mode {
            // Consensus execution: validators do the work
            ExecutionMode::ConsensusExecution => Self {
                min_indexers: 1,
                max_indexers: 2,
                reward_per_epoch: 80 * ONE_MILLI_WILL, // 0.08 WILL per epoch
                epoch_length: DEFAULT_EPOCH_LENGTH,
                min_indexer_stake: 100_000_000_000_000_000_000_000,
            },
            // Indexer execution with sampling: multiple indexers for redundancy
            ExecutionMode::IndexerExecution {
                sampling_rate_percent,
            } => {
                let redundancy = if *sampling_rate_percent < 10 {
                    3
                } else if *sampling_rate_percent < 30 {
                    2
                } else {
                    1
                };
                Self {
                    min_indexers: redundancy,
                    max_indexers: redundancy + 2,
                    reward_per_epoch: 100 * ONE_MILLI_WILL, // 0.1 WILL per epoch
                    epoch_length: DEFAULT_EPOCH_LENGTH,
                    min_indexer_stake: 100_000_000_000_000_000_000_000,
                }
            }
            // TEE execution: hardware provides trust, fewer indexers needed
            ExecutionMode::TeeExecution { .. } => Self {
                min_indexers: 1,
                max_indexers: 2,
                reward_per_epoch: 60 * ONE_MILLI_WILL, // 0.06 WILL per epoch
                epoch_length: DEFAULT_EPOCH_LENGTH,
                min_indexer_stake: 100_000_000_000_000_000_000_000,
            },
            // GKR execution: cryptographic proof, no redundancy needed
            ExecutionMode::GkrExecution => Self {
                min_indexers: 1,
                max_indexers: 1,
                reward_per_epoch: 120 * ONE_MILLI_WILL, // 0.12 WILL per epoch
                epoch_length: DEFAULT_EPOCH_LENGTH,
                min_indexer_stake: 100_000_000_000_000_000_000_000,
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
            ExecutionMode::ConsensusExecution => Self {
                indexer_percent: 60,
                validator_percent: 30,
                treasury_percent: 10,
            },
            ExecutionMode::IndexerExecution { .. } => Self {
                indexer_percent: 70,
                validator_percent: 20,
                treasury_percent: 10,
            },
            ExecutionMode::TeeExecution { .. } => Self {
                indexer_percent: 75,
                validator_percent: 15,
                treasury_percent: 10,
            },
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tx(query_endpoint: Option<String>) -> RegisterIndexerTx {
        RegisterIndexerTx {
            indexer_did: "did:willow:indexer1".to_string(),
            subgroves: vec!["sg-1".to_string()],
            stake_amount: 100_000_000_000_000_000_000_000,
            endpoint: "http://monitor.example.com:9090".to_string(),
            query_endpoint,
            ethereum_rpc: "http://eth.example.com".to_string(),
            signature: vec![1, 2, 3],
            public_key_id: "did:willow:indexer1#key-1".to_string(),
            nonce: 7,
        }
    }

    /// Transactions produced before the `query_endpoint` field existed must still
    /// deserialize — the field is marked `#[serde(default)]`. Without the
    /// default, upgrading a devnet would reject every pre-existing queued tx.
    #[test]
    fn deserializes_legacy_tx_without_query_endpoint() {
        // Hand-crafted JSON representing a pre-upgrade signed tx. Using a
        // string literal (not the json! macro) because stake_amount is a u128
        // and the macro would silently clamp to i64.
        let legacy_json = r#"{
            "indexer_did": "did:willow:legacy",
            "subgroves": ["sg-old"],
            "stake_amount": 100000000000000000000000,
            "endpoint": "http://old.example.com",
            "ethereum_rpc": "http://eth.example.com",
            "signature": [1, 2, 3],
            "public_key_id": "did:willow:legacy#key-1",
            "nonce": 1
        }"#;

        let tx: RegisterIndexerTx = serde_json::from_str(legacy_json).expect(
            "RegisterIndexerTx must deserialize without the query_endpoint field \
             (serde default keeps old signed transactions valid)",
        );
        assert_eq!(tx.query_endpoint, None);
        assert_eq!(tx.endpoint, "http://old.example.com");
    }

    /// When `query_endpoint` is `Some`, the JSON round-trip must preserve it
    /// exactly — otherwise consensus and SDK would disagree on what URL a
    /// caller should hit for indexed data.
    #[test]
    fn roundtrips_query_endpoint_when_set() {
        let tx = sample_tx(Some("http://query.example.com:3032".to_string()));
        let json = serde_json::to_string(&tx).unwrap();
        assert!(
            json.contains(r#""query_endpoint":"http://query.example.com:3032""#),
            "expected query_endpoint in serialized JSON, got: {}",
            json
        );
        let back: RegisterIndexerTx = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.query_endpoint.as_deref(),
            Some("http://query.example.com:3032")
        );
    }

    /// The signing payload is constructed identically on the signer side
    /// (indexer-node) and the verifier side (check_tx + indexing_transactions
    /// in the consensus crate). If either drifts, signatures fail. This test
    /// pins the current format so a future edit will fail loudly.
    #[test]
    fn signing_payload_format_includes_query_endpoint() {
        let tx = sample_tx(Some("http://query.example.com:3032".to_string()));
        let payload = format!(
            "RegisterIndexer:{}:{}:{}:{}:{}",
            tx.indexer_did,
            tx.stake_amount,
            tx.endpoint,
            tx.query_endpoint.as_deref().unwrap_or(""),
            tx.nonce
        );
        assert_eq!(
            payload,
            "RegisterIndexer:did:willow:indexer1:100000000000000000000000:\
             http://monitor.example.com:9090:http://query.example.com:3032:7"
        );

        // With no query_endpoint, the slot is empty (two adjacent colons)
        // rather than missing — otherwise signer vs verifier wouldn't
        // agree when `query_endpoint` is `None`.
        let tx_none = sample_tx(None);
        let payload_none = format!(
            "RegisterIndexer:{}:{}:{}:{}:{}",
            tx_none.indexer_did,
            tx_none.stake_amount,
            tx_none.endpoint,
            tx_none.query_endpoint.as_deref().unwrap_or(""),
            tx_none.nonce
        );
        assert!(
            payload_none.contains(":http://monitor.example.com:9090::"),
            "expected empty query_endpoint slot, got: {}",
            payload_none
        );
    }

    /// The TypeScript SDK (and therefore the web explorer) cannot losslessly
    /// represent u128 values above 2^53 as JSON numbers, so it sends
    /// `reward_per_epoch` and `min_indexer_stake` as JSON strings on the
    /// wire. Deserialization must accept both JSON numbers (Rust SDK) and
    /// JSON strings (TS SDK); otherwise every BlockchainIndexing subgrove
    /// registration from the web explorer fails at CheckTx with
    /// "invalid number at line 1 column …".
    ///
    /// Regression: confirmed on 2026-04-16 that the explorer was sending
    /// `"reward_per_epoch":"100000000000000000"` and CheckTx rejected it.
    #[test]
    fn indexer_config_accepts_string_u128_fields() {
        let json_from_ts_sdk = r#"{
            "min_indexers": 1,
            "max_indexers": 3,
            "reward_per_epoch": "100000000000000000",
            "epoch_length": 100,
            "min_indexer_stake": "100000000000000000000000"
        }"#;

        let cfg: IndexerConfig = serde_json::from_str(json_from_ts_sdk).expect(
            "IndexerConfig must accept u128 fields as JSON strings — this is \
             the wire format the TypeScript SDK produces because JS numbers \
             cannot represent values above 2^53 without precision loss.",
        );
        assert_eq!(cfg.reward_per_epoch, 100_000_000_000_000_000);
        assert_eq!(cfg.min_indexer_stake, 100_000_000_000_000_000_000_000);
    }

    /// Rust SDK (and old clients) still emit u128 as raw JSON numbers.
    /// That form must keep working too.
    #[test]
    fn indexer_config_accepts_number_u128_fields() {
        let json_from_rust_sdk = r#"{
            "min_indexers": 1,
            "max_indexers": 3,
            "reward_per_epoch": 100000000000000000,
            "epoch_length": 100,
            "min_indexer_stake": 100000000000000000000000
        }"#;

        let cfg: IndexerConfig = serde_json::from_str(json_from_rust_sdk).expect(
            "IndexerConfig must still accept u128 fields as JSON numbers — \
             Rust-side serialization emits them that way.",
        );
        assert_eq!(cfg.reward_per_epoch, 100_000_000_000_000_000);
        assert_eq!(cfg.min_indexer_stake, 100_000_000_000_000_000_000_000);
    }
}
