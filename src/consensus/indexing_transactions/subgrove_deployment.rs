use serde::{Deserialize, Serialize};

use super::execution_modes::ExecutionMode;
use super::indexer_config::IndexerConfig;

/// The mode of a subgrove: either data storage or blockchain indexing.
///
/// When deserializing old payloads that lack a `mode` field, the default
/// is `DataStorage` with empty defaults, preserving backward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubgroveMode {
    /// Data storage mode — stores arbitrary off-chain data with verification.
    DataStorage {
        /// Human-readable name.
        name: String,
        /// DIDs with write permission.
        writers: Vec<String>,
        /// DIDs with free read permission (no payment required).
        #[serde(alias = "readers")]
        free_readers: Vec<String>,
        /// Pricing configuration for paid reads.
        #[serde(default)]
        read_pricing: Option<crate::token::ReadPricing>,
    },
    /// File storage mode — stores files (images, documents, binaries) with
    /// cryptographic verification. Metadata goes through consensus, actual
    /// file data lives on dedicated storage nodes.
    FileStorage {
        /// Human-readable name.
        name: String,
        /// Maximum file size in bytes (capped at MAX_FILE_SIZE).
        max_file_size: u64,
        /// Minimum number of storage nodes that must hold each file.
        replication_factor: u8,
        /// DIDs with write (upload) permission.
        writers: Vec<String>,
        /// DIDs with free read (download) permission.
        free_readers: Vec<String>,
        /// Pricing configuration for paid downloads.
        #[serde(default)]
        read_pricing: Option<crate::token::ReadPricing>,
        /// Retention period in seconds (0 = permanent).
        #[serde(default)]
        retention_period: u64,
    },
    /// Blockchain indexing mode — indexes on-chain data with optional WASM
    /// transformations for custom logic. Standard patterns (ERC-20 transfers,
    /// Uniswap swaps, etc.) work declaratively without WASM modules.
    BlockchainIndexing {
        /// Raw manifest content for on-chain verification.
        manifest_content: Vec<u8>,
        /// Optional WASM modules for custom event handlers and transformations.
        /// Standard indexing patterns work without WASM; only needed for custom logic.
        #[serde(default)]
        wasm_modules: Vec<WasmModule>,
        /// Execution mode for this subgrove.
        execution_mode: ExecutionMode,
        /// Configuration for indexer requirements and rewards.
        indexer_config: IndexerConfig,
        /// Retention window for real-time indexed data on consensus nodes.
        /// Defaults to Indefinite for backward compatibility.
        #[serde(default)]
        retention_window: RetentionWindow,
        /// Optional commitments to the subgrove's log and transaction filters,
        /// binding completeness proofs to the filters the subgrove was
        /// registered with.
        /// `None` = subgrove does not opt into completeness proofs (backward-
        /// compatible with existing registrations).
        #[serde(default)]
        completeness: Option<CompletenessCommitments>,
        /// Trust model for historical (pre-Capella) Ethereum block
        /// authentication. Defaults to `BftEquivalent`; opt into
        /// `CanonizedAccumulator` to index pre-April-2023 blocks.
        #[serde(default)]
        historical_auth_mode: HistoricalAuthMode,
    },
}

/// Trust model under which historical (pre-Capella) Ethereum block
/// authentication is acceptable for this subgrove. Pre-Capella headers
/// cannot be authenticated solely by a current beacon sync-committee
/// signature, so subgroves that need to index that range must
/// explicitly opt into a weaker trust assumption: the canonized
/// pre-merge / `historical_roots` accumulators shipped with Willow.
/// Default is `BftEquivalent` — preserves the protocol's strong trust
/// guarantee for any subgrove that doesn't need pre-Capella history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum HistoricalAuthMode {
    /// Only accept block authentications that chain to a current beacon
    /// sync-committee signature (Helios). Pre-Capella blocks cannot be
    /// authenticated under this mode.
    #[default]
    BftEquivalent,
    /// Accept block authentications via Willow's embedded canonized
    /// pre-merge and `historical_roots` accumulators in addition to
    /// Helios. Required to index any block before Capella
    /// (block 17,034,870, ~April 2023).
    CanonizedAccumulator,
}

/// Commitments to a subgrove's filter definitions, used as public inputs to
/// completeness proofs. Each field is a Poseidon2 digest produced by the
/// corresponding `willow_gkr::circuits::completeness_direct::native_*_config_hash`
/// oracle over the canonical byte serialization of the filter.
///
/// Stored element-wise as `u32` (reduced M31 field values) so that
/// `willow-types` doesn't have to depend on `willow-gkr`. The consensus /
/// proof-verification layer converts to `[M31; 4]` at use time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletenessCommitments {
    /// Commitment to the log filter (see `SubgroveFilter` in `willow-gkr`).
    /// For the canonical "match all logs" filter use
    /// `willow_gkr::circuits::completeness_direct::EMPTY_LOG_CONFIG_HASH`.
    pub log_config_hash: [u32; 4],
    /// Commitment to the transaction filter (see `TransactionFilter` in
    /// `willow-gkr`). For the canonical "match all transactions" filter use
    /// `willow_gkr::circuits::completeness_direct::EMPTY_TX_CONFIG_HASH`.
    pub tx_config_hash: [u32; 4],
    /// Defer completeness verification to a `CompleteBlockTx` against the
    /// in-state anchor (deterministic) instead of running it at the tip.
    #[serde(default)]
    pub deferred: bool,
    /// WILL bond (in wei) the indexer locks per deferred submission, asserting
    /// "this is the complete set for this block." Released to the indexer when
    /// the block settles complete at finalization; slashed (split between the
    /// settling `CompleteBlockTx.beneficiary` and the treasury) if an omission
    /// is proven. `0` opts out of the instant economic-completeness tier — the
    /// subgrove then behaves exactly as a deferred subgrove with no bond
    /// (head-anchor completeness only). Any non-zero value must meet
    /// [`crate::token::units::MIN_COMPLETENESS_BOND`].
    #[serde(default)]
    pub bond_amount: u128,
}

impl CompletenessCommitments {
    /// Validate the per-subgrove completeness bond: either `0` (opt out of the
    /// economic tier) or at least the protocol minimum, so a slash is always a
    /// meaningful deterrent. Enforced at subgrove registration.
    pub fn validate(&self) -> Result<(), String> {
        if self.bond_amount != 0 && self.bond_amount < crate::token::units::MIN_COMPLETENESS_BOND {
            return Err(format!(
                "completeness bond_amount {} is below the protocol minimum {}",
                self.bond_amount,
                crate::token::units::MIN_COMPLETENESS_BOND
            ));
        }
        Ok(())
    }
}

/// Default subgrove mode: DataStorage with empty defaults.
pub fn default_data_storage_mode() -> SubgroveMode {
    SubgroveMode::DataStorage {
        name: String::new(),
        writers: Vec::new(),
        free_readers: Vec::new(),
        read_pricing: None,
    }
}

/// A WebAssembly module containing transformation logic.
///
/// WASM modules process blockchain events and produce indexed entities.
/// The hash is verified against the content to ensure integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmModule {
    /// Module name (e.g., "mapping", "handlers").
    pub name: String,
    /// SHA256 hash of the WASM bytecode.
    pub hash: [u8; 32],
    /// The actual WASM bytecode.
    pub content: Vec<u8>,
}

/// Checkpoint verification configuration.
///
/// All checkpoints use optimistic acceptance: submitted by one indexer,
/// entering a challenge window during which any other indexer can dispute
/// via bisection protocol. If no dispute is opened, the checkpoint becomes trusted.
///
/// Optionally, a subgrove can require TEE hardware attestation, which provides
/// additional trust and allows a shorter challenge window (500 blocks vs 1000).
///
/// ## Trust Model
///
/// | Configuration  | Trust Assumption                    | Challenge Window |
/// |----------------|-------------------------------------|------------------|
/// | No TEE         | Economic (dispute + slashing)       | 1000 blocks      |
/// | With TEE       | Hardware (Intel/AWS attestation)    | 500 blocks       |
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointVerificationConfig {
    /// Optional TEE requirement for checkpoint submissions.
    /// When set, checkpoints must include a valid hardware attestation
    /// of the specified type. This also reduces the challenge window
    /// from 1000 blocks to 500 blocks.
    #[serde(default)]
    pub required_tee: Option<crate::tee::TeeType>,
}

impl CheckpointVerificationConfig {
    /// Returns true if this config requires TEE attestation.
    pub fn requires_tee(&self) -> bool {
        self.required_tee.is_some()
    }

    /// Get the required TEE type, if any.
    pub fn tee_type(&self) -> Option<crate::tee::TeeType> {
        self.required_tee
    }

    /// Validate the checkpoint verification configuration.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(tee_type) = &self.required_tee {
            if !tee_type.is_supported() {
                return Err(format!("TEE type {:?} is not yet supported", tee_type));
            }
        }
        Ok(())
    }

    /// Create a config requiring TEE attestation of the given type.
    pub fn with_tee(tee_type: crate::tee::TeeType) -> Self {
        CheckpointVerificationConfig {
            required_tee: Some(tee_type),
        }
    }
}

/// How long real-time indexed data is retained on consensus nodes.
/// After the retention window expires (and a trusted checkpoint covers the blocks),
/// data is pruned from consensus and queries route to indexer nodes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum RetentionWindow {
    /// Retain for N consensus blocks. Min: 100, Max: 15,768,000 (~1 year at 2s blocks).
    Blocks(u64),
    /// Retain for N seconds. Min: 300 (5 minutes), Max: 31,536,000 (1 year).
    Seconds(u64),
    /// Never prune (current behavior). Priced at ~10-year storage horizon.
    #[default]
    Indefinite,
    /// Verify and discard: consensus verifies submissions but does not store raw data.
    /// Only metadata (block hashes, data_hash, indexer DID) is stored for audit trail.
    /// Queries always route to indexer nodes (code 2 redirect). Cheapest tier: base_tx_cost only.
    /// Not allowed with ConsensusExecution (validators would compute data just to discard it).
    VerifyOnly,
}

pub const MIN_RETENTION_BLOCKS: u64 = 100;
pub const MAX_RETENTION_BLOCKS: u64 = 15_768_000;
pub const MIN_RETENTION_SECONDS: u64 = 300;
pub const MAX_RETENTION_SECONDS: u64 = 31_536_000;

/// 10-year storage horizon in seconds (basis for current cost_per_byte pricing).
pub const STORAGE_HORIZON_SECONDS: u64 = 315_576_000;
/// Assumed block time in seconds for cost calculations.
pub const ASSUMED_BLOCK_TIME_SECONDS: u64 = 2;

impl RetentionWindow {
    /// Validate that the retention window parameters are within bounds.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            RetentionWindow::Blocks(n) => {
                if *n < MIN_RETENTION_BLOCKS {
                    return Err(format!(
                        "Retention blocks {} is below minimum {}",
                        n, MIN_RETENTION_BLOCKS
                    ));
                }
                if *n > MAX_RETENTION_BLOCKS {
                    return Err(format!(
                        "Retention blocks {} exceeds maximum {}",
                        n, MAX_RETENTION_BLOCKS
                    ));
                }
            }
            RetentionWindow::Seconds(n) => {
                if *n < MIN_RETENTION_SECONDS {
                    return Err(format!(
                        "Retention seconds {} is below minimum {}",
                        n, MIN_RETENTION_SECONDS
                    ));
                }
                if *n > MAX_RETENTION_SECONDS {
                    return Err(format!(
                        "Retention seconds {} exceeds maximum {}",
                        n, MAX_RETENTION_SECONDS
                    ));
                }
            }
            RetentionWindow::Indefinite => {}
            RetentionWindow::VerifyOnly => {}
        }
        Ok(())
    }

    /// Returns the storage cost multiplier as a fraction (numerator, denominator).
    /// Based on the 10-year (315,576,000 second) storage horizon that cost_per_byte prices in.
    /// Indefinite = 1/1 (full 10-year price, current behavior).
    pub fn storage_cost_fraction(&self) -> (u128, u128) {
        match self {
            RetentionWindow::Indefinite => (1, 1),
            RetentionWindow::VerifyOnly => (0, 1),
            RetentionWindow::Seconds(n) => (*n as u128, STORAGE_HORIZON_SECONDS as u128),
            RetentionWindow::Blocks(n) => (
                *n as u128 * ASSUMED_BLOCK_TIME_SECONDS as u128,
                STORAGE_HORIZON_SECONDS as u128,
            ),
        }
    }
}

#[cfg(test)]
mod completeness_bond_tests {
    use super::CompletenessCommitments;
    use crate::token::units::{MIN_COMPLETENESS_BOND, ONE_WILL};

    fn commitments(bond_amount: u128) -> CompletenessCommitments {
        CompletenessCommitments {
            log_config_hash: [1, 2, 3, 4],
            tx_config_hash: [5, 6, 7, 8],
            deferred: true,
            bond_amount,
        }
    }

    #[test]
    fn zero_bond_opts_out_and_validates() {
        assert!(commitments(0).validate().is_ok());
    }

    #[test]
    fn at_or_above_minimum_validates() {
        assert!(commitments(MIN_COMPLETENESS_BOND).validate().is_ok());
        assert!(commitments(1000 * ONE_WILL).validate().is_ok());
    }

    #[test]
    fn nonzero_below_minimum_is_rejected() {
        let err = commitments(MIN_COMPLETENESS_BOND - 1)
            .validate()
            .unwrap_err();
        assert!(err.contains("below the protocol minimum"), "got: {err}");
    }

    #[test]
    fn bond_amount_survives_bincode_round_trip() {
        let c = commitments(250 * ONE_WILL);
        let bytes = bincode::serialize(&c).unwrap();
        let got: CompletenessCommitments = bincode::deserialize(&bytes).unwrap();
        assert_eq!(got.bond_amount, 250 * ONE_WILL);
        assert_eq!(got.deferred, true);
    }

    #[test]
    fn legacy_json_without_bond_defaults_to_zero() {
        // Pre-bond records (JSON in SubgroveIndexingInfo) had no bond_amount;
        // #[serde(default)] must read them back as opt-out.
        let json = r#"{"log_config_hash":[1,2,3,4],"tx_config_hash":[5,6,7,8],"deferred":true}"#;
        let got: CompletenessCommitments = serde_json::from_str(json).unwrap();
        assert_eq!(got.bond_amount, 0);
    }

    /// Locks the bincode field order inside `SubgroveMode::BlockchainIndexing`:
    /// `bond_amount` lives inside `completeness`, which sits *before*
    /// `historical_auth_mode`. bincode is positional with no field tags, so a
    /// future reorder would silently corrupt the bond amount on the wire — this
    /// asserts both the embedded `bond_amount` and the trailing
    /// `historical_auth_mode` survive a round-trip of the whole mode.
    #[test]
    fn blockchain_indexing_mode_preserves_bond_and_field_order() {
        use super::{HistoricalAuthMode, RetentionWindow, SubgroveMode};
        use crate::consensus::indexing_transactions::{ExecutionMode, IndexerConfig};

        let mode = SubgroveMode::BlockchainIndexing {
            manifest_content: vec![1, 2, 3],
            wasm_modules: vec![],
            execution_mode: ExecutionMode::default(),
            indexer_config: IndexerConfig::default(),
            retention_window: RetentionWindow::default(),
            completeness: Some(commitments(250 * ONE_WILL)),
            historical_auth_mode: HistoricalAuthMode::CanonizedAccumulator,
        };
        let bytes = bincode::serialize(&mode).unwrap();
        let got: SubgroveMode = bincode::deserialize(&bytes).unwrap();
        match got {
            SubgroveMode::BlockchainIndexing {
                completeness,
                historical_auth_mode,
                ..
            } => {
                assert_eq!(completeness.unwrap().bond_amount, 250 * ONE_WILL);
                assert_eq!(
                    historical_auth_mode,
                    HistoricalAuthMode::CanonizedAccumulator
                );
            }
            _ => panic!("expected BlockchainIndexing"),
        }
    }
}
