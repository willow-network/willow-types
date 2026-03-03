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
    },
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointVerificationConfig {
    /// Optional TEE requirement for checkpoint submissions.
    /// When set, checkpoints must include a valid hardware attestation
    /// of the specified type. This also reduces the challenge window
    /// from 1000 blocks to 500 blocks.
    #[serde(default)]
    pub required_tee: Option<crate::tee::TeeType>,
}

impl Default for CheckpointVerificationConfig {
    fn default() -> Self {
        CheckpointVerificationConfig {
            required_tee: None,
        }
    }
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
