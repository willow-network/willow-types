pub mod transactions;
pub mod indexing_transactions;
pub mod dispute_resolution;

pub use transactions::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeMonitoringConfig {
    /// Ethereum RPC endpoints (multiple for redundancy)
    pub eth_rpc_endpoints: Vec<String>,

    /// Ethereum bridge contract address
    pub bridge_contract_address: [u8; 20],

    /// Starting block for monitoring (0 for latest)
    pub start_block: u64,

    /// Number of confirmations required
    pub required_confirmations: u64,

    /// Block polling interval in seconds
    pub polling_interval_secs: u64,

    /// Maximum blocks to process per batch
    pub max_blocks_per_batch: u64,

    /// Retry configuration
    pub retry_config: RetryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retries
    pub max_retries: u32,

    /// Initial retry delay in milliseconds
    pub initial_delay_ms: u64,

    /// Maximum retry delay in milliseconds
    pub max_delay_ms: u64,

    /// Exponential backoff multiplier
    pub backoff_multiplier: f64,
}
