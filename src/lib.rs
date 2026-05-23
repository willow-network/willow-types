//! Shared data types for the Willow protocol.
//!
//! This crate contains pure data type definitions (structs, enums, constants)
//! used across multiple Willow subsystems. By placing these in a shared crate,
//! circular dependencies between subsystems are eliminated.

pub mod consensus;
pub mod error;
pub mod indexer_node;
pub mod indexing;
pub mod p2p;
pub mod reputation;
pub mod serde_helpers;
pub mod state_proof;
pub mod state_sync;
pub mod storage;
pub mod tee;
pub mod token;
pub mod verifiable_rpc;

// Re-export commonly used types at the crate root
pub use consensus::transactions::Transaction;
pub use error::{
    ApiError, ConfigError, ConsensusError, IndexingError, LightClientError, NetworkError,
    StorageError, WillowError,
};
pub use reputation::{IndexerProfile, IndexerReputation, OperatorEntity};
pub use tee::{TeeAttestation, TeeCapability, TeeType, TeeVerificationError};
pub use token::{Balance, FeeSchedule, ReadPricing, TokenState};
