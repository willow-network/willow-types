//! Shared data types for the Willow protocol.
//!
//! This crate contains pure data type definitions (structs, enums, constants)
//! used across multiple Willow subsystems. By placing these in a shared crate,
//! circular dependencies between subsystems are eliminated.

pub mod error;
pub mod token;
pub mod storage;
pub mod tee;
pub mod reputation;
pub mod consensus;
pub mod indexer_node;
pub mod state_sync;
pub mod p2p;
pub mod indexing;

// Re-export commonly used types at the crate root
pub use error::{WillowError, StorageError, ConsensusError, IndexingError, ApiError, NetworkError, ConfigError, LightClientError};
pub use token::{Balance, FeeSchedule, ReadPricing, TokenState};
pub use tee::{TeeType, TeeAttestation, TeeCapability, TeeVerificationError};
pub use reputation::{IndexerReputation, ReputationTier, IndexerProfile, OperatorEntity};
pub use consensus::transactions::Transaction;
