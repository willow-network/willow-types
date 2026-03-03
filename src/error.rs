//! Comprehensive error types for the Willow indexing system
//!
//! This module defines all error types used throughout the codebase,
//! providing typed errors with proper context instead of generic Box<dyn Error>.

use thiserror::Error;

/// Main error type for the Willow system.
///
/// This enum encompasses all error types that can occur throughout the Willow
/// codebase, providing typed errors with proper context for debugging and handling.
///
/// # Example
///
/// ```rust,ignore
/// use willow_core::error::{WillowError, StorageError};
///
/// fn example() -> Result<(), WillowError> {
///     Err(StorageError::KeyNotFound("test_key".to_string()).into())
/// }
/// ```
#[derive(Error, Debug)]
pub enum WillowError {
    /// Storage-related errors
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    /// Consensus-related errors
    #[error("Consensus error: {0}")]
    Consensus(#[from] ConsensusError),

    /// Indexing-related errors
    #[error("Indexing error: {0}")]
    Indexing(#[from] IndexingError),

    /// API server errors
    #[error("API error: {0}")]
    Api(#[from] ApiError),

    /// Network/P2P errors
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// Light client errors
    #[error("Light client error: {0}")]
    LightClient(#[from] LightClientError),

    /// State sync errors
    #[error("State sync error: {0}")]
    StateSyncError(String),

    /// Validation errors
    #[error("Validation error: {0}")]
    Validation(String),

    /// Generic internal errors
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Storage layer errors for GroveDB operations.
///
/// These errors occur during database read/write operations,
/// serialization, and path traversal.
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("GroveDB error: {0}")]
    GroveDb(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Storage path error: {0}")]
    PathError(String),
}

/// Consensus layer errors for transaction and block processing.
///
/// These errors occur during transaction validation, signature verification,
/// and state transitions in the CometBFT consensus layer.
#[derive(Error, Debug)]
pub enum ConsensusError {
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Signature verification failed: {0}")]
    InvalidSignature(String),

    #[error("Insufficient stake: required {required}, got {actual}")]
    InsufficientStake { required: u128, actual: u128 },

    #[error("Block validation failed: {0}")]
    BlockValidation(String),

    #[error("State transition error: {0}")]
    StateTransition(String),

    #[error("Fee calculation error: {0}")]
    FeeCalculation(String),
}

/// Indexing subsystem errors for blockchain data processing.
///
/// These errors occur during indexer registration, WASM execution,
/// proof verification, and query processing.
#[derive(Error, Debug)]
pub enum IndexingError {
    #[error("Indexer not found: {0}")]
    IndexerNotFound(String),

    #[error("Subgrove not found: {0}")]
    SubgroveNotFound(String),

    #[error("WASM execution error: {0}")]
    WasmExecution(String),

    #[error("Proof verification failed: {0}")]
    ProofVerification(String),

    #[error("Query execution error: {0}")]
    QueryExecution(String),

    #[error("State diff validation failed: {0}")]
    StateDiffValidation(String),

    #[error("Shard assignment error: {0}")]
    ShardAssignment(String),

    #[error("Indexer already registered: {0}")]
    IndexerAlreadyRegistered(String),
}

/// API server errors for HTTP request handling.
///
/// These errors occur during request validation, authentication,
/// authorization, and rate limiting.
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Authorization failed: {0}")]
    AuthorizationFailed(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("Invalid GraphQL query: {0}")]
    InvalidGraphQL(String),
}

/// Network layer errors for P2P communication.
///
/// These errors occur during peer connections, message broadcasting,
/// and protocol handling in the Waku P2P layer.
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("P2P connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Message broadcast failed: {0}")]
    BroadcastFailed(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Lock poisoned: {0}")]
    LockPoisoned(String),

    #[error("Duration conversion error: {0}")]
    DurationError(String),
}

/// Configuration errors for node and network setup.
///
/// These errors occur when loading, parsing, or validating
/// configuration files and environment variables.
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Missing configuration: {0}")]
    Missing(String),

    #[error("Invalid configuration: {0}")]
    Invalid(String),

    #[error("File read error: {0}")]
    FileRead(String),

    #[error("Parse error: {0}")]
    Parse(String),
}

/// Light client errors for header and proof verification.
///
/// These errors occur during Willow light client operations including
/// header synchronization and query proof verification.
#[derive(Error, Debug)]
pub enum LightClientError {
    #[error("Lock poisoned: {0}")]
    LockPoisoned(String),

    #[error("Parent header not found: {0}")]
    ParentNotFound(String),

    #[error("Header not found: {0}")]
    HeaderNotFound(String),

    #[error("Invalid block number: {0}")]
    InvalidBlockNumber(u64),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}

/// Result type alias using [`WillowError`].
///
/// This is the preferred result type for new code in the Willow crate.
pub type Result<T> = std::result::Result<T, WillowError>;

/// Conversion implementations for common error types
impl From<std::io::Error> for WillowError {
    fn from(err: std::io::Error) -> Self {
        WillowError::Internal(format!("IO error: {}", err))
    }
}

impl From<serde_json::Error> for WillowError {
    fn from(err: serde_json::Error) -> Self {
        WillowError::Internal(format!("JSON error: {}", err))
    }
}

// Helper macros for error handling

/// Macro to convert `Option` to `Result` with a custom error message.
///
/// # Example
///
/// ```rust,ignore
/// use willow_core::{ok_or_error, WillowError};
///
/// let opt: Option<i32> = None;
/// let result = ok_or_error!(opt, WillowError::Internal("value not found".to_string()));
/// ```
#[macro_export]
macro_rules! ok_or_error {
    ($option:expr, $error:expr) => {
        $option.ok_or_else(|| $error)
    };
}

/// Macro to add context to errors for better debugging.
///
/// Wraps an error with additional context information, converting it
/// to a [`WillowError::Internal`] with the combined message.
///
/// # Example
///
/// ```rust,ignore
/// use willow_core::with_context;
///
/// let result = std::fs::read("nonexistent.txt");
/// let with_ctx = with_context!(result, "Failed to read config file");
/// ```
#[macro_export]
macro_rules! with_context {
    ($result:expr, $context:expr) => {
        $result.map_err(|e| $crate::error::WillowError::Internal(format!("{}: {}", $context, e)))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ConsensusError::InsufficientStake {
            required: 100000,
            actual: 50000,
        };
        assert_eq!(
            err.to_string(),
            "Insufficient stake: required 100000, got 50000"
        );
    }

    #[test]
    fn test_error_conversion() {
        let storage_err = StorageError::KeyNotFound("test_key".to_string());
        let willow_err: WillowError = storage_err.into();
        assert!(matches!(willow_err, WillowError::Storage(_)));
    }
}
