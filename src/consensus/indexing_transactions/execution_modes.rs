use serde::{Deserialize, Serialize};

/// Execution mode for real-time (chain-tip) indexer submissions.
///
/// Determines who performs the data transformation (indexer or consensus)
/// and how verification is done. Each subgrove chooses an execution mode
/// at registration time.
///
/// **Note:** This only applies to real-time indexing (new blocks as they arrive).
/// Historical indexing uses a separate checkpoint-based system with optimistic
/// acceptance and bisection disputes. See [`HistoricalCheckpointTx`].
///
/// ## Modes
///
/// - **ConsensusExecution** (default): Indexers submit raw blockchain data,
///   validators execute the transformation. Simplest and most direct.
///
/// - **IndexerExecution**: Indexers perform transformation and submit results,
///   validators randomly sample and re-execute to verify correctness.
///   More scalable for expensive transformations, but requires sampling.
///
/// - **TeeExecution**: Indexers run in a Trusted Execution Environment (TEE)
///   and submit data with hardware attestations. Consensus verifies the
///   attestation instead of re-executing. Trusts hardware.
///
/// ## Trust Model Comparison
///
/// | Mode              | Verification Cost | Trust Assumption                |
/// |-------------------|-------------------|---------------------------------|
/// | ConsensusExecution| Medium            | BFT (2/3+ honest validators)    |
/// | IndexerExecution  | Low-Medium        | Economic (sampling + slashing)  |
/// | TeeExecution      | Low               | Hardware (Intel/AWS attestation)|
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum ExecutionMode {
    /// Validators execute all transformations. Indexers submit raw data only.
    ///
    /// **This mode does NOT use sampling.** Consensus executes 100% of transformations
    /// deterministically. Every submission is fully processed by validators.
    ///
    /// This is the default and simplest mode:
    /// - Indexers fetch raw blockchain data (blocks, events, receipts)
    /// - Indexers submit raw data with Merkle proofs to consensus
    /// - Validators execute the subgrove's transformation rules directly
    /// - No sampling, no probabilistic verification - consensus does all the work
    /// - Simplest trust model: data is transformed by the consensus layer itself
    ///
    /// Best for: Most use cases, especially when transformations are simple
    /// (parsing, filtering, basic decoding).
    ///
    /// Fee multiplier: 1.0x (base rate)
    #[default]
    ConsensusExecution,

    /// Indexers execute transformations. Consensus samples for verification.
    ///
    /// In this mode:
    /// - Indexers fetch raw blockchain data AND transform it
    /// - Indexers submit transformed data with proofs to consensus
    /// - Consensus randomly samples submissions for re-execution
    /// - If re-execution produces different results, indexer is slashed
    ///
    /// The sampling rate determines what percentage of submissions are verified:
    /// - 0% = no verification (trust indexers completely, lowest cost)
    /// - Higher rates = more security, more cost
    /// - Maximum 50% (use ConsensusExecution for higher verification rates)
    ///
    /// Best for: Expensive transformations (complex WASM, heavy aggregations)
    /// where parallelizing work across indexers provides significant benefit.
    ///
    /// Fee multiplier: 0.3x - 0.65x (depending on sampling rate)
    IndexerExecution {
        /// Percentage of submissions to verify via re-execution (0-50).
        /// Lower values reduce verification cost but increase fraud risk.
        /// Recommended: 5-20% for most use cases.
        sampling_rate_percent: u8,
    },

    /// Indexers run in a Trusted Execution Environment (TEE).
    ///
    /// In this mode:
    /// - Indexers run inside a hardware-protected enclave (AWS Nitro, Intel SGX)
    /// - The enclave fetches data, transforms it, and generates an attestation
    /// - Indexers submit transformed data with the TEE attestation to consensus
    /// - Consensus verifies the attestation signature and enclave image hash
    /// - No re-execution needed - hardware attests to correct execution
    ///
    /// The attestation proves:
    /// - The exact code that ran (enclave image hash / PCR0 / MRENCLAVE)
    /// - The data hash matches the submitted data
    /// - The code ran in a genuine TEE (hardware signature)
    ///
    /// Best for: Cost-sensitive applications where hardware trust is acceptable.
    /// Indexers choosing to index this subgrove must have TEE capability.
    ///
    /// Fee multiplier: 0.1x (90% discount)
    TeeExecution {
        /// The type of TEE required for this subgrove.
        tee_type: crate::tee::TeeType,
    },
}

impl ExecutionMode {
    /// Returns true if this mode requires consensus to execute transformations.
    pub fn is_consensus_execution(&self) -> bool {
        matches!(self, ExecutionMode::ConsensusExecution)
    }

    /// Returns true if this mode has indexers execute transformations with sampling.
    pub fn is_indexer_execution(&self) -> bool {
        matches!(self, ExecutionMode::IndexerExecution { .. })
    }

    /// Returns true if this mode uses TEE attestation for verification.
    pub fn is_tee_execution(&self) -> bool {
        matches!(self, ExecutionMode::TeeExecution { .. })
    }

    /// Get the sampling rate for verification (0.0 to 1.0).
    ///
    /// - ConsensusExecution: Returns 1.0 (100% - consensus always executes)
    /// - IndexerExecution: Returns the configured sampling rate
    /// - TeeExecution: Returns 0.0 (no re-execution, attestation only)
    pub fn verification_rate(&self) -> f64 {
        match self {
            ExecutionMode::ConsensusExecution => 1.0,
            ExecutionMode::IndexerExecution {
                sampling_rate_percent,
            } => *sampling_rate_percent as f64 / 100.0,
            ExecutionMode::TeeExecution { .. } => 0.0,
        }
    }

    /// Get the sampling rate as a percentage (0-100).
    pub fn verification_rate_percent(&self) -> u8 {
        match self {
            ExecutionMode::ConsensusExecution => 100,
            ExecutionMode::IndexerExecution {
                sampling_rate_percent,
            } => *sampling_rate_percent,
            ExecutionMode::TeeExecution { .. } => 0,
        }
    }

    /// Returns true if verification uses sampling (not deterministic 100%).
    pub fn uses_sampling(&self) -> bool {
        matches!(self, ExecutionMode::IndexerExecution { .. })
    }

    /// Returns true if this mode requires TEE attestation.
    pub fn requires_tee_attestation(&self) -> bool {
        matches!(self, ExecutionMode::TeeExecution { .. })
    }

    /// Returns true if this mode requires consensus to execute transformations.
    ///
    /// - ConsensusExecution: consensus executes directly (indexers submit raw data)
    /// - IndexerExecution: consensus re-executes a sample of indexer submissions
    pub fn requires_reexecution(&self) -> bool {
        match self {
            ExecutionMode::ConsensusExecution => true,
            ExecutionMode::IndexerExecution {
                sampling_rate_percent,
            } => *sampling_rate_percent > 0,
            ExecutionMode::TeeExecution { .. } => false,
        }
    }

    /// Get the TEE type if this is TeeExecution mode.
    pub fn tee_type(&self) -> Option<crate::tee::TeeType> {
        match self {
            ExecutionMode::TeeExecution { tee_type } => Some(*tee_type),
            _ => None,
        }
    }

    /// Get the fee multiplier for this execution mode.
    ///
    /// - ConsensusExecution: 1.0 (full price - consensus executes all transformations)
    /// - IndexerExecution: 0.3 - 0.65 (depending on sampling rate)
    /// - TeeExecution: 0.1 (90% discount - attestation verification only)
    pub fn fee_multiplier(&self) -> f64 {
        match self {
            ExecutionMode::ConsensusExecution => 1.0,
            ExecutionMode::IndexerExecution {
                sampling_rate_percent,
            } => 0.3 + (0.35 * *sampling_rate_percent as f64 / 50.0),
            ExecutionMode::TeeExecution { .. } => 0.1,
        }
    }

    /// Validate the execution mode configuration.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            ExecutionMode::ConsensusExecution => Ok(()),
            ExecutionMode::IndexerExecution {
                sampling_rate_percent,
            } => {
                if *sampling_rate_percent > 50 {
                    Err(
                        "IndexerExecution sampling rate must be 0-50% (use ConsensusExecution for higher verification)"
                            .to_string(),
                    )
                } else {
                    Ok(())
                }
            }
            ExecutionMode::TeeExecution { tee_type } => {
                if !tee_type.is_supported() {
                    Err(format!("TEE type {:?} is not yet supported", tee_type))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Create IndexerExecution with common preset sampling rates.
    pub fn indexer_low() -> Self {
        ExecutionMode::IndexerExecution {
            sampling_rate_percent: 1,
        }
    }

    pub fn indexer_medium() -> Self {
        ExecutionMode::IndexerExecution {
            sampling_rate_percent: 5,
        }
    }

    pub fn indexer_high() -> Self {
        ExecutionMode::IndexerExecution {
            sampling_rate_percent: 20,
        }
    }

    /// Create TeeExecution with AWS Nitro.
    pub fn tee_nitro() -> Self {
        ExecutionMode::TeeExecution {
            tee_type: crate::tee::TeeType::AwsNitro,
        }
    }

    /// Create TeeExecution with Intel SGX.
    pub fn tee_sgx() -> Self {
        ExecutionMode::TeeExecution {
            tee_type: crate::tee::TeeType::IntelSgx,
        }
    }
}

#[cfg(test)]
mod execution_mode_tests {
    use super::*;

    #[test]
    fn execution_mode_discriminants_are_pinned() {
        // Bincode encodes enum discriminants by declaration order. If any
        // variant drifts from its position, existing serialized data fails
        // to decode (or decodes as the wrong mode). Pin all three surviving
        // discriminants at 0/1/2.
        let consensus_bytes =
            bincode::serialize(&ExecutionMode::ConsensusExecution).expect("serialize consensus");
        assert_eq!(&consensus_bytes[..4], &[0, 0, 0, 0]);
        let indexer_bytes = bincode::serialize(&ExecutionMode::IndexerExecution {
            sampling_rate_percent: 5,
        })
        .expect("serialize indexer");
        assert_eq!(&indexer_bytes[..4], &[1, 0, 0, 0]);
        let tee_bytes = bincode::serialize(&ExecutionMode::TeeExecution {
            tee_type: crate::tee::TeeType::AwsNitro,
        })
        .expect("serialize tee");
        assert_eq!(&tee_bytes[..4], &[2, 0, 0, 0]);
    }
}
