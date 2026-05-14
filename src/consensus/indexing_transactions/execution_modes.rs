use serde::{Deserialize, Serialize};

use super::gkr_proof_types::GkrProofConfig;

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
/// - **GkrExecution**: Indexers perform transformation and submit results
///   with a cryptographic GKR proof. Consensus verifies the proof instead
///   of re-executing. Cryptographic trust without hardware dependencies.
///   Primarily useful for privacy-sensitive applications, since proof
///   verification is currently slower than direct consensus execution.
///
/// - **WarpExecution**: Indexers accumulate per-block claims into a single
///   WARP fold instance and submit a folding-scheme proof per submission.
///   Consensus verifies via the WARP decider (`willow-folding`). Designed
///   for fast historical sync — many block-level claims aggregate into a
///   single decider check, with per-block prover cost ~1 ms (GPU, batched).
///
/// ## Trust Model Comparison
///
/// | Mode              | Verification Cost | Trust Assumption                |
/// |-------------------|-------------------|---------------------------------|
/// | ConsensusExecution| Medium            | BFT (2/3+ honest validators)    |
/// | IndexerExecution  | Low-Medium        | Economic (sampling + slashing)  |
/// | TeeExecution      | Low               | Hardware (Intel/AWS attestation)|
/// | GkrExecution      | High              | Cryptographic (mathematical)    |
/// | WarpExecution     | Low (amortized)   | Cryptographic (folding scheme)  |
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

    /// Indexers execute transformations and submit results with a GKR proof.
    ///
    /// In this mode:
    /// - Indexers fetch raw blockchain data, transform it, and generate a GKR proof
    /// - Indexers submit transformed data with the cryptographic proof to consensus
    /// - Consensus verifies the GKR proof instead of re-executing
    /// - No re-execution needed - mathematical proof attests to correct execution
    ///
    /// The proof guarantees:
    /// - The transformation was applied correctly to the input events
    /// - The output data hash matches the submitted data
    /// - Input events are bound to verified Ethereum data via commitment
    ///
    /// Best for: Privacy-sensitive applications where validators should not
    /// see raw input data. Proof verification is currently slower than direct
    /// consensus execution, so the main advantage is privacy, not performance.
    /// Indexers choosing to index this subgrove must be capable of generating
    /// GKR proofs.
    ///
    /// Fee multiplier: 0.15x (85% discount)
    GkrExecution,

    /// Indexers submit accumulated WARP fold proofs (folding scheme).
    ///
    /// Designed for high-throughput historical sync. Indexers accumulate
    /// many per-block claims into a single twin-constrained accumulator
    /// instance via WARP folding, then submit periodic checkpoints with
    /// a small fold-step proof linking each submission to its predecessor.
    /// Consensus verifies via the WARP decider in `willow-folding`.
    ///
    /// Per-block prover cost on GPU (batched, RTX 5090, n=2¹⁴): ~1 ms.
    /// Per-block verifier cost is dominated by the (rare) decider step,
    /// not the per-step fold update — making this the cheapest mode for
    /// long-range historical sync.
    ///
    /// Fee multiplier: 0.12x (88% discount).
    WarpExecution {
        /// log₂ of the WARP codeword length used for this subgrove. The
        /// fold's codeword has length `2 · 2^codeword_log_n` (twin form).
        /// 14 is the validated bench size; production scale targets 22.
        codeword_log_n: u8,
        /// Construction 7.2 OOD sample count. Drives r = 1 + n_ood +
        /// n_shifts, which must be a power of two. Soundness for OOD
        /// sampling improves geometrically per query at log_n cost.
        n_ood: u8,
        /// Construction 7.2 shift-query count. Each query authenticates
        /// one codeword leaf against the Merkle commitment, giving
        /// Reed-Solomon-style proximity testing. Shipped default
        /// `(n_ood, n_shifts) = (1, 2)` mirrors the bench config.
        n_shifts: u8,
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

    /// Returns true if this mode requires GKR proof verification.
    pub fn is_gkr_execution(&self) -> bool {
        matches!(self, ExecutionMode::GkrExecution)
    }

    /// Returns true if this mode requires a GKR proof in every submission.
    pub fn requires_gkr_proof(&self) -> bool {
        matches!(self, ExecutionMode::GkrExecution)
    }

    /// Returns true if this mode uses WARP folding-scheme verification.
    pub fn is_warp_execution(&self) -> bool {
        matches!(self, ExecutionMode::WarpExecution { .. })
    }

    /// Returns true if this mode requires a WARP fold-step proof in every submission.
    pub fn requires_warp_proof(&self) -> bool {
        matches!(self, ExecutionMode::WarpExecution { .. })
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
            ExecutionMode::GkrExecution => 0.0,
            ExecutionMode::WarpExecution { .. } => 0.0,
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
            ExecutionMode::GkrExecution => 0,
            ExecutionMode::WarpExecution { .. } => 0,
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
            ExecutionMode::GkrExecution => false,
            ExecutionMode::WarpExecution { .. } => false,
        }
    }

    /// Get the TEE type if this is TeeExecution mode.
    pub fn tee_type(&self) -> Option<crate::tee::TeeType> {
        match self {
            ExecutionMode::TeeExecution { tee_type } => Some(*tee_type),
            _ => None,
        }
    }

    /// Get the WARP codeword `log_n` if this is WarpExecution mode.
    pub fn warp_codeword_log_n(&self) -> Option<u8> {
        match self {
            ExecutionMode::WarpExecution { codeword_log_n, .. } => Some(*codeword_log_n),
            _ => None,
        }
    }

    /// Get the WARP `(n_ood, n_shifts)` sampling counts if this is
    /// WarpExecution mode.
    pub fn warp_sampling(&self) -> Option<(u8, u8)> {
        match self {
            ExecutionMode::WarpExecution {
                n_ood, n_shifts, ..
            } => Some((*n_ood, *n_shifts)),
            _ => None,
        }
    }

    /// Get the fee multiplier for this execution mode.
    ///
    /// - ConsensusExecution: 1.0 (full price - consensus executes all transformations)
    /// - IndexerExecution: 0.3 - 0.65 (depending on sampling rate)
    /// - TeeExecution: 0.1 (90% discount - attestation verification only)
    /// - GkrExecution: 0.15 (85% discount - proof verification only)
    pub fn fee_multiplier(&self) -> f64 {
        match self {
            ExecutionMode::ConsensusExecution => 1.0,
            ExecutionMode::IndexerExecution {
                sampling_rate_percent,
            } => 0.3 + (0.35 * *sampling_rate_percent as f64 / 50.0),
            ExecutionMode::TeeExecution { .. } => 0.1,
            ExecutionMode::GkrExecution => 0.15,
            ExecutionMode::WarpExecution { .. } => 0.12,
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
            ExecutionMode::GkrExecution => Ok(()),
            ExecutionMode::WarpExecution {
                codeword_log_n,
                n_ood,
                n_shifts,
            } => {
                if !(8..=24).contains(codeword_log_n) {
                    return Err(format!(
                        "WarpExecution codeword_log_n must be in [8, 24]; got {codeword_log_n}",
                    ));
                }
                let r = 1usize + *n_ood as usize + *n_shifts as usize;
                if !r.is_power_of_two() {
                    return Err(format!(
                        "WarpExecution r = 1 + n_ood + n_shifts = {r} must be a power of two",
                    ));
                }
                // Below r=4 the sampling profile (no OOD samples + at
                // most one shift query) collapses Construction 7.2's
                // codeword-batching soundness. The bench-validated
                // default `(1, 2)` sits exactly at r=4.
                if r < 4 {
                    return Err(format!(
                        "WarpExecution r = {r} is below the soundness floor (≥ 4)",
                    ));
                }
                if r > 256 {
                    return Err(format!(
                        "WarpExecution r = {r} exceeds reasonable bound (≤ 256)",
                    ));
                }
                Ok(())
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

    /// Create GkrExecution mode (requires GKR proof in every submission).
    pub fn gkr() -> Self {
        ExecutionMode::GkrExecution
    }

    /// Create WarpExecution mode with the bench-validated codeword size (n=2¹⁴)
    /// and the default sampling profile `(n_ood=1, n_shifts=2)` → `r=4`.
    pub fn warp() -> Self {
        ExecutionMode::WarpExecution {
            codeword_log_n: 14,
            n_ood: 1,
            n_shifts: 2,
        }
    }

    /// Create WarpExecution mode with a specific codeword size and the
    /// default `(n_ood=1, n_shifts=2)` sampling profile.
    pub fn warp_with_log_n(codeword_log_n: u8) -> Self {
        ExecutionMode::WarpExecution {
            codeword_log_n,
            n_ood: 1,
            n_shifts: 2,
        }
    }

    /// Create WarpExecution mode with explicit codeword size and sampling
    /// counts. `r = 1 + n_ood + n_shifts` must be a power of two.
    pub fn warp_with(codeword_log_n: u8, n_ood: u8, n_shifts: u8) -> Self {
        ExecutionMode::WarpExecution {
            codeword_log_n,
            n_ood,
            n_shifts,
        }
    }
}

/// Configuration for real-time blockchain indexing with GKR proofs.
///
/// This configuration controls how the indexer handles chain-tip (non-finalized)
/// blocks and generates GKR proofs for each block update.
///
/// # Performance Characteristics
///
/// | Operation | Typical Time |
/// |-----------|--------------|
/// | Proof generation (CPU) | ~560ms |
/// | Proof generation (GPU) | ~70ms (estimated) |
/// | Proof verification | ~176ms |
/// | Ethereum block time | 12,000ms |
///
/// With CPU-only proving, indexers can generate proofs for ~21 blocks per slot,
/// which is sufficient for most single-contract indexing scenarios.
///
/// # Tradeoffs vs Re-execution
///
/// GKR proofs are SLOWER to verify (~176ms) than WASM re-execution (~10-50ms),
/// but provide:
/// - Cryptographic trust (mathematical proof vs validator honesty)
/// - No WASM runtime required on validators
/// - No raw event data needed for verification
/// - Deterministic verification (no WASM non-determinism concerns)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeIndexingConfig {
    /// Whether to generate GKR proofs for each block update.
    /// If false, blocks are submitted for re-execution verification.
    pub enable_gkr_proofs: bool,

    /// GKR proof generation configuration.
    pub proof_config: GkrProofConfig,

    /// Maximum time (ms) to wait for proof generation before falling back.
    /// If proof generation exceeds this, submit without proof for re-execution.
    /// Set to 0 to disable timeout (always wait for proof).
    ///
    /// Recommended: 10000 (10 seconds) to stay within Ethereum slot time.
    pub proof_generation_timeout_ms: u64,

    /// Number of blocks to batch together for a single proof.
    /// Higher values improve throughput but increase latency.
    ///
    /// Recommended: 1 for real-time (lowest latency), 4-8 for higher throughput.
    pub batch_size: u32,

    /// Whether to use GPU acceleration for proof generation.
    /// Requires CUDA-compatible GPU with appropriate drivers.
    pub gpu_acceleration: bool,

    /// Maximum acceptable latency from chain tip (in blocks).
    /// If the indexer falls behind by this many blocks, it may skip proof
    /// generation temporarily to catch up.
    ///
    /// Recommended: 3-5 blocks for real-time indexing.
    pub max_latency_blocks: u32,

    /// Whether to fall back to re-execution mode if proof generation fails.
    /// If true, failed proofs result in submission without proof.
    /// If false, failed proofs cause the submission to be retried.
    pub fallback_to_reexecution: bool,

    /// Execution mode for consensus validation.
    /// Determines how validators verify submissions.
    pub chain_tip_execution_mode: ExecutionMode,
}

impl Default for RealtimeIndexingConfig {
    fn default() -> Self {
        Self {
            enable_gkr_proofs: true,
            proof_config: GkrProofConfig::default(),
            proof_generation_timeout_ms: 10_000, // 10 seconds
            batch_size: 1,
            gpu_acceleration: false,
            max_latency_blocks: 5,
            fallback_to_reexecution: true,
            chain_tip_execution_mode: ExecutionMode::ConsensusExecution,
        }
    }
}

impl RealtimeIndexingConfig {
    /// Create a configuration optimized for lowest latency.
    ///
    /// Single-block batches with no timeout waiting. Best for applications
    /// that need data available as soon as possible after each block.
    pub fn low_latency() -> Self {
        Self {
            enable_gkr_proofs: true,
            proof_config: GkrProofConfig::default(),
            proof_generation_timeout_ms: 5_000, // 5 seconds
            batch_size: 1,
            gpu_acceleration: false,
            max_latency_blocks: 2,
            fallback_to_reexecution: true,
            chain_tip_execution_mode: ExecutionMode::ConsensusExecution,
        }
    }

    /// Create a configuration optimized for highest throughput.
    ///
    /// Larger batches with GPU acceleration. Best for high-volume contracts
    /// where some latency is acceptable for better efficiency.
    pub fn high_throughput() -> Self {
        Self {
            enable_gkr_proofs: true,
            proof_config: GkrProofConfig::default(),
            proof_generation_timeout_ms: 30_000, // 30 seconds
            batch_size: 4,
            gpu_acceleration: true,
            max_latency_blocks: 10,
            fallback_to_reexecution: true,
            chain_tip_execution_mode: ExecutionMode::ConsensusExecution,
        }
    }

    /// Create a configuration where GKR proofs are mandatory.
    ///
    /// Proofs are required for every submission with no fallback to re-execution.
    /// Best for subgroves using `ExecutionMode::GkrExecution` where cryptographic
    /// trust is required.
    pub fn gkr_mandatory() -> Self {
        Self {
            enable_gkr_proofs: true,
            proof_config: GkrProofConfig::default(),
            proof_generation_timeout_ms: 0, // No timeout - always wait for proof
            batch_size: 1,
            gpu_acceleration: false,
            max_latency_blocks: 5,
            fallback_to_reexecution: false, // No fallback - proofs required
            chain_tip_execution_mode: ExecutionMode::GkrExecution,
        }
    }

    /// Create a configuration that uses re-execution instead of GKR proofs.
    ///
    /// For subgroves where GKR proof overhead is not justified or when
    /// hardware requirements cannot be met.
    pub fn reexecution_only() -> Self {
        Self {
            enable_gkr_proofs: false,
            proof_config: GkrProofConfig::default(),
            proof_generation_timeout_ms: 0,
            batch_size: 1,
            gpu_acceleration: false,
            max_latency_blocks: 3,
            fallback_to_reexecution: true,
            chain_tip_execution_mode: ExecutionMode::IndexerExecution {
                sampling_rate_percent: 5,
            },
        }
    }

    /// Check if this configuration can meet the given latency target.
    ///
    /// Returns true if the expected proof generation time is less than
    /// the target latency in milliseconds.
    pub fn can_meet_latency_target(&self, target_latency_ms: u64) -> bool {
        if !self.enable_gkr_proofs {
            return true; // Re-execution is always fast enough
        }

        // Estimated proof generation times (ms)
        let base_proof_time = if self.gpu_acceleration { 70 } else { 560 };
        let estimated_time = base_proof_time * self.batch_size as u64;

        estimated_time <= target_latency_ms
    }
}

#[cfg(test)]
mod warp_execution_mode_tests {
    use super::*;

    #[test]
    fn warp_constructor_uses_bench_validated_size() {
        let mode = ExecutionMode::warp();
        assert_eq!(mode.warp_codeword_log_n(), Some(14));
        assert!(mode.is_warp_execution());
        assert!(mode.requires_warp_proof());
        assert!(!mode.is_gkr_execution());
        assert!(!mode.requires_reexecution());
        assert_eq!(mode.verification_rate(), 0.0);
        assert_eq!(mode.verification_rate_percent(), 0);
    }

    #[test]
    fn warp_validate_rejects_out_of_range_log_n() {
        assert!(ExecutionMode::warp_with_log_n(7).validate().is_err());
        assert!(ExecutionMode::warp_with_log_n(25).validate().is_err());
        assert!(ExecutionMode::warp_with_log_n(8).validate().is_ok());
        assert!(ExecutionMode::warp_with_log_n(14).validate().is_ok());
        assert!(ExecutionMode::warp_with_log_n(24).validate().is_ok());
    }

    #[test]
    fn warp_fee_multiplier_sits_between_tee_and_gkr() {
        // TEE (0.10, hardware-attested) is cheapest; WARP (0.12, log-time decider)
        // is between TEE and GKR (0.15, full-circuit verify); both crypto modes
        // beat indexer/consensus execution.
        let warp = ExecutionMode::warp().fee_multiplier();
        let tee = ExecutionMode::tee_nitro().fee_multiplier();
        let gkr = ExecutionMode::GkrExecution.fee_multiplier();
        assert!(tee < warp, "tee {tee} should be < warp {warp}");
        assert!(warp < gkr, "warp {warp} should be < gkr {gkr}");
        assert!(warp < ExecutionMode::indexer_low().fee_multiplier());
        assert!(warp < ExecutionMode::ConsensusExecution.fee_multiplier());
    }

    #[test]
    fn warp_round_trips_through_serde_json() {
        let mode = ExecutionMode::warp_with_log_n(18);
        let json = serde_json::to_string(&mode).expect("serialize");
        let decoded: ExecutionMode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(mode, decoded);
        assert_eq!(decoded.warp_codeword_log_n(), Some(18));
    }

    #[test]
    fn warp_round_trips_through_bincode() {
        let mode = ExecutionMode::warp_with(14, 1, 2);
        let bytes = bincode::serialize(&mode).expect("bincode serialize");
        let decoded: ExecutionMode = bincode::deserialize(&bytes).expect("bincode deserialize");
        assert_eq!(mode, decoded);
    }

    #[test]
    fn warp_validate_rejects_r_below_soundness_floor() {
        // r = 1 + 0 + 0 = 1: degenerate, no OOD samples, no shift queries.
        // Construction 7.2 codeword-batching soundness collapses below r=4.
        let mode = ExecutionMode::warp_with(14, 0, 0);
        let err = mode.validate().expect_err("r=1 must be rejected");
        assert!(
            err.contains("soundness floor"),
            "error should explain soundness floor, got: {err}"
        );
        // r = 1 + 1 + 0 = 2: still below floor, but is_power_of_two() rejects
        // it first with a different message. Either rejection is acceptable.
        assert!(ExecutionMode::warp_with(14, 1, 0).validate().is_err());
        // r = 1 + 1 + 2 = 4: bench-validated default, passes.
        assert!(ExecutionMode::warp_with(14, 1, 2).validate().is_ok());
        // r = 1 + 3 + 4 = 8: still valid.
        assert!(ExecutionMode::warp_with(14, 3, 4).validate().is_ok());
    }

    #[test]
    fn execution_mode_warp_is_last_variant() {
        // Bincode encodes enum discriminants by declaration order. If
        // WarpExecution drifts from the tail, every variant after it
        // shifts and existing serialized data fails to decode. Pin the
        // discriminant via a bincode round-trip of the next-to-last
        // variant (GkrExecution → discriminant 3) and WarpExecution
        // (→ discriminant 4, the tail).
        let gkr_bytes = bincode::serialize(&ExecutionMode::GkrExecution).expect("serialize gkr");
        assert_eq!(&gkr_bytes[..4], &[3, 0, 0, 0]);
        let warp_bytes = bincode::serialize(&ExecutionMode::warp()).expect("serialize warp");
        assert_eq!(&warp_bytes[..4], &[4, 0, 0, 0]);
    }
}
