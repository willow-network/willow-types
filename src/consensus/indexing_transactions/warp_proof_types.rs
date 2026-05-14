// ============================================================================
// WARP Proof Types — folding-scheme submissions for high-throughput historical
// sync. Mirrors `gkr_proof_types.rs` but for WARP (eprint 2025/753) proofs
// produced by `willow-folding`.
// ============================================================================

use serde::{Deserialize, Serialize};

/// Public inputs for a WARP fold-step proof.
///
/// Mirrors `GkrPublicInputs` semantically: pins the proof to specific output
/// data and to the prior accumulator state. The verifier reconstructs the
/// initial twin-constrained instance from `prev_instance_root` and checks
/// the submitted fold message against it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WarpPublicInputs {
    /// Merkle root of the output entities (indexed data after transformation).
    pub output_root: [u8; 32],

    /// Block range covered by this fold step (start_block, end_block inclusive).
    pub block_range: (u64, u64),

    /// Hash of the subgrove configuration used for transformation.
    pub config_hash: [u8; 32],

    /// Merkle root of the running WARP accumulator state *before* this fold step.
    /// The first submission of a subgrove sets this to all zeros (genesis).
    /// Subsequent submissions must match the prior submission's `new_instance_root`,
    /// chaining the fold tree cryptographically.
    pub prev_instance_root: [u8; 32],

    /// Merkle root of the running WARP accumulator state *after* this fold step.
    /// This becomes the next submission's `prev_instance_root`.
    pub new_instance_root: [u8; 32],
}

/// Complete WARP fold-step proof data for submission and verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarpProofData {
    /// Serialized WARP fold-step proof bytes.
    /// Encoded via `expander-serdes` over the transcript:
    /// `(BatchedEvalClaims, MultilinearBatchingMsg, CodewordBatchingMsg, ...)`
    pub proof: Vec<u8>,

    /// Public inputs that bind the proof to specific data and accumulator state.
    pub public_inputs: WarpPublicInputs,

    /// Codeword `log_n` used by this proof. Must match the subgrove's
    /// `WarpExecution.codeword_log_n` declared at registration.
    pub codeword_log_n: u8,

    /// Construction 7.2 OOD sample count used by this proof. Must match
    /// the subgrove's `WarpExecution.n_ood` — the FS transcript depends
    /// on it, so a mismatch is a divergence and gets rejected.
    pub n_ood: u8,

    /// Construction 7.2 shift-query count used by this proof. Same
    /// FS-binding constraint as `n_ood`.
    pub n_shifts: u8,

    /// Number of parallel-rep folds in this proof (currently fixed at 2 for
    /// 128-bit security over M31Ext3).
    pub parallel_rep: u8,

    /// Size of the proof in bytes (for metrics/limits).
    pub proof_size_bytes: u64,

    /// Time taken to generate the proof in milliseconds.
    pub generation_time_ms: u64,

    /// Whether the proof was generated using GPU acceleration.
    pub gpu_accelerated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warp_proof_data_round_trips_through_serde_json() {
        let data = WarpProofData {
            proof: vec![0xAA; 256],
            public_inputs: WarpPublicInputs {
                output_root: [1u8; 32],
                block_range: (1_000, 1_000),
                config_hash: [2u8; 32],
                prev_instance_root: [3u8; 32],
                new_instance_root: [4u8; 32],
            },
            codeword_log_n: 14,
            n_ood: 1,
            n_shifts: 2,
            parallel_rep: 2,
            proof_size_bytes: 256,
            generation_time_ms: 5,
            gpu_accelerated: true,
        };
        let json = serde_json::to_string(&data).expect("serialize");
        let decoded: WarpProofData = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.proof, data.proof);
        assert_eq!(decoded.public_inputs, data.public_inputs);
        assert_eq!(decoded.codeword_log_n, 14);
        assert_eq!(decoded.parallel_rep, 2);
        assert!(decoded.gpu_accelerated);
    }

    #[test]
    fn warp_public_inputs_default_is_all_zeros() {
        let zero = WarpPublicInputs::default();
        assert_eq!(zero.output_root, [0u8; 32]);
        assert_eq!(zero.block_range, (0, 0));
        assert_eq!(zero.config_hash, [0u8; 32]);
        assert_eq!(zero.prev_instance_root, [0u8; 32]);
        assert_eq!(zero.new_instance_root, [0u8; 32]);
    }

    #[test]
    fn warp_proof_data_round_trips_through_bincode() {
        // Bincode is the wire/storage format for tx submissions. JSON
        // tolerates field reorder; bincode does not — re-encoding here
        // is the load-bearing guard against accidental chain-break.
        let data = WarpProofData {
            proof: vec![0xCD; 257],
            public_inputs: WarpPublicInputs {
                output_root: [9u8; 32],
                block_range: (42, 42),
                config_hash: [7u8; 32],
                prev_instance_root: [5u8; 32],
                new_instance_root: [6u8; 32],
            },
            codeword_log_n: 12,
            n_ood: 3,
            n_shifts: 4,
            parallel_rep: 2,
            proof_size_bytes: 257,
            generation_time_ms: 11,
            gpu_accelerated: false,
        };
        let bytes = bincode::serialize(&data).expect("bincode serialize");
        let decoded: WarpProofData = bincode::deserialize(&bytes).expect("bincode deserialize");
        assert_eq!(decoded.proof, data.proof);
        assert_eq!(decoded.public_inputs, data.public_inputs);
        assert_eq!(decoded.codeword_log_n, data.codeword_log_n);
        assert_eq!(decoded.n_ood, data.n_ood);
        assert_eq!(decoded.n_shifts, data.n_shifts);
        assert_eq!(decoded.parallel_rep, data.parallel_rep);
        assert_eq!(decoded.proof_size_bytes, data.proof_size_bytes);
        assert_eq!(decoded.generation_time_ms, data.generation_time_ms);
        assert_eq!(decoded.gpu_accelerated, data.gpu_accelerated);
    }
}
