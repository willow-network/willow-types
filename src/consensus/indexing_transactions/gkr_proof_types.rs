// ============================================================================
// GKR Proof Types - Cryptographic proof system for real-time (chain-tip) indexing verification
// ============================================================================

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Configuration for GKR proof generation and verification.
///
/// GKR (Goldwasser-Kalai-Rothblum) is an interactive proof system that allows
/// efficient verification of computation. When enabled, a single indexer can
/// cryptographically prove they correctly executed the indexing transformation,
/// eliminating the need for multiple redundant indexers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct GkrProofConfig {
    /// Whether GPU acceleration is enabled for proof generation.
    /// GPU proving is significantly faster (8-10x) but requires compatible hardware.
    pub gpu_enabled: bool,

    /// Hash of the circuit version used for proving.
    /// Must match between prover and verifier to ensure compatibility.
    /// This is computed from the circuit definition at compile time.
    pub circuit_version: [u8; 32],

    /// Polynomial commitment scheme to use.
    pub commitment_scheme: GkrCommitmentScheme,

    /// Hash function used for internal commitments.
    pub hash_function: GkrHashFunction,
}

impl Default for GkrProofConfig {
    fn default() -> Self {
        Self {
            gpu_enabled: false,
            circuit_version: [0u8; 32], // Must be set during deployment
            commitment_scheme: GkrCommitmentScheme::Orion,
            hash_function: GkrHashFunction::Poseidon,
        }
    }
}

/// Polynomial commitment scheme for GKR proofs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum GkrCommitmentScheme {
    /// Orion commitment scheme (transparent, no trusted setup).
    #[default]
    Orion,
    /// Brakedown commitment scheme (code-based, post-quantum).
    Brakedown,
    /// KZG commitment scheme (requires trusted setup, smallest proofs).
    Kzg,
}

/// Hash function used in GKR proofs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum GkrHashFunction {
    /// SHA256 - widely compatible, slower in circuits.
    Sha256,
    /// Poseidon - ZK-friendly, efficient in circuits.
    #[default]
    Poseidon,
    /// MiMC - alternative ZK-friendly hash.
    Mimc,
}

/// Public inputs for GKR proof verification.
///
/// These values are visible to the verifier and bind the proof to specific
/// output data and configuration. Events binding is handled inside the
/// circuit via Poseidon (`pub_input_events_hash`); the verifier extracts
/// that value from the proof's public-input region and compares against
/// `events_hash(real Ethereum logs)` from a light client.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GkrPublicInputs {
    /// Merkle root of the output entities (indexed data after transformation).
    pub output_root: [u8; 32],

    /// Block range covered by this proof (start_block, end_block inclusive).
    pub block_range: (u64, u64),

    /// Hash of the subgrove configuration used for transformation.
    /// Ensures the correct transformation rules were applied.
    pub config_hash: [u8; 32],

    /// Merkle root of the starting state this proof transitioned from.
    /// Validator enforces starting_state_root == last block's output_root
    /// to chain proofs cryptographically. Zeroed for circuits without
    /// state, and for the genesis block of a stateful subgrove.
    #[serde(default)]
    pub starting_state_root: [u8; 32],
}

impl GkrPublicInputs {
    /// SHA-256 commitment over the public inputs, embedded inside the
    /// proof bytes by the prover and re-derived by the verifier. The
    /// prover and verifier MUST agree byte-for-byte on this recipe;
    /// historical drift between sites caused every full GKR proof to be
    /// rejected. Both call this method — never inline the hash.
    pub fn embedded_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.output_root);
        hasher.update(self.config_hash);
        hasher.update(self.block_range.0.to_be_bytes());
        hasher.update(self.block_range.1.to_be_bytes());
        hasher.update(self.starting_state_root);
        hasher.finalize().into()
    }
}

/// Current proof-format version; verifiers reject other values.
pub const CURRENT_PROOF_VERSION: u8 = 1;

/// Complete GKR proof data for submission and verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GkrProofData {
    /// Wire-format version; must equal [`CURRENT_PROOF_VERSION`].
    pub proof_version: u8,

    /// The serialized GKR proof bytes.
    pub proof: Vec<u8>,

    /// Public inputs that bind the proof to specific data.
    pub public_inputs: GkrPublicInputs,

    /// Hash of the verification key used.
    /// Verifiers look up the key by this hash.
    pub verification_key_hash: [u8; 32],

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
    fn embedded_hash_matches_frozen_layout() {
        // Frozen byte layout for the public-input commitment. If this
        // changes, every existing full GKR proof becomes unverifiable
        // (consensus break). Bumping it is a deliberate, coordinated
        // protocol change — never an incidental edit.
        let inputs = GkrPublicInputs {
            output_root: [0x11; 32],
            block_range: (100, 200),
            config_hash: [0x22; 32],
            starting_state_root: [0x33; 32],
        };
        let h = inputs.embedded_hash();

        let mut expected = Sha256::new();
        expected.update([0x11; 32]);
        expected.update([0x22; 32]);
        expected.update(100u64.to_be_bytes());
        expected.update(200u64.to_be_bytes());
        expected.update([0x33; 32]);
        let expected: [u8; 32] = expected.finalize().into();

        assert_eq!(h, expected);
    }

    #[test]
    fn embedded_hash_is_deterministic() {
        let a = GkrPublicInputs {
            output_root: [0xaa; 32],
            block_range: (1, 2),
            config_hash: [0xbb; 32],
            starting_state_root: [0xcc; 32],
        };
        let b = a.clone();
        assert_eq!(a.embedded_hash(), b.embedded_hash());
    }

    #[test]
    fn embedded_hash_differs_on_each_field() {
        let base = GkrPublicInputs {
            output_root: [0; 32],
            block_range: (0, 0),
            config_hash: [0; 32],
            starting_state_root: [0; 32],
        };
        let h0 = base.embedded_hash();

        let mut v = base.clone();
        v.output_root[0] = 1;
        assert_ne!(h0, v.embedded_hash(), "output_root must affect hash");

        let mut v = base.clone();
        v.config_hash[0] = 1;
        assert_ne!(h0, v.embedded_hash(), "config_hash must affect hash");

        let mut v = base.clone();
        v.block_range.0 = 1;
        assert_ne!(h0, v.embedded_hash(), "block_range.0 must affect hash");

        let mut v = base.clone();
        v.block_range.1 = 1;
        assert_ne!(h0, v.embedded_hash(), "block_range.1 must affect hash");

        let mut v = base.clone();
        v.starting_state_root[0] = 1;
        assert_ne!(
            h0,
            v.embedded_hash(),
            "starting_state_root must affect hash"
        );
    }
}
