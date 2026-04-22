// ============================================================================
// GKR Proof Types - Cryptographic proof system for real-time (chain-tip) indexing verification
// ============================================================================

use serde::{Deserialize, Serialize};

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
/// input data, output data, and configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GkrPublicInputs {
    /// SHA256 hash commitment to all input events (raw Ethereum data).
    pub input_commitment: [u8; 32],

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

/// Complete GKR proof data for submission and verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GkrProofData {
    /// The serialized GKR proof bytes. Base64-encoded on the wire so
    /// JSON-serialized txs don't blow up 4x (default serde_json encoding
    /// of Vec<u8> is a numeric array like [131, 7, ...]). A ~3.7MB proof
    /// becomes ~15MB as a number array; base64 keeps it at ~5MB.
    #[serde(with = "base64_bytes")]
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

mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        STANDARD.encode(bytes).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}
