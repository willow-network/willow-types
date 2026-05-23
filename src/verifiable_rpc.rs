//! Wire types for the verifiable RPC flow.
//!
//! An indexer serves a query result with a GKR proof attached, and the client
//! verifies locally without any blockchain round-trip. The types in this module
//! define the on-the-wire shape of that response so both the indexer-node HTTP
//! handler and any SDK decode into the same struct.
//!
//! See `docs/VERIFIABLE_RPC.md` for the end-to-end design.

use serde::{Deserialize, Serialize};

use crate::consensus::indexing_transactions::GkrProofData;
use crate::state_proof::StateProof;

/// Response served by `GET /verifiable-rpc/:subgrove_id/:query_key`.
///
/// The client verifies:
/// 1. The GKR proof (`gkr_proof`) is valid — confirms `state_root` is the
///    correct output of applying the subgrove transformation to committed
///    events.
/// 2. The GroveDB Merkle proof (`grovedb_proof`) verifies against `state_root`,
///    tying `answer` to the committed state.
///
/// `gkr_proof` is optional: a freshly started indexer may have an answer and
/// a GroveDB proof before it has generated a GKR proof for the current
/// checkpoint. Clients in `VerifyMode::Strict` should reject responses without
/// a GKR proof; clients in `VerifyMode::GroveDbOnly` can still trust the
/// answer by anchoring the root via consensus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableRpcResponse {
    pub subgrove_id: String,

    /// The key that was queried (echoed back for client-side sanity).
    #[serde(with = "crate::serde_helpers::bytes_base64")]
    pub key: Vec<u8>,

    /// The value stored at that key. Empty when `answer_exists == false`.
    #[serde(with = "crate::serde_helpers::bytes_base64")]
    pub answer: Vec<u8>,

    /// `false` means the key was not present in the subgrove's state tree.
    /// A non-existence GroveDB proof is still returned in `grovedb_proof` so
    /// the absence is cryptographically verifiable.
    pub answer_exists: bool,

    /// Latest checkpoint ID this indexer has for the subgrove.
    pub checkpoint_id: [u8; 32],

    /// State root the answer is proven against. For single-chunk
    /// transformations this equals `gkr_proofs[0].public_inputs.output_root`;
    /// for chunked transformations, it equals the *last* chunk's
    /// `output_root` (the block's final transformed state).
    pub state_root: [u8; 32],

    /// Inclusive block range covered by the checkpoint that produced
    /// `state_root`.
    pub block_range: (u64, u64),

    /// GroveDB Merkle proof that `answer` (or its absence) is the value at
    /// `key` in the tree rooted at `state_root`.
    #[serde(with = "crate::serde_helpers::bytes_base64")]
    pub grovedb_proof: Vec<u8>,

    /// GKR proofs of correct transformation, one per chunk.
    ///
    /// - Empty: the indexer hasn't generated proofs for the current
    ///   checkpoint yet (typical shortly after startup or right after
    ///   a new checkpoint is accepted). Strict-mode clients reject;
    ///   GroveDB-only clients can still trust the answer by anchoring
    ///   against consensus.
    /// - Length 1: single-chunk submission (matched events fit in one
    ///   circuit batch). Mirrors the bulk of real-world traffic.
    /// - Length > 1: chunked submission. The indexer generated one
    ///   transformation proof per chunk of `COMPLETENESS_LOG_BATCH`
    ///   matched events; chunk i+1's `starting_state_root` chains to
    ///   chunk i's `output_root`. Browsers verify each chunk in turn
    ///   and confirm the final chunk's `output_root == state_root`.
    #[serde(default)]
    pub gkr_proofs: Vec<GkrProofData>,

    /// Serialized `ChunkedBlockCompletenessProof` for the same
    /// checkpoint. Present when the subgrove is completeness-enabled
    /// and the indexer kept the proof for this checkpoint.
    ///
    /// Browsers consume this via
    /// `gkr_verify_wasm::verify_chunked_block_completeness` to verify
    /// independently of the transformation proof, closing the
    /// indexer-subset-picking attack on the browser side that
    /// consensus already catches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "crate::serde_helpers::option_bytes_base64")]
    pub completeness_proof: Option<Vec<u8>>,

    /// Verifiable Ethereum state proofs attached to this response.
    /// Populated for `/verifiable-rpc/eth/state` and
    /// `/verifiable-rpc/eth/call` flows; empty for the legacy
    /// subgrove-query path. Each entry binds account (and optional
    /// storage slot) values to the block's `state_root` via MPT
    /// inclusion. SDKs cross-check each `state_root` against their
    /// own light-client-verified header before trusting the values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub state_proofs: Vec<StateProof>,

    /// When the indexer generated this response (unix seconds). Used by the
    /// client to enforce a freshness bound.
    pub served_at_unix_secs: u64,
}

/// Error returned by the verifiable RPC endpoint.
///
/// Status-code mapping lives in the handler; this struct is the JSON body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableRpcErrorBody {
    pub code: VerifiableRpcErrorCode,
    pub message: String,
}

/// Machine-readable error classification.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerifiableRpcErrorCode {
    /// Verifiable RPC is disabled on this indexer.
    Disabled,
    /// The indexer has never seen the requested subgrove.
    SubgroveNotFound,
    /// The indexer knows the subgrove but has no checkpoint for it yet.
    NoCheckpoint,
    /// The query key was not a valid hex string.
    InvalidKey,
    /// GroveDB failed to produce a proof for the query.
    QueryFailed,
    /// Uncategorized internal failure.
    Internal,
}

impl VerifiableRpcErrorCode {
    /// Suggested HTTP status for this error code.
    pub fn http_status(self) -> u16 {
        match self {
            VerifiableRpcErrorCode::Disabled => 404,
            VerifiableRpcErrorCode::SubgroveNotFound => 404,
            VerifiableRpcErrorCode::NoCheckpoint => 503,
            VerifiableRpcErrorCode::InvalidKey => 400,
            VerifiableRpcErrorCode::QueryFailed => 500,
            VerifiableRpcErrorCode::Internal => 500,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::indexing_transactions::{
        GkrCommitmentScheme, GkrHashFunction, GkrPublicInputs,
    };
    use crate::consensus::CURRENT_PROOF_VERSION;
    use base64::Engine;

    fn sample_proof() -> GkrProofData {
        GkrProofData {
            proof_version: CURRENT_PROOF_VERSION,
            proof: vec![0xaau8; 256],
            public_inputs: GkrPublicInputs {
                output_root: [2; 32],
                block_range: (100, 200),
                config_hash: [3; 32],
                starting_state_root: [0; 32],
            },
            verification_key_hash: [4; 32],
            proof_size_bytes: 256,
            generation_time_ms: 42,
            gpu_accelerated: false,
        }
    }

    #[test]
    fn response_roundtrips_through_json() {
        let proof = sample_proof();
        let resp = VerifiableRpcResponse {
            subgrove_id: "balance-aggregator".into(),
            key: vec![0xde, 0xad, 0xbe, 0xef],
            answer: vec![1, 2, 3, 4, 5],
            answer_exists: true,
            checkpoint_id: [7; 32],
            state_root: proof.public_inputs.output_root,
            block_range: proof.public_inputs.block_range,
            grovedb_proof: vec![0x55; 128],
            gkr_proofs: vec![proof.clone()],
            completeness_proof: None,
            state_proofs: vec![],
            served_at_unix_secs: 1_700_000_000,
        };

        let json = serde_json::to_string(&resp).expect("serialize");
        // Outer binary fields (key, answer, grovedb_proof) must be base64 —
        // the JSON must contain our encoded strings and not expose those
        // specific bytes as number arrays.
        let expected_key_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&resp.key);
        let expected_proof_b64 =
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(&resp.grovedb_proof);
        assert!(json.contains(&format!("\"{}\"", expected_key_b64)));
        assert!(json.contains(&format!("\"{}\"", expected_proof_b64)));

        let parsed: VerifiableRpcResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.subgrove_id, resp.subgrove_id);
        assert_eq!(parsed.key, resp.key);
        assert_eq!(parsed.answer, resp.answer);
        assert_eq!(parsed.grovedb_proof, resp.grovedb_proof);
        assert_eq!(parsed.state_root, resp.state_root);
        assert_eq!(parsed.block_range, resp.block_range);
        assert_eq!(parsed.gkr_proofs.len(), 1, "gkr_proofs vec preserved");
        let parsed_proof = &parsed.gkr_proofs[0];
        assert_eq!(parsed_proof.proof, proof.proof);
        assert_eq!(parsed_proof.public_inputs, proof.public_inputs);
        assert_eq!(
            parsed_proof.verification_key_hash,
            proof.verification_key_hash
        );
    }

    #[test]
    fn response_carries_state_proofs_when_populated() {
        use crate::consensus::indexing_transactions::data_updates::MptProof;
        use crate::state_proof::{AccountState, StateProof, StorageSlotProof};

        let state_proof = StateProof {
            address: [0xaau8; 20],
            block_number: 19_000_000,
            block_hash: [0xbbu8; 32],
            state_root: [0xccu8; 32],
            account_proof: MptProof {
                key: vec![0x01u8; 32],
                value: vec![0x02u8; 64],
                proof_nodes: vec![vec![0x03u8; 96]],
            },
            account_state: AccountState {
                nonce: 7,
                balance: [0x04u8; 32],
                storage_hash: [0x05u8; 32],
                code_hash: [0x06u8; 32],
            },
            storage_proofs: vec![StorageSlotProof {
                slot: [0x07u8; 32],
                value: [0x08u8; 32],
                proof: MptProof {
                    key: vec![0x09u8; 32],
                    value: vec![0x0au8; 32],
                    proof_nodes: vec![vec![0x0bu8; 96]],
                },
            }],
        };

        let resp = VerifiableRpcResponse {
            subgrove_id: "eth-state".into(),
            key: vec![],
            answer: vec![],
            answer_exists: true,
            checkpoint_id: [0; 32],
            state_root: state_proof.state_root,
            block_range: (state_proof.block_number, state_proof.block_number),
            grovedb_proof: vec![],
            gkr_proofs: vec![],
            completeness_proof: None,
            state_proofs: vec![state_proof.clone()],
            served_at_unix_secs: 1_700_000_000,
        };

        let json = serde_json::to_string(&resp).expect("serialize");
        let parsed: VerifiableRpcResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.state_proofs.len(), 1);
        assert_eq!(parsed.state_proofs[0].address, state_proof.address);
        assert_eq!(parsed.state_proofs[0].state_root, state_proof.state_root);
        assert_eq!(
            parsed.state_proofs[0].account_state,
            state_proof.account_state
        );
        assert_eq!(parsed.state_proofs[0].storage_proofs.len(), 1);

        // Also confirm we elide the field when empty — gkr-only callers
        // shouldn't see a stray `"state_proofs":[]` in their wire.
        let resp_empty = VerifiableRpcResponse {
            state_proofs: vec![],
            ..resp
        };
        let json_empty = serde_json::to_string(&resp_empty).expect("serialize");
        assert!(
            !json_empty.contains("state_proofs"),
            "empty state_proofs should be skipped on the wire, got: {}",
            json_empty
        );
    }

    #[test]
    fn response_accepts_legacy_json_without_state_proofs() {
        // Wire-format forward compatibility: a payload from an indexer
        // built before `state_proofs` existed must deserialize cleanly
        // and yield an empty Vec, not a parse error.
        let proof = sample_proof();
        let resp = VerifiableRpcResponse {
            subgrove_id: "legacy".into(),
            key: vec![1, 2, 3],
            answer: vec![4, 5, 6],
            answer_exists: true,
            checkpoint_id: [9; 32],
            state_root: proof.public_inputs.output_root,
            block_range: proof.public_inputs.block_range,
            grovedb_proof: vec![0x77; 32],
            gkr_proofs: vec![proof],
            completeness_proof: None,
            state_proofs: vec![],
            served_at_unix_secs: 1_700_000_001,
        };
        // Serialize, then strip the absent state_proofs key from the
        // JSON (it should already be absent due to skip_serializing_if)
        // and verify the result still round-trips.
        let json = serde_json::to_string(&resp).expect("serialize");
        assert!(!json.contains("state_proofs"));
        let parsed: VerifiableRpcResponse = serde_json::from_str(&json).expect("deserialize");
        assert!(parsed.state_proofs.is_empty());
    }

    #[test]
    fn error_code_http_status_covers_all_variants() {
        for code in [
            VerifiableRpcErrorCode::Disabled,
            VerifiableRpcErrorCode::SubgroveNotFound,
            VerifiableRpcErrorCode::NoCheckpoint,
            VerifiableRpcErrorCode::InvalidKey,
            VerifiableRpcErrorCode::QueryFailed,
            VerifiableRpcErrorCode::Internal,
        ] {
            let status = code.http_status();
            assert!(
                (400..600).contains(&status),
                "bad status {} for {:?}",
                status,
                code
            );
        }
        // Silence unused-import warning when additional variants live in the
        // GKR module but aren't used here.
        let _ = (GkrCommitmentScheme::Orion, GkrHashFunction::Poseidon);
    }
}
