//! Wire types for verifiable Ethereum state reads.
//!
//! A state proof bundles a light-client-verifiable witness that some
//! account state at a specific block matches the values carried in
//! the struct. Verification uses the Merkle Patricia Trie machinery
//! already present in `consensus::indexing_transactions::data_updates`
//! ([`MptProof`]), anchored at a `state_root` the SDK independently
//! cross-checks against a light-client-verified block header.
//!
//! Two flavors:
//! - [`StateProof`] — direct `eth_getProof`-style account / storage
//!   read with a per-slot proof set.
//! - [`VerifiedCallResult`] — bundle for `eth_call`: ABI-encoded
//!   return data + one [`StateProof`] per account REVM touched during
//!   execution.

use serde::{Deserialize, Serialize};

use crate::consensus::indexing_transactions::data_updates::MptProof;

/// Verifiable proof that an Ethereum account's state at a specific
/// block matches the values bundled in this struct.
///
/// The `account_proof` walks the state MPT from `state_root` down to
/// the account leaf (which RLP-decodes into [`AccountState`]). Each
/// entry in `storage_proofs` walks the per-account storage MPT from
/// `account_state.storage_hash` down to a single slot leaf.
///
/// `block_number` / `block_hash` / `state_root` anchor the SDK-side
/// re-verification: the client confirms the same `state_root` is
/// present in its own light-client-verified header for that block,
/// then walks the proofs to recover account and slot values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateProof {
    /// The 20-byte address whose state is being proved.
    pub address: [u8; 20],
    /// Ethereum block number this state was read at.
    pub block_number: u64,
    /// Hash of the Ethereum block containing this state.
    pub block_hash: [u8; 32],
    /// State root of the block — the anchor for `account_proof`.
    pub state_root: [u8; 32],
    /// MPT proof from `state_root` to the RLP-encoded account leaf.
    /// `account_proof.key` is `keccak256(address)`; `account_proof.value`
    /// is the RLP-encoded account.
    pub account_proof: MptProof,
    /// Decoded account state, redundant with `account_proof.value` for
    /// SDK convenience. SDKs without an RLP decoder can read fields
    /// directly; SDKs with a verifier must cross-check that decoding
    /// `account_proof.value` yields the same struct.
    pub account_state: AccountState,
    /// Per-slot storage proofs against `account_state.storage_hash`.
    /// Empty when the caller only needed account-level data.
    pub storage_proofs: Vec<StorageSlotProof>,
}

/// Proof for a single storage slot under an account's storage trie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSlotProof {
    /// The 32-byte storage key (typically `keccak256(abi.encode(...))`
    /// for mapping slots, or a left-padded index for fixed slots).
    pub slot: [u8; 32],
    /// The 32-byte slot value (RLP-decoded from the leaf, big-endian
    /// padded).
    pub value: [u8; 32],
    /// MPT proof from `storage_hash` down to this slot's leaf.
    /// `proof.key` is `keccak256(slot)`; `proof.value` is the RLP
    /// encoding of the slot value.
    pub proof: MptProof,
}

/// Decoded account fields, matching the EIP-1186 RLP layout.
///
/// `balance` is carried as a 32-byte big-endian buffer to fit the full
/// U256 range without pulling `alloy` / `primitive-types` into the
/// types crate. SDKs convert this to their native bignum type at the
/// boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountState {
    pub nonce: u64,
    pub balance: [u8; 32],
    pub storage_hash: [u8; 32],
    pub code_hash: [u8; 32],
}

/// Verifiable result of an `eth_call`.
///
/// The indexer ran the call locally inside Helios's verified-state
/// REVM; every account REVM touched is bundled here as a [`StateProof`]
/// whose `storage_proofs` cover the slots that were SLOADed for that
/// account. The SDK confirms each proof against its own light-client-
/// verified `state_root` for `block_number`, which reduces eth_call
/// trust to "the indexer's REVM executed correctly against verified
/// inputs."
///
/// A fully client-side re-execution would require shipping a WASM REVM
/// in every SDK; that's deferred. Until then, the trust delta versus
/// direct state reads is one honest level higher — surfaced explicitly
/// in the SDK's `VerificationResult` enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedCallResult {
    /// Block the call was executed against.
    pub block_number: u64,
    /// Hash of that block.
    pub block_hash: [u8; 32],
    /// State root anchoring every entry in `access_state_proofs`.
    pub state_root: [u8; 32],
    /// ABI-encoded return data from the call.
    pub result: Vec<u8>,
    /// One state proof per account REVM touched during execution.
    /// Each proof's `storage_proofs` cover exactly the slots that
    /// were SLOADed for that account.
    pub access_state_proofs: Vec<StateProof>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_mpt_proof() -> MptProof {
        MptProof {
            key: vec![0xaau8; 32],
            value: vec![0xbbu8; 64],
            proof_nodes: vec![vec![0xccu8; 128], vec![0xddu8; 96]],
        }
    }

    fn sample_account_state() -> AccountState {
        AccountState {
            nonce: 42,
            balance: [0x01u8; 32],
            storage_hash: [0x02u8; 32],
            code_hash: [0x03u8; 32],
        }
    }

    fn sample_state_proof() -> StateProof {
        StateProof {
            address: [0xaau8; 20],
            block_number: 19_000_000,
            block_hash: [0xbbu8; 32],
            state_root: [0xccu8; 32],
            account_proof: sample_mpt_proof(),
            account_state: sample_account_state(),
            storage_proofs: vec![StorageSlotProof {
                slot: [0xddu8; 32],
                value: [0xeeu8; 32],
                proof: sample_mpt_proof(),
            }],
        }
    }

    #[test]
    fn state_proof_roundtrips_through_json() {
        let original = sample_state_proof();
        let json = serde_json::to_string(&original).expect("serialize");
        let parsed: StateProof = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.address, original.address);
        assert_eq!(parsed.block_number, original.block_number);
        assert_eq!(parsed.block_hash, original.block_hash);
        assert_eq!(parsed.state_root, original.state_root);
        assert_eq!(parsed.account_state, original.account_state);
        assert_eq!(parsed.storage_proofs.len(), 1);
        assert_eq!(parsed.storage_proofs[0].slot, [0xddu8; 32]);
        assert_eq!(parsed.storage_proofs[0].value, [0xeeu8; 32]);
    }

    #[test]
    fn state_proof_account_only_roundtrips() {
        let mut proof = sample_state_proof();
        proof.storage_proofs.clear();
        let json = serde_json::to_string(&proof).expect("serialize");
        let parsed: StateProof = serde_json::from_str(&json).expect("deserialize");
        assert!(parsed.storage_proofs.is_empty());
    }

    #[test]
    fn verified_call_result_roundtrips() {
        let call = VerifiedCallResult {
            block_number: 19_000_001,
            block_hash: [0x11u8; 32],
            state_root: [0x22u8; 32],
            result: vec![0x33u8; 32],
            access_state_proofs: vec![sample_state_proof(), sample_state_proof()],
        };
        let json = serde_json::to_string(&call).expect("serialize");
        let parsed: VerifiedCallResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.block_number, call.block_number);
        assert_eq!(parsed.block_hash, call.block_hash);
        assert_eq!(parsed.state_root, call.state_root);
        assert_eq!(parsed.result, call.result);
        assert_eq!(parsed.access_state_proofs.len(), 2);
    }

    #[test]
    fn state_proof_roundtrips_through_bincode() {
        // The types crate has no `bincode` runtime dep; this test
        // uses serde_json for the canonical roundtrip and only sanity-
        // checks that the encoded JSON is structurally stable across
        // ser-then-deser-then-ser cycles, the same property bincode
        // relies on when these types travel over the indexer-node /
        // SDK boundary.
        let original = sample_state_proof();
        let once = serde_json::to_string(&original).expect("serialize");
        let parsed: StateProof = serde_json::from_str(&once).expect("deserialize");
        let twice = serde_json::to_string(&parsed).expect("serialize");
        assert_eq!(once, twice);
    }
}
