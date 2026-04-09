//! Canonical block output hash for dispute resolution.
//!
//! This module defines the single canonical hash function that all parties
//! in the system must use to compute the transformation output for a block.
//! The hash is deterministic: given the same block number and the same set
//! of transformed entities, every party produces the same hash.
//!
//! Used by:
//! - The indexer pipeline (during normal indexing)
//! - The dispute service (during checkpoint verification)
//! - The consensus layer (during adjudication)

use sha2::{Digest, Sha256};

/// Domain separator for the canonical block output hash.
const DOMAIN_SEPARATOR: &[u8] = b"WILLOW_BLOCK_TRANSFORM_V1:";

/// Marker for blocks that produce no matching entities.
const EMPTY_MARKER: &[u8] = b"EMPTY";

/// Computes the canonical hash of a block's transformation output.
///
/// The hash covers the block number and all transformed entities in
/// deterministic sorted order. This is the building block for the
/// accumulated hash chain used in bisection disputes.
///
/// # Arguments
///
/// * `block_number` - The Ethereum block number
/// * `entities` - Mutable slice of `(entity_type, entity_id, entity_json)` tuples.
///   Will be sorted in place by `(entity_type, entity_id)` for determinism.
///
/// # Determinism
///
/// The function sorts entities by `(entity_type, entity_id)` before hashing.
/// Each field is length-prefixed (4 bytes LE) to prevent ambiguity.
/// JSON serialization uses `serde_json::to_vec` which produces deterministic
/// output for the same `serde_json::Value`.
pub fn compute_canonical_block_output_hash(
    block_number: u64,
    entities: &mut [(String, String, serde_json::Value)],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SEPARATOR);
    hasher.update(block_number.to_le_bytes());

    if entities.is_empty() {
        hasher.update(EMPTY_MARKER);
        return hasher.finalize().into();
    }

    // Sort by (entity_type, entity_id) for deterministic ordering
    entities.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));

    for (entity_type, entity_id, entity_json) in entities.iter() {
        // Length-prefix each field to prevent concatenation ambiguity
        let type_bytes = entity_type.as_bytes();
        hasher.update((type_bytes.len() as u32).to_le_bytes());
        hasher.update(type_bytes);

        let id_bytes = entity_id.as_bytes();
        hasher.update((id_bytes.len() as u32).to_le_bytes());
        hasher.update(id_bytes);

        // Strip metadata fields before hashing — these are context from the
        // block/transaction and any honest party can reconstruct them. Only
        // the event-derived fields (the transformation output) matter for
        // dispute resolution.
        let mut clean_json = entity_json.clone();
        if let Some(obj) = clean_json.as_object_mut() {
            obj.remove("id");
            obj.remove("blockNumber");
            obj.remove("timestamp");
            obj.remove("transactionHash");
            obj.remove("logIndex");
        }
        let json_bytes = serde_json::to_vec(&clean_json).unwrap_or_default();
        hasher.update((json_bytes.len() as u32).to_le_bytes());
        hasher.update(&json_bytes);
    }

    hasher.finalize().into()
}

/// Computes the next accumulated hash in the chain.
///
/// H_B = SHA256(H_{B-1} || block_output_hash)
///
/// The accumulated hash chain is:
/// - H_0 = [0u8; 32] (the initial state before any block)
/// - H_B = SHA256(H_{B-1} || canonical_block_output_hash(block_B))
///
/// The chain of H values is committed via a Merkle tree, and individual
/// values can be proven with Merkle proofs during bisection disputes.
pub fn compute_accumulated_hash(previous: &[u8; 32], block_output_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(previous);
    hasher.update(block_output_hash);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_block_produces_deterministic_hash() {
        let h1 = compute_canonical_block_output_hash(100, &mut []);
        let h2 = compute_canonical_block_output_hash(100, &mut []);
        assert_eq!(h1, h2);

        // Different block number produces different hash
        let h3 = compute_canonical_block_output_hash(101, &mut []);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_entity_order_does_not_matter() {
        let mut entities1 = vec![
            (
                "Swap".to_string(),
                "id-2".to_string(),
                serde_json::json!({"amount": "100"}),
            ),
            (
                "Swap".to_string(),
                "id-1".to_string(),
                serde_json::json!({"amount": "200"}),
            ),
        ];
        let mut entities2 = vec![
            (
                "Swap".to_string(),
                "id-1".to_string(),
                serde_json::json!({"amount": "200"}),
            ),
            (
                "Swap".to_string(),
                "id-2".to_string(),
                serde_json::json!({"amount": "100"}),
            ),
        ];

        let h1 = compute_canonical_block_output_hash(100, &mut entities1);
        let h2 = compute_canonical_block_output_hash(100, &mut entities2);
        assert_eq!(h1, h2, "Order should not matter — entities are sorted");
    }

    #[test]
    fn test_different_entities_produce_different_hash() {
        let mut honest = vec![(
            "Swap".to_string(),
            "id-1".to_string(),
            serde_json::json!({"amount": "100"}),
        )];
        let mut malicious = vec![(
            "Swap".to_string(),
            "id-1".to_string(),
            serde_json::json!({"amount": "200"}),
        )];

        let h1 = compute_canonical_block_output_hash(100, &mut honest);
        let h2 = compute_canonical_block_output_hash(100, &mut malicious);
        assert_ne!(h1, h2, "Different entity data must produce different hash");
    }

    #[test]
    fn test_accumulated_hash_chain() {
        let h0 = [0u8; 32];
        let block1_hash = compute_canonical_block_output_hash(1, &mut []);
        let h1 = compute_accumulated_hash(&h0, &block1_hash);
        assert_ne!(h1, h0);

        let block2_hash = compute_canonical_block_output_hash(2, &mut []);
        let h2 = compute_accumulated_hash(&h1, &block2_hash);
        assert_ne!(h2, h1);

        // Same inputs produce same chain
        let h1_again = compute_accumulated_hash(&h0, &block1_hash);
        assert_eq!(h1, h1_again);
    }

    #[test]
    fn test_skipped_entity_changes_hash() {
        // Honest: 2 entities
        let mut honest = vec![
            (
                "Swap".to_string(),
                "id-1".to_string(),
                serde_json::json!({"amount": "100"}),
            ),
            (
                "Swap".to_string(),
                "id-2".to_string(),
                serde_json::json!({"amount": "200"}),
            ),
        ];
        // Malicious: skipped entity id-2
        let mut malicious = vec![(
            "Swap".to_string(),
            "id-1".to_string(),
            serde_json::json!({"amount": "100"}),
        )];

        let h1 = compute_canonical_block_output_hash(100, &mut honest);
        let h2 = compute_canonical_block_output_hash(100, &mut malicious);
        assert_ne!(h1, h2, "Skipping an entity must produce different hash");
    }
}
