//! Simple binary SHA256 Merkle tree for bisection dispute proofs.
//!
//! This is NOT GroveDB - it's a standalone Merkle tree used to commit to
//! intermediate accumulated transformation hashes so that bisection disputes
//! can verify individual block claims cheaply.

use sha2::{Digest, Sha256};

/// Hashes two 32-byte siblings together: SHA256(left || right).
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Builds a binary SHA256 Merkle tree from a list of leaf hashes.
///
/// Returns the Merkle root. If the number of leaves is not a power of two,
/// the tree is padded with zero hashes on the right.
///
/// Panics if `leaves` is empty.
pub fn build_merkle_tree(leaves: &[[u8; 32]]) -> [u8; 32] {
    assert!(
        !leaves.is_empty(),
        "Cannot build Merkle tree from empty leaves"
    );

    // Pad to next power of two
    let n = leaves.len().next_power_of_two();
    let mut layer: Vec<[u8; 32]> = Vec::with_capacity(n);
    layer.extend_from_slice(leaves);
    layer.resize(n, [0u8; 32]);

    while layer.len() > 1 {
        let mut next_layer = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            next_layer.push(hash_pair(&pair[0], &pair[1]));
        }
        layer = next_layer;
    }

    layer[0]
}

/// Generates a Merkle proof (list of sibling hashes) for the leaf at `index`.
///
/// The proof is ordered from leaf level to root level.
pub fn generate_merkle_proof(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    assert!(
        !leaves.is_empty(),
        "Cannot generate proof from empty leaves"
    );
    assert!(index < leaves.len(), "Index out of bounds");

    let n = leaves.len().next_power_of_two();
    let mut padded: Vec<[u8; 32]> = Vec::with_capacity(n);
    padded.extend_from_slice(leaves);
    padded.resize(n, [0u8; 32]);

    let mut proof = Vec::new();
    let mut layer = padded;
    let mut idx = index;

    while layer.len() > 1 {
        // Sibling index
        let sibling = idx ^ 1;
        proof.push(layer[sibling]);

        // Build next layer
        let mut next_layer = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            next_layer.push(hash_pair(&pair[0], &pair[1]));
        }
        layer = next_layer;
        idx /= 2;
    }

    proof
}

/// Verifies a Merkle proof for a given leaf.
///
/// - `root`: expected Merkle root
/// - `leaf`: the leaf hash being proven
/// - `index`: position of the leaf in the original array
/// - `total_leaves`: total number of leaves (before padding)
/// - `proof`: sibling hashes from leaf to root
pub fn verify_merkle_proof(
    root: &[u8; 32],
    leaf: &[u8; 32],
    index: usize,
    total_leaves: usize,
    proof: &[[u8; 32]],
) -> bool {
    if total_leaves == 0 || index >= total_leaves {
        return false;
    }

    let n = total_leaves.next_power_of_two();
    let expected_depth = (n as f64).log2() as usize;

    if proof.len() != expected_depth {
        return false;
    }

    let mut current = *leaf;
    let mut idx = index;

    for sibling in proof {
        if idx % 2 == 0 {
            current = hash_pair(&current, sibling);
        } else {
            current = hash_pair(sibling, &current);
        }
        idx /= 2;
    }

    current == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_leaf() {
        let leaf = [1u8; 32];
        let root = build_merkle_tree(&[leaf]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn test_two_leaves() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let root = build_merkle_tree(&[a, b]);
        assert_eq!(root, hash_pair(&a, &b));
    }

    #[test]
    fn test_proof_roundtrip() {
        let leaves: Vec<[u8; 32]> = (0..8u8).map(|i| [i; 32]).collect();
        let root = build_merkle_tree(&leaves);

        for i in 0..leaves.len() {
            let proof = generate_merkle_proof(&leaves, i);
            assert!(
                verify_merkle_proof(&root, &leaves[i], i, leaves.len(), &proof),
                "Proof failed for index {}",
                i
            );
        }
    }

    #[test]
    fn test_proof_non_power_of_two() {
        let leaves: Vec<[u8; 32]> = (0..5u8).map(|i| [i; 32]).collect();
        let root = build_merkle_tree(&leaves);

        for i in 0..leaves.len() {
            let proof = generate_merkle_proof(&leaves, i);
            assert!(
                verify_merkle_proof(&root, &leaves[i], i, leaves.len(), &proof),
                "Proof failed for index {} with 5 leaves",
                i
            );
        }
    }

    #[test]
    fn test_wrong_leaf_fails() {
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
        let root = build_merkle_tree(&leaves);
        let proof = generate_merkle_proof(&leaves, 0);
        let wrong_leaf = [99u8; 32];
        assert!(!verify_merkle_proof(
            &root,
            &wrong_leaf,
            0,
            leaves.len(),
            &proof
        ));
    }

    #[test]
    fn test_wrong_index_fails() {
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
        let root = build_merkle_tree(&leaves);
        let proof = generate_merkle_proof(&leaves, 0);
        assert!(!verify_merkle_proof(
            &root,
            &leaves[0],
            1,
            leaves.len(),
            &proof
        ));
    }
}
