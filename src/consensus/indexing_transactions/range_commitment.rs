//! Per-block range commitment (v1) for historical checkpoints.
//!
//! `HistoricalCheckpointTx::block_headers_commitment` binds the FULL set of
//! `(block_number, block_hash, parent_hash)` triples in the checkpoint's
//! range — one domain-separated leaf per block, Merkle-rooted, then wrapped
//! with the range endpoints and count so a root can never be reused for a
//! different range. Consumers must RECOMPUTE this value from verifier-produced
//! records (never trust the submitted one) and fail closed on any mismatch;
//! the legacy endpoints-only value is a pure function of the range and is
//! statelessly detectable via [`legacy_endpoints_commitment`] for rejection.

use crate::consensus::dispute_resolution::build_merkle_tree;
use sha2::{Digest, Sha256};

/// Domain prefix for a v1 per-block leaf.
const RANGE_LEAF_DOMAIN_V1: &[u8] = b"WILLOW_RANGE_LEAF_V1";
/// Domain prefix for the v1 outer commitment wrap.
const RANGE_COMMIT_DOMAIN_V1: &[u8] = b"WILLOW_RANGE_COMMIT_V1";

/// Why a range commitment could not be built. Every variant is fail-closed:
/// the caller must not submit or accept a checkpoint on `Err`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeCommitmentError {
    /// No entries — an empty range commits to nothing.
    Empty,
    /// Block numbers must ascend by exactly 1 (index = n - start).
    NonConsecutive { expected: u64, got: u64 },
}

impl std::fmt::Display for RangeCommitmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RangeCommitmentError::Empty => write!(f, "range commitment over zero blocks"),
            RangeCommitmentError::NonConsecutive { expected, got } => write!(
                f,
                "non-consecutive block numbers: expected {expected}, got {got}"
            ),
        }
    }
}

impl std::error::Error for RangeCommitmentError {}

/// v1 leaf: `SHA256("WILLOW_RANGE_LEAF_V1" || le64(block_number) || block_hash || parent_hash)`.
pub fn range_leaf_v1(block_number: u64, block_hash: &[u8; 32], parent_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RANGE_LEAF_DOMAIN_V1);
    hasher.update(block_number.to_le_bytes());
    hasher.update(block_hash);
    hasher.update(parent_hash);
    hasher.finalize().into()
}

/// Build the v1 commitment over `(block_number, block_hash, parent_hash)`
/// entries, ascending and consecutive (leaf index = block_number - start):
/// `SHA256("WILLOW_RANGE_COMMIT_V1" || le64(start) || le64(end) || le64(count) || merkle_root)`.
/// The outer wrap pins the range and count, so zero-padding in the tree and
/// cross-range root reuse are inert. Fail-closed: `Err` on empty input or any
/// gap/reorder — callers must not fall back to a degenerate commitment.
pub fn build_range_commitment_v1(
    entries: &[(u64, [u8; 32], [u8; 32])],
) -> Result<[u8; 32], RangeCommitmentError> {
    let (start, _, _) = *entries.first().ok_or(RangeCommitmentError::Empty)?;
    let mut leaves = Vec::with_capacity(entries.len());
    for (i, (block_number, block_hash, parent_hash)) in entries.iter().enumerate() {
        let expected = start
            .checked_add(i as u64)
            .ok_or(RangeCommitmentError::NonConsecutive {
                expected: u64::MAX,
                got: *block_number,
            })?;
        if *block_number != expected {
            return Err(RangeCommitmentError::NonConsecutive {
                expected,
                got: *block_number,
            });
        }
        leaves.push(range_leaf_v1(*block_number, block_hash, parent_hash));
    }
    let root = build_merkle_tree(&leaves);
    let end = entries[entries.len() - 1].0;
    let mut hasher = Sha256::new();
    hasher.update(RANGE_COMMIT_DOMAIN_V1);
    hasher.update(start.to_le_bytes());
    hasher.update(end.to_le_bytes());
    hasher.update((entries.len() as u64).to_le_bytes());
    hasher.update(root);
    Ok(hasher.finalize().into())
}

/// The pre-v1 endpoints-only value: `SHA256("BLOCK_HEADERS:" || le64(start) || le64(end))`.
/// Kept ONLY so validators can statelessly detect and REJECT old-scheme
/// checkpoints — it binds no per-block data and must never verify as covered.
pub fn legacy_endpoints_commitment(start: u64, end: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BLOCK_HEADERS:");
    hasher.update(start.to_le_bytes());
    hasher.update(end.to_le_bytes());
    hasher.finalize().into()
}

/// Known-answer vectors (computed independently with python hashlib) pin the
/// exact byte encoding; the tamper tests pin the fail-closed builder rules.
#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    /// KAT: leaf encoding is domain || le64(n) || block_hash || parent_hash.
    #[test]
    fn leaf_v1_known_answer() {
        assert_eq!(
            range_leaf_v1(1, &[0x11; 32], &[0x22; 32]),
            hex32("4f679c22e0c7a8bd70a6565edc3c37d0d0223f3287c46b1b84248c3763a11763")
        );
    }

    /// KAT: single-block range — root == leaf, outer wrap binds (5,5,1).
    #[test]
    fn single_block_commitment_known_answer() {
        assert_eq!(
            range_leaf_v1(5, &[0xAA; 32], &[0xBB; 32]),
            hex32("1c0a5857eccd93cb05dde74c7b6911f501f7536dbd42a3ff4986e3b44b059e02")
        );
        assert_eq!(
            build_range_commitment_v1(&[(5, [0xAA; 32], [0xBB; 32])]).unwrap(),
            hex32("c5a26277f155e3179f6079796b9eb43efa13f724cb0d9185cf281725c112f836")
        );
    }

    /// KAT: 3 blocks (zero-padded to 4 leaves) — padding is pinned by count.
    #[test]
    fn three_block_commitment_known_answer() {
        let entries = [
            (100, [0x01; 32], [0x09; 32]),
            (101, [0x02; 32], [0x01; 32]),
            (102, [0x03; 32], [0x02; 32]),
        ];
        assert_eq!(
            build_range_commitment_v1(&entries).unwrap(),
            hex32("e21b52cc6f0e97dc10d9df0e5fe84348798d585d15c9968bc6cd4e21e91bfa59")
        );
    }

    /// KAT: the legacy value reproduces the old producer bytes exactly, so
    /// validators can statelessly recognize (and reject) old-scheme checkpoints.
    #[test]
    fn legacy_endpoints_commitment_known_answer() {
        assert_eq!(
            legacy_endpoints_commitment(100, 200),
            hex32("5f6fa92795daf2cb7501ab0af8a3a2d73bc57ef8c1bd22e3a89e5ed3c5dbbaa5")
        );
        // The legacy scheme can never collide with a v1 commitment over the
        // same range (different domains).
        let entries = [(100, [0x01; 32], [0x09; 32])];
        assert_ne!(
            legacy_endpoints_commitment(100, 100),
            build_range_commitment_v1(&entries).unwrap()
        );
    }

    /// Fail-closed builder: empty input and any gap/reorder/duplicate are Err.
    #[test]
    fn builder_rejects_empty_and_non_consecutive() {
        assert_eq!(
            build_range_commitment_v1(&[]),
            Err(RangeCommitmentError::Empty)
        );
        let gap = [(100, [1; 32], [9; 32]), (102, [3; 32], [2; 32])];
        assert_eq!(
            build_range_commitment_v1(&gap),
            Err(RangeCommitmentError::NonConsecutive {
                expected: 101,
                got: 102
            })
        );
        let reorder = [(101, [2; 32], [1; 32]), (100, [1; 32], [9; 32])];
        assert!(build_range_commitment_v1(&reorder).is_err());
        let dup = [(100, [1; 32], [9; 32]), (100, [1; 32], [9; 32])];
        assert!(build_range_commitment_v1(&dup).is_err());
    }

    /// Every field of every entry is binding: tampering any one changes the
    /// commitment, and omitting a block cannot be compensated by renumbering
    /// (count + positions shift the root and the outer wrap).
    #[test]
    fn commitment_binds_every_entry_field() {
        let honest = [
            (100, [0x01; 32], [0x09; 32]),
            (101, [0x02; 32], [0x01; 32]),
            (102, [0x03; 32], [0x02; 32]),
        ];
        let base = build_range_commitment_v1(&honest).unwrap();
        // Tamper block_hash of the middle entry.
        let mut t = honest;
        t[1].1 = [0xEE; 32];
        assert_ne!(base, build_range_commitment_v1(&t).unwrap());
        // Tamper parent_hash of the middle entry (a chain break is a
        // DIFFERENT commitment — an honest recompute can't match a forged one).
        let mut t = honest;
        t[1].2 = [0xEE; 32];
        assert_ne!(base, build_range_commitment_v1(&t).unwrap());
        // Swap block_hash/parent_hash within a leaf (fixed-width fields:
        // position is binding).
        let swapped = [(100, [0x09; 32], [0x01; 32])];
        let straight = [(100, [0x01; 32], [0x09; 32])];
        assert_ne!(
            build_range_commitment_v1(&swapped).unwrap(),
            build_range_commitment_v1(&straight).unwrap()
        );
        // Omit the last block: shorter range = different endpoints + count.
        assert_ne!(base, build_range_commitment_v1(&honest[..2]).unwrap());
        // Same triples claimed one block later: leaves move, commitment moves.
        let shifted = [
            (101, [0x01; 32], [0x09; 32]),
            (102, [0x02; 32], [0x01; 32]),
            (103, [0x03; 32], [0x02; 32]),
        ];
        assert_ne!(base, build_range_commitment_v1(&shifted).unwrap());
    }
}
