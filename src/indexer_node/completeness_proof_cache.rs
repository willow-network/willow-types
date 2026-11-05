//! Disk-cache container + path rule for per-block completeness proofs.
//!
//! The indexer's window backfill writes one
//! [`CachedCompletenessProof`] per proof-bearing block as it proves; the
//! API's `/completeness/{subgrove}/{block}` route serves it back for a
//! client to RE-VERIFY against the block's authenticated `receipts_root`. The
//! server never interprets the proof — it stores and serves the exact bytes.
//!
//! The cache key is `(subgrove, filter_hash, block)`. `filter_hash` is part of
//! the key on purpose: a completeness proof is only meaningful bound to the
//! filter it was proved against, so a proof for filter A must never be served
//! for filter B (cross-filter bleed). Both the writer and the reader
//! derive the file path through the SINGLE [`completeness_cache_file_path`]
//! here, so the anti-bleed property is structural, not just tested.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::consensus_submitter::HistoricalHeaderProof;

/// One cached per-block completeness proof plus the minimum header/auth
/// material a client needs to bind it. Bincode-serialized to a single `.bin`
/// file at [`completeness_cache_file_path`].
///
/// The auth fields are primitive (not the consensus `StoredBlockAuth` struct)
/// so the cache stays decoupled from consensus code — the API's
/// reader depends only on `willow-types`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedCompletenessProof {
    /// EL block number this proof authenticates completeness for.
    pub block: u64,
    /// Hash of the `SubgroveFilter` the proof was generated against. Part of
    /// the cache key — a proof for a different filter hashes to a different
    /// file, so it can never be served for the wrong filter.
    pub filter_hash: [u8; 32],
    /// `ChunkedBlockCompletenessProof::to_bytes()` — served verbatim; the
    /// client re-verifies it, never trusting the cache.
    pub completeness_proof: Vec<u8>,
    /// The v2 binius receipts-root proof, when one was produced (N >= 2 crypto
    /// blocks). `None` for smaller blocks / non-crypto subgroves.
    pub receipts_root_proof: Option<Vec<u8>>,
    /// SSZ/EIP-4788 header authentication chain that anchors the block's
    /// `receipts_root`/`transactions_root` to a finalized beacon root. `Some`
    /// for backfilled (historical) blocks.
    pub historical_header_proof: Option<HistoricalHeaderProof>,
    /// EL block hash (linkage + the value a child's `parent_hash` must name).
    pub block_hash: [u8; 32],
    /// EL parent hash.
    pub parent_hash: [u8; 32],
    /// Authenticated receipts-trie root the completeness proof binds to.
    pub receipts_root: [u8; 32],
    /// Authenticated transactions-trie root.
    pub transactions_root: [u8; 32],
}

/// Deterministic cache file path: `{cache_dir}/{subgrove}/{filter_hash_hex}/{block}.bin`.
///
/// The SINGLE path rule shared by the indexer's writer and the API's
/// reader. `filter_hash` is lowercase-hex (64 chars); `block` is decimal. A
/// different `filter_hash` yields a different directory, so a proof can never
/// bleed across filters.
pub fn completeness_cache_file_path(
    cache_dir: &Path,
    subgrove: &str,
    filter_hash: &[u8; 32],
    block: u64,
) -> PathBuf {
    cache_dir
        .join(subgrove)
        .join(hex::encode(filter_hash))
        .join(format!("{block}.bin"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(block: u64, filter_hash: [u8; 32]) -> CachedCompletenessProof {
        CachedCompletenessProof {
            block,
            filter_hash,
            completeness_proof: vec![1, 2, 3, 4],
            receipts_root_proof: Some(vec![9, 9]),
            historical_header_proof: None,
            block_hash: [0xAB; 32],
            parent_hash: [0xCD; 32],
            receipts_root: [0x11; 32],
            transactions_root: [0x22; 32],
        }
    }

    /// The container round-trips through bincode byte-for-byte, so what the
    /// writer stores is exactly what the reader serves.
    #[test]
    fn cache_container_bincode_roundtrips() {
        let att = sample(18_000_000, [0x7F; 32]);
        let bytes = bincode::serialize(&att).unwrap();
        let back: CachedCompletenessProof = bincode::deserialize(&bytes).unwrap();
        // HistoricalHeaderProof isn't Eq, so compare via re-serialization.
        assert_eq!(bytes, bincode::serialize(&back).unwrap());
        assert_eq!(att.block, back.block);
        assert_eq!(att.filter_hash, back.filter_hash);
    }

    /// Cross-filter bleed is structurally impossible: the same block under two
    /// different filter hashes maps to two DIFFERENT files, and the same
    /// `(subgrove, filter, block)` maps to a STABLE file. If these ever
    /// coincided, a proof for filter A could be served for filter B.
    #[test]
    fn path_is_filter_and_block_exact() {
        let dir = Path::new("/cache");
        let a = completeness_cache_file_path(dir, "sg1", &[0x01; 32], 100);
        let b = completeness_cache_file_path(dir, "sg1", &[0x02; 32], 100);
        assert_ne!(a, b, "different filters must not share a cache file");

        let c = completeness_cache_file_path(dir, "sg1", &[0x01; 32], 101);
        assert_ne!(a, c, "different blocks must not share a cache file");

        let a_again = completeness_cache_file_path(dir, "sg1", &[0x01; 32], 100);
        assert_eq!(a, a_again, "the path rule must be deterministic");

        // Sanity on the exact layout the reader globs.
        assert!(a.ends_with(format!("sg1/{}/100.bin", hex::encode([0x01u8; 32]))));
    }

    /// A different subgrove never shares a file either.
    #[test]
    fn path_is_subgrove_exact() {
        let dir = Path::new("/cache");
        let a = completeness_cache_file_path(dir, "sg1", &[0x01; 32], 100);
        let b = completeness_cache_file_path(dir, "sg2", &[0x01; 32], 100);
        assert_ne!(a, b);
    }
}
