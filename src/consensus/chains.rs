use serde::{Deserialize, Serialize};

/// Family a `SupportedChain` belongs to. Selected at the family level
/// because the indexer pipeline, manifest data-source shape, and proof
/// primitives differ by family — every EVM chain shares 20-byte addresses,
/// RLP encoding, and a log-topic event model; every Solana cluster shares
/// 32-byte Ed25519 pubkeys, instruction discriminators, and slot-based
/// ordering. Downstream code dispatches on this rather than enumerating
/// chain variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChainFamily {
    Evm,
    Solana,
}

/// The canonical set of blockchains that Willow's `BlockchainIndexing`
/// subgroves are allowed to target.
///
/// Identifiers follow the subgraph / The Graph convention (lowercase,
/// kebab-case). Validators reject `RegisterSubgrove` transactions whose
/// manifest references a network outside this set, so any value persisted
/// on-chain is guaranteed to round-trip through this enum.
///
/// Adding a chain is a consensus change: bump this enum, update tests,
/// and coordinate with downstream readers (light client, indexer service,
/// SDKs). Family-specific identifiers (EIP-155 chain id for EVM, none for
/// Solana) are exposed via per-family accessors that return `Option`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupportedChain {
    // EVM family.
    Mainnet,
    Sepolia,
    Holesky,
    Bsc,
    Optimism,
    ArbitrumOne,
    Base,
    Polygon,
    // Solana family. Devnet/Testnet intentionally omitted from v1; add
    // them when there's a real reason (separate indexer config + an
    // explicit manifest fixture exercising the variant).
    SolanaMainnet,
}

impl SupportedChain {
    /// Every canonical chain, in declaration order. Useful for table-driven
    /// tests and for SDK fan-out (`SUPPORTED_CHAINS` constants in each SDK
    /// mirror this list).
    pub const ALL: &'static [SupportedChain] = &[
        SupportedChain::Mainnet,
        SupportedChain::Sepolia,
        SupportedChain::Holesky,
        SupportedChain::Bsc,
        SupportedChain::Optimism,
        SupportedChain::ArbitrumOne,
        SupportedChain::Base,
        SupportedChain::Polygon,
        SupportedChain::SolanaMainnet,
    ];

    /// Canonical kebab-case identifier (matches the serde representation).
    pub const fn canonical_id(&self) -> &'static str {
        match self {
            SupportedChain::Mainnet => "mainnet",
            SupportedChain::Sepolia => "sepolia",
            SupportedChain::Holesky => "holesky",
            SupportedChain::Bsc => "bsc",
            SupportedChain::Optimism => "optimism",
            SupportedChain::ArbitrumOne => "arbitrum-one",
            SupportedChain::Base => "base",
            SupportedChain::Polygon => "polygon",
            SupportedChain::SolanaMainnet => "solana-mainnet",
        }
    }

    /// Which [`ChainFamily`] this chain belongs to. Drives manifest
    /// data-source dispatch, indexer pipeline selection, and proof
    /// primitive choice.
    pub const fn family(&self) -> ChainFamily {
        match self {
            SupportedChain::Mainnet
            | SupportedChain::Sepolia
            | SupportedChain::Holesky
            | SupportedChain::Bsc
            | SupportedChain::Optimism
            | SupportedChain::ArbitrumOne
            | SupportedChain::Base
            | SupportedChain::Polygon => ChainFamily::Evm,
            SupportedChain::SolanaMainnet => ChainFamily::Solana,
        }
    }

    /// EIP-155 chain id, for chains in the [`ChainFamily::Evm`] family.
    /// Returns `None` for non-EVM chains. Provided so SDKs and indexer
    /// services that key off numeric chain ids can map to/from the
    /// canonical string in one place.
    pub const fn evm_chain_id(&self) -> Option<u64> {
        match self {
            SupportedChain::Mainnet => Some(1),
            SupportedChain::Sepolia => Some(11_155_111),
            SupportedChain::Holesky => Some(17_000),
            SupportedChain::Bsc => Some(56),
            SupportedChain::Optimism => Some(10),
            SupportedChain::ArbitrumOne => Some(42_161),
            SupportedChain::Base => Some(8453),
            SupportedChain::Polygon => Some(137),
            SupportedChain::SolanaMainnet => None,
        }
    }

    /// Whether Willow currently has light-client support for this chain.
    /// Today only the three Ethereum networks are wired; other chains can
    /// still be indexed via execution modes that don't require a light
    /// client (e.g., `IndexerExecution`). A Solana light client is a
    /// separate engineering effort and is intentionally `false` here
    /// until that lands.
    pub const fn is_light_client_supported(&self) -> bool {
        matches!(
            self,
            SupportedChain::Mainnet | SupportedChain::Sepolia | SupportedChain::Holesky
        )
    }

    /// Parse a canonical string into the enum. Returns `None` for any
    /// non-canonical value — no aliases (`"ethereum"`, `"binance-smart-chain"`,
    /// etc.) are accepted; callers must use the canonical identifier.
    pub fn from_canonical_id(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.canonical_id() == s)
    }

    /// Map an EIP-155 chain id to a canonical chain. Returns `None` for
    /// any chain id outside the supported EVM set (including non-EVM
    /// chains, which have no EIP-155 id).
    pub fn from_evm_chain_id(id: u64) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|c| c.evm_chain_id() == Some(id))
    }
}

impl std::fmt::Display for SupportedChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.canonical_id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_ids_are_distinct() {
        let mut ids: Vec<&str> = SupportedChain::ALL
            .iter()
            .map(|c| c.canonical_id())
            .collect();
        ids.sort();
        let original_len = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), original_len, "canonical ids must be distinct");
    }

    #[test]
    fn evm_chain_ids_are_distinct() {
        let mut ids: Vec<u64> = SupportedChain::ALL
            .iter()
            .filter_map(|c| c.evm_chain_id())
            .collect();
        ids.sort();
        let original_len = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), original_len, "evm chain ids must be distinct");
    }

    #[test]
    fn canonical_round_trip() {
        for chain in SupportedChain::ALL {
            assert_eq!(
                SupportedChain::from_canonical_id(chain.canonical_id()),
                Some(*chain),
            );
            if let Some(id) = chain.evm_chain_id() {
                assert_eq!(SupportedChain::from_evm_chain_id(id), Some(*chain));
            }
        }
    }

    #[test]
    fn unknown_string_rejected() {
        assert_eq!(SupportedChain::from_canonical_id("ethereum"), None);
        assert_eq!(SupportedChain::from_canonical_id("frobnitz"), None);
        assert_eq!(SupportedChain::from_canonical_id(""), None);
        assert_eq!(SupportedChain::from_canonical_id("MAINNET"), None);
        assert_eq!(SupportedChain::from_canonical_id("solana"), None);
    }

    #[test]
    fn unknown_evm_id_rejected() {
        assert_eq!(SupportedChain::from_evm_chain_id(0), None);
        assert_eq!(SupportedChain::from_evm_chain_id(99_999), None);
    }

    #[test]
    fn serde_uses_kebab_case() {
        let json = serde_json::to_string(&SupportedChain::ArbitrumOne).unwrap();
        assert_eq!(json, "\"arbitrum-one\"");

        let parsed: SupportedChain = serde_json::from_str("\"mainnet\"").unwrap();
        assert_eq!(parsed, SupportedChain::Mainnet);

        let bad: Result<SupportedChain, _> = serde_json::from_str("\"ethereum\"");
        assert!(bad.is_err(), "non-canonical alias must not deserialize");

        let solana_json = serde_json::to_string(&SupportedChain::SolanaMainnet).unwrap();
        assert_eq!(solana_json, "\"solana-mainnet\"");
        let parsed_solana: SupportedChain = serde_json::from_str("\"solana-mainnet\"").unwrap();
        assert_eq!(parsed_solana, SupportedChain::SolanaMainnet);
    }

    #[test]
    fn light_client_subset() {
        assert!(SupportedChain::Mainnet.is_light_client_supported());
        assert!(SupportedChain::Sepolia.is_light_client_supported());
        assert!(SupportedChain::Holesky.is_light_client_supported());
        assert!(!SupportedChain::Bsc.is_light_client_supported());
        assert!(!SupportedChain::Polygon.is_light_client_supported());
        assert!(!SupportedChain::SolanaMainnet.is_light_client_supported());
    }

    #[test]
    fn family_classification() {
        for chain in SupportedChain::ALL {
            let expected = match chain {
                SupportedChain::SolanaMainnet => ChainFamily::Solana,
                _ => ChainFamily::Evm,
            };
            assert_eq!(chain.family(), expected, "{}", chain.canonical_id());
        }
    }

    #[test]
    fn solana_has_no_evm_chain_id() {
        assert_eq!(SupportedChain::SolanaMainnet.evm_chain_id(), None);
    }

    #[test]
    fn chain_family_serde_uses_kebab_case() {
        assert_eq!(serde_json::to_string(&ChainFamily::Evm).unwrap(), "\"evm\"");
        assert_eq!(
            serde_json::to_string(&ChainFamily::Solana).unwrap(),
            "\"solana\""
        );
    }
}
