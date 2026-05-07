use serde::{Deserialize, Serialize};

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
/// SDKs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupportedChain {
    Mainnet,
    Sepolia,
    Holesky,
    Bsc,
    Optimism,
    ArbitrumOne,
    Base,
    Polygon,
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
        }
    }

    /// EIP-155 chain id. Provided so SDKs and indexer services that key off
    /// numeric chain ids can map to/from the canonical string in one place.
    pub const fn evm_chain_id(&self) -> u64 {
        match self {
            SupportedChain::Mainnet => 1,
            SupportedChain::Sepolia => 11_155_111,
            SupportedChain::Holesky => 17_000,
            SupportedChain::Bsc => 56,
            SupportedChain::Optimism => 10,
            SupportedChain::ArbitrumOne => 42_161,
            SupportedChain::Base => 8453,
            SupportedChain::Polygon => 137,
        }
    }

    /// Whether Willow currently has light-client support for this chain.
    /// Today only the three Ethereum networks are wired; other chains can
    /// still be indexed via execution modes that don't require a light
    /// client (e.g., `IndexerExecution`).
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

    /// Map an EIP-155 chain id to a canonical chain. Returns `None` for any
    /// chain id outside the supported set.
    pub fn from_evm_chain_id(id: u64) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.evm_chain_id() == id)
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
            .map(|c| c.evm_chain_id())
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
            assert_eq!(
                SupportedChain::from_evm_chain_id(chain.evm_chain_id()),
                Some(*chain),
            );
        }
    }

    #[test]
    fn unknown_string_rejected() {
        assert_eq!(SupportedChain::from_canonical_id("ethereum"), None);
        assert_eq!(SupportedChain::from_canonical_id("frobnitz"), None);
        assert_eq!(SupportedChain::from_canonical_id(""), None);
        assert_eq!(SupportedChain::from_canonical_id("MAINNET"), None);
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
    }

    #[test]
    fn light_client_subset() {
        assert!(SupportedChain::Mainnet.is_light_client_supported());
        assert!(SupportedChain::Sepolia.is_light_client_supported());
        assert!(SupportedChain::Holesky.is_light_client_supported());
        assert!(!SupportedChain::Bsc.is_light_client_supported());
        assert!(!SupportedChain::Polygon.is_light_client_supported());
    }
}
