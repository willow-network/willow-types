# willow-types

Shared data types for the [Willow](https://github.com/willow-network/willow) protocol — the wire-format definitions every Willow client (SDKs, indexers, third-party tools) needs to construct valid transactions, parse responses, and verify proofs.

## Installation

```toml
[dependencies]
willow-types = "0.1"
```

## What's in here

```text
consensus/              Transaction types (RegisterDid, StoreData, RegisterSubgrove, …)
                        + canonical WillowManifest schema + ExecutionMode + dispute resolution
storage/                Subgrove registration, balances, schema definitions
token/                  Balance, FeeSchedule, ReadPricing, TokenState
tee/                    TEE attestation (AWS Nitro, Intel SGX) types
indexing/               Indexer registration + checkpoint + slash transactions
indexer_node/           Block-update + GKR proof submission types
verifiable_rpc/         Wire format for proof-bearing query responses
state_sync/             CometBFT state-sync message types
reputation/             Indexer reputation + operator entity types
p2p/                    Waku P2P message types
error.rs                Shared error enum
serde_helpers.rs        u128 + flexible deserializers (JSON number-or-string, etc.)
```

The `consensus` and `storage` modules are what SDK callers touch most. The rest are wire types the protocol uses internally — exposed so that anyone building a Willow-compatible tool can encode/decode them.

## Stability

- `0.x` — pre-1.0. Schemas may change before `1.0.0`. Wire-format changes are tagged in the changelog.
- All public structs implement `Serialize` + `Deserialize` (serde JSON + bincode round-trip).
- Variants are added at the tail of any enum that's on-the-wire (per the append-only rule in `consensus::Transaction`).

## License

MIT — see [LICENSE](LICENSE).
