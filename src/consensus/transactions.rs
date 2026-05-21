use serde::{Deserialize, Serialize};

// Re-export indexing-specific transactions
pub use super::indexing_transactions::*;

/// Enumeration of all transaction types supported by the Willow consensus layer.
///
/// Each variant wraps a specific transaction struct containing the transaction
/// parameters and cryptographic signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Transaction {
    // Token transactions
    /// Transfer WILL tokens between accounts.
    Transfer(TransferTx),

    // Staking transactions
    /// Stake tokens as a validator.
    Stake(StakeTx),
    /// Begin unstaking tokens (subject to unbonding period).
    Unstake(UnstakeTx),

    // Subgrove transactions (with fees)
    /// Register a new subgrove.
    RegisterSubgrove(RegisterSubgroveTx),
    /// Deregister (delete) a subgrove and refund remaining balance.
    DeregisterSubgrove(DeregisterSubgroveTx),
    /// Fund a subgrove's balance.
    FundSubgrove(FundSubgroveTx),
    /// Update read pricing for a subgrove.
    UpdateSubgroveReadPricing(UpdateSubgroveReadPricingTx),
    /// Update the free readers list for a subgrove.
    UpdateSubgroveFreeReaders(UpdateSubgroveFreeReadersTx),

    // Identity transactions
    /// Register a decentralized identifier (DID).
    RegisterDid(RegisterDidTx),

    // Data transactions
    /// Store new data in a subgrove.
    StoreData(StoreDataTx),
    /// Update existing data.
    UpdateData(UpdateDataTx),
    /// Delete data from a subgrove.
    DeleteData(DeleteDataTx),

    // Indexing transactions
    /// Register as a blockchain indexer.
    RegisterIndexer(RegisterIndexerTx),
    /// Submit indexed data for a single block (with optional GKR proof).
    IndexedBlockSubmission(crate::indexer_node::consensus_submitter::IndexedBlockSubmissionTx),
    /// Slash a misbehaving indexer.
    SlashIndexer(SlashIndexerTx),
    /// Collect accumulated query fees.
    CollectQueryFees(CollectQueryFeesTx),

    // Historical indexing transactions
    /// Submit a historical indexing checkpoint (for bootstrapping large datasets).
    HistoricalCheckpoint(HistoricalCheckpointTx),

    // Historical data availability transactions
    /// Submit proof of data availability for a checkpoint (periodic proof).
    AvailabilityProof(AvailabilityProofTx),
    /// Withdraw from serving historical data for a checkpoint.
    WithdrawHistoricalAvailability(WithdrawHistoricalAvailabilityTx),

    // Reputation transactions
    /// Update indexer profile information.
    UpdateIndexerProfile(UpdateIndexerProfileTx),
    /// Create an operator entity (group of indexers).
    CreateOperatorEntity(CreateOperatorEntityTx),
    /// Link an indexer to an operator entity.
    LinkIndexerToEntity(LinkIndexerToEntityTx),
    /// Unlink an indexer from an operator entity.
    UnlinkIndexerFromEntity(UnlinkIndexerFromEntityTx),
    /// Record a funding source for an indexer.
    RecordFundingSource(RecordFundingSourceTx),

    // Dispute resolution transactions (bisection-based)
    /// Open a bisection dispute against a checkpoint.
    OpenBisectionDispute(super::dispute_resolution::OpenBisectionDisputeTx),
    /// Submit a bisection step response.
    BisectionStep(super::dispute_resolution::BisectionStepTx),
    /// Trigger adjudication of a narrowed bisection dispute.
    AdjudicateBisection(super::dispute_resolution::AdjudicateBisectionTx),
    /// Set indexer's availability for dispute resolution work.
    SetDisputeAvailability(super::dispute_resolution::SetDisputeAvailabilityTx),
    /// Open a commitment dispute against a private subgrove provider.
    OpenCommitmentDispute(super::dispute_resolution::OpenCommitmentDisputeTx),
    /// Respond to a commitment dispute with a GroveDB proof.
    RespondCommitmentDispute(super::dispute_resolution::RespondCommitmentDisputeTx),

    // TEE enclave governance transactions
    /// Add an approved TEE enclave image (admin only).
    AddApprovedEnclave(crate::tee::AddApprovedEnclaveTx),
    /// Remove (revoke) an approved TEE enclave image (admin only).
    RemoveApprovedEnclave(crate::tee::RemoveApprovedEnclaveTx),

    // TEE admin governance transactions
    /// Add a new TEE enclave registry admin (admin only).
    AddEnclaveAdmin(crate::tee::AddEnclaveAdminTx),
    /// Remove a TEE enclave registry admin (admin only).
    RemoveEnclaveAdmin(crate::tee::RemoveEnclaveAdminTx),

    // Privacy / private subgrove transactions
    /// Grant a subgrove encryption key to a DID.
    GrantSubgroveKey(GrantSubgroveKeyTx),
    /// Revoke a subgrove encryption key from a DID.
    RevokeSubgroveKey(RevokeSubgroveKeyTx),
    /// Rotate the subgrove encryption key and re-grant to authorized DIDs.
    RotateSubgroveKey(RotateSubgroveKeyTx),
    /// Submit a state root commitment for a private subgrove.
    PrivateSubgroveCommitment(PrivateSubgroveCommitmentTx),

    // ERC-8004 transactions
    /// Link an Ethereum address to a DID (derived from secp256k1 key).
    LinkEthAddress(LinkEthAddressTx),
    /// Record an ERC-8004 agent registration on Ethereum.
    RegisterErc8004Agent(RegisterErc8004AgentTx),

    // File storage transactions
    /// Store a file manifest (metadata + cryptographic commitments) on-chain.
    StoreFileManifest(StoreFileManifestTx),
    /// Delete a file manifest from on-chain storage.
    DeleteFileManifest(DeleteFileManifestTx),
    /// Register a storage node for serving file data.
    RegisterStorageNode(RegisterStorageNodeTx),
    /// Submit a storage availability proof (proves a storage node holds file chunks).
    StorageAvailabilityProof(StorageAvailabilityProofTx),
    /// Unregister a storage node and begin stake unbonding.
    UnregisterStorageNode(UnregisterStorageNodeTx),

    // Content moderation transactions
    /// Add a content hash to the blocklist (admin only).
    BlockContentHash(BlockContentHashTx),
    /// Remove a content hash from the blocklist (admin only).
    UnblockContentHash(UnblockContentHashTx),
    /// Report content for governance review (any DID).
    ReportContent(ReportContentTx),

    // ⚠️ Append-only beyond this point. Bincode encodes enum variant tags by
    // declaration order, and the tx bytes for every block on the live chain
    // are immutable. Inserting a variant earlier in the enum shifts every
    // subsequent variant's tag and silently breaks historical tx decoding
    // (`/tx/decode`, block explorer, anything that round-trips bincode
    // Transactions). Always add new variants at the end.
    /// Update (rotate) an existing DID document. The tx must be signed by a
    /// key already in the current on-chain DID document's authentication set,
    /// so it can swap in fresh public keys for the same DID.
    UpdateDid(UpdateDidTx),
}

/// Transaction to transfer WILL tokens between accounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferTx {
    /// DID of the sender.
    pub from_did: String,
    /// DID of the recipient.
    pub to_did: String,
    /// Amount of WILL tokens to transfer.
    #[serde(with = "crate::serde_helpers::u128_flexible")]
    pub amount: u128,
    /// Optional memo/note for the transfer.
    pub memo: Option<String>,
    /// Cryptographic signature from the sender.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to stake WILL tokens and become a validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeTx {
    /// DID of the validator.
    pub validator_did: String,
    /// Amount of WILL tokens to stake.
    #[serde(with = "crate::serde_helpers::u128_flexible")]
    pub amount: u128,
    /// Public key for CometBFT consensus participation.
    pub consensus_pubkey: String,
    /// Cryptographic signature from the validator.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to begin unstaking tokens (subject to unbonding period).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnstakeTx {
    /// DID of the validator unstaking.
    pub validator_did: String,
    /// Amount of WILL tokens to unstake.
    #[serde(with = "crate::serde_helpers::u128_flexible")]
    pub amount: u128,
    /// Cryptographic signature from the validator.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Upper bounds enforced by the consensus validator on `RegisterSubgroveTx`
/// fields. Chosen to keep on-chain state bounded per subgrove and to limit
/// the work the validator + mempool have to do per transaction. Bumping any
/// of these is a consensus change: every validator has to agree on the new
/// bound at the same height.
pub const MAX_SUBGROVE_ID_LEN: usize = 64;
pub const MAX_SUBGROVE_NAME_LEN: usize = 128;
pub const MAX_SUBGROVE_DESCRIPTION_LEN: usize = 1024;
pub const MAX_SUBGROVE_SCHEMA_LEN: usize = 65_536;
pub const MAX_SUBGROVE_ADMINS: usize = 32;
pub const MAX_WASM_MODULES_PER_SUBGROVE: usize = 8;
pub const MAX_WASM_MODULE_BYTES: usize = 5 * 1024 * 1024;

/// Required prefix for every DID in Willow's identity system. Validators
/// reject any `*_did` field whose value doesn't start here.
pub const WILLOW_DID_PREFIX: &str = "did:willow:";

/// Upper bound on the full DID string (`did:willow:` + identifier body).
pub const MAX_DID_LEN: usize = 128;

/// Upper bound on the key fragment portion of a `public_key_id`
/// (everything after the `#`), e.g. `key-1`.
pub const MAX_KEY_FRAGMENT_LEN: usize = 64;

/// Upper bound on the full `public_key_id` (`{did}#{fragment}`).
pub const MAX_PUBLIC_KEY_ID_LEN: usize = MAX_DID_LEN + 1 + MAX_KEY_FRAGMENT_LEN;

/// Validate a Willow DID string: must start with `did:willow:`, must fit
/// within `MAX_DID_LEN`, and the identifier body must be a non-empty
/// run of ASCII alphanumerics plus `_` / `-`. The label argument is used
/// in the error message so callers can attribute the failure ("owner_did",
/// "admins[3]", etc.).
pub fn validate_did(did: &str, label: &str) -> Result<(), String> {
    if !did.starts_with(WILLOW_DID_PREFIX) {
        return Err(format!("{} must start with {:?}", label, WILLOW_DID_PREFIX));
    }
    if did.len() > MAX_DID_LEN {
        return Err(format!(
            "{} length {} exceeds maximum {}",
            label,
            did.len(),
            MAX_DID_LEN
        ));
    }
    let body = &did[WILLOW_DID_PREFIX.len()..];
    if body.is_empty() {
        return Err(format!("{} identifier body must not be empty", label));
    }
    if !body
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(format!(
            "{} identifier body {:?} must be ASCII alphanumeric, '-', or '_'",
            label, body
        ));
    }
    Ok(())
}

/// Validate a `public_key_id` of the form `{did}#{fragment}`. The DID
/// portion must pass `validate_did`; the fragment must be a non-empty
/// run of ASCII alphanumerics plus `_` / `-`, bounded by
/// `MAX_KEY_FRAGMENT_LEN`. Exactly one `#` is required.
pub fn validate_public_key_id(public_key_id: &str, label: &str) -> Result<(), String> {
    if public_key_id.len() > MAX_PUBLIC_KEY_ID_LEN {
        return Err(format!(
            "{} length {} exceeds maximum {}",
            label,
            public_key_id.len(),
            MAX_PUBLIC_KEY_ID_LEN
        ));
    }
    let (did_part, fragment) = match public_key_id.split_once('#') {
        Some((d, f)) => (d, f),
        None => {
            return Err(format!(
                "{} must contain '#' separating DID from key fragment",
                label
            ))
        }
    };
    if fragment.contains('#') {
        return Err(format!("{} must contain exactly one '#'", label));
    }
    validate_did(did_part, &format!("{} DID portion", label))?;
    if fragment.is_empty() {
        return Err(format!("{} key fragment must not be empty", label));
    }
    if fragment.len() > MAX_KEY_FRAGMENT_LEN {
        return Err(format!(
            "{} key fragment length {} exceeds maximum {}",
            label,
            fragment.len(),
            MAX_KEY_FRAGMENT_LEN
        ));
    }
    if !fragment
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(format!(
            "{} key fragment {:?} must be ASCII alphanumeric, '-', or '_'",
            label, fragment
        ));
    }
    Ok(())
}

#[cfg(test)]
mod did_format_tests {
    use super::*;

    #[test]
    fn accepts_real_world_dids() {
        for did in [
            "did:willow:owner",
            "did:willow:val",
            "did:willow:indexer123",
            "did:willow:test-owner",
            "did:willow:replay-attacker",
            "did:willow:treasury",
        ] {
            validate_did(did, "did").unwrap_or_else(|e| panic!("{did}: {e}"));
        }
    }

    #[test]
    fn rejects_missing_prefix() {
        assert!(validate_did("willow:owner", "did").is_err());
        assert!(validate_did("did:other:owner", "did").is_err());
        assert!(validate_did("", "did").is_err());
    }

    #[test]
    fn rejects_empty_body() {
        assert!(validate_did("did:willow:", "did").is_err());
    }

    #[test]
    fn rejects_body_with_invalid_chars() {
        for did in [
            "did:willow:has space",
            "did:willow:with/slash",
            "did:willow:with.dot",
            "did:willow:café",
            "did:willow:colon:in:body",
        ] {
            assert!(
                validate_did(did, "did").is_err(),
                "{did} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_did_too_long() {
        let did = format!("did:willow:{}", "a".repeat(MAX_DID_LEN));
        assert!(validate_did(&did, "did").is_err());
    }

    #[test]
    fn accepts_did_at_max_length() {
        let body_len = MAX_DID_LEN - WILLOW_DID_PREFIX.len();
        let did = format!("did:willow:{}", "a".repeat(body_len));
        validate_did(&did, "did").unwrap();
    }

    #[test]
    fn accepts_real_world_public_key_ids() {
        for pkid in [
            "did:willow:owner#key-1",
            "did:willow:indexer123#key-1",
            "did:willow:test-owner#key_2",
        ] {
            validate_public_key_id(pkid, "public_key_id").unwrap_or_else(|e| panic!("{pkid}: {e}"));
        }
    }

    #[test]
    fn rejects_public_key_id_missing_hash() {
        assert!(validate_public_key_id("did:willow:owner", "public_key_id").is_err());
    }

    #[test]
    fn rejects_public_key_id_empty_fragment() {
        assert!(validate_public_key_id("did:willow:owner#", "public_key_id").is_err());
    }

    #[test]
    fn rejects_public_key_id_with_multiple_hashes() {
        // Catches malformed ids like "did:willow:owner#key#extra" — must be
        // exactly one '#'.
        assert!(validate_public_key_id("did:willow:owner#key#extra", "public_key_id").is_err());
    }

    #[test]
    fn rejects_public_key_id_with_bad_fragment() {
        assert!(validate_public_key_id("did:willow:owner#has space", "public_key_id").is_err());
        assert!(validate_public_key_id("did:willow:owner#café", "public_key_id").is_err());
    }

    #[test]
    fn rejects_public_key_id_with_bad_did_portion() {
        // DID portion itself malformed.
        assert!(validate_public_key_id("did:other:owner#key-1", "public_key_id").is_err());
        assert!(validate_public_key_id("did:willow:#key-1", "public_key_id").is_err());
    }
}

/// Transaction to register a new subgrove.
///
/// Supports three modes via the `mode` field:
/// - `DataStorage`: For off-chain structured data with verification
/// - `BlockchainIndexing`: For on-chain data indexing with WASM transformations
/// - `FileStorage`: For binary file storage on dedicated storage nodes
///
/// When `mode` is omitted during deserialization, defaults to `DataStorage`
/// with empty values for backward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterSubgroveTx {
    /// Unique identifier for the subgrove.
    pub subgrove_id: String,
    /// Human-readable name.
    pub name: String,
    /// Description of the subgrove.
    #[serde(default)]
    pub description: String,
    /// JSON schema defining the data structure.
    pub schema: String,
    /// DID of the subgrove owner.
    pub owner_did: String,
    /// List of admin DIDs with elevated permissions.
    #[serde(default)]
    pub admins: Vec<String>,
    /// Optional initial funding amount (in smallest token unit) to atomically
    /// fund the subgrove during registration. Accepts a JSON number, a JSON
    /// string (TS SDK), or `null` — see `crate::serde_helpers::option_u128_flexible`.
    #[serde(default, with = "crate::serde_helpers::option_u128_flexible")]
    pub initial_funding: Option<u128>,
    /// Checkpoint verification configuration.
    /// Optionally requires TEE attestation for checkpoint submissions.
    #[serde(default)]
    pub checkpoint_verification: super::indexing_transactions::CheckpointVerificationConfig,
    /// The subgrove mode: DataStorage, BlockchainIndexing, or FileStorage.
    #[serde(default = "super::indexing_transactions::default_data_storage_mode")]
    pub mode: super::indexing_transactions::SubgroveMode,
    /// Optional privacy configuration for private subgroves.
    #[serde(default)]
    pub privacy: Option<crate::storage::PrivacyConfig>,
    /// Optional initial key grant for the owner (when privacy is enabled).
    #[serde(default)]
    pub initial_owner_key_grant: Option<crate::storage::EncryptedKeyGrant>,
    /// ZK-template binding for GkrExecution mode.
    #[serde(default)]
    pub template_config: Option<crate::storage::TemplateSubgroveConfig>,
    /// Blocks held in the chain-tip buffer before submissions fire.
    /// 0 = head-tier only (subsecond, reorg-supersedable).
    #[serde(default)]
    pub confirmation_depth: u32,
    /// Cryptographic signature from the owner.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to fund a subgrove's balance for storage fees.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundSubgroveTx {
    /// Subgrove to fund.
    pub subgrove_id: String,
    /// Amount of WILL tokens to add.
    #[serde(with = "crate::serde_helpers::u128_flexible")]
    pub amount: u128,
    /// DID of the funder.
    pub from_did: String,
    /// Cryptographic signature from the funder.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to deregister (delete) a subgrove.
///
/// Only the subgrove owner can submit this transaction.
/// Remaining subgrove funding balance is refunded to the owner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeregisterSubgroveTx {
    /// Subgrove to deregister.
    pub subgrove_id: String,
    /// DID of the subgrove owner.
    pub owner_did: String,
    /// Cryptographic signature from the owner.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to update read pricing configuration for a subgrove.
///
/// Only the subgrove owner can submit this transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSubgroveReadPricingTx {
    /// Subgrove to update.
    pub subgrove_id: String,
    /// DID of the subgrove owner making the change.
    pub owner_did: String,
    /// New pricing configuration (None to disable paid reads).
    pub read_pricing: Option<crate::token::ReadPricing>,
    /// Cryptographic signature from the owner.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to update the free readers list for a subgrove.
///
/// Only the subgrove owner can submit this transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSubgroveFreeReadersTx {
    /// Subgrove to update.
    pub subgrove_id: String,
    /// DID of the subgrove owner making the change.
    pub owner_did: String,
    /// New complete list of DIDs with free read access.
    pub free_readers: Vec<String>,
    /// Cryptographic signature from the owner.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to register a new decentralized identifier (DID).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDidTx {
    /// The DID document containing identity information.
    pub did_document: DidDocument,
    /// Cryptographic signature proving key ownership.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to update (rotate) an existing DID document.
///
/// The tx must be signed with a key that is currently in the on-chain DID
/// document's authentication set. The replacement document may then list
/// arbitrarily different public keys, enabling key rotation: add the new
/// key, remove the old one, submit. After the tx commits, only keys in the
/// new authentication set can sign further txs as this DID.
///
/// `public_key_id` identifies the key used to sign this tx. It must resolve
/// against the **current** on-chain DID document, not the new one carried
/// in `did_document`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateDidTx {
    /// The new DID document. Its `id` must match the on-chain DID being updated.
    pub did_document: DidDocument,
    /// Signature over a canonical message that includes the new document and nonce.
    pub signature: Vec<u8>,
    /// ID of the **current** (on-chain) public key used to sign this update.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// DID Document structure following W3C DID specification.
///
/// Contains the public keys, authentication methods, and service endpoints
/// associated with a decentralized identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    /// The DID identifier (e.g., "did:willow:abc123").
    pub id: String,
    /// Public keys associated with this DID.
    pub public_keys: Vec<PublicKey>,
    /// Key IDs that can authenticate as this DID.
    pub authentication: Vec<String>,
    /// Service endpoints for discovering services.
    pub service: Vec<ServiceEndpoint>,
    /// Unix timestamp when the DID was created.
    pub created: u64,
    /// Unix timestamp when the DID was last updated.
    pub updated: u64,
    /// Optional cryptographic proof of the document.
    #[serde(default)]
    pub proof: Option<Proof>,
}

/// Cryptographic proof attached to a DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// Proof type (e.g., "Ed25519Signature2018").
    #[serde(rename = "type")]
    pub proof_type: String,
    /// Unix timestamp when the proof was created.
    pub created: u64,
    /// Key ID used to create the proof.
    pub verification_method: String,
    /// Purpose of the proof (e.g., "assertionMethod").
    pub proof_purpose: String,
    /// JSON Web Signature of the proof.
    pub jws: String,
}

/// A public key in a DID document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKey {
    /// Key identifier (e.g., "did:willow:abc123#key-1").
    pub id: String,
    /// Key type (e.g., "Ed25519VerificationKey2018", "EcdsaSecp256k1VerificationKey2019").
    #[serde(rename = "type")]
    pub key_type: String,
    /// DID that controls this key.
    pub controller: String,
    /// Public key encoded in base58 (optional).
    #[serde(default)]
    pub public_key_base58: Option<String>,
    /// Public key encoded in hex (optional).
    #[serde(default)]
    pub public_key_hex: Option<String>,
}

/// A service endpoint in a DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    /// Service identifier.
    pub id: String,
    /// Type of service (e.g., "MessagingService", "ProfileService").
    #[serde(rename = "type")]
    pub service_type: String,
    /// URL or URI of the service.
    pub service_endpoint: String,
}

/// Transaction to store new data in a subgrove.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreDataTx {
    /// Subgrove to store data in.
    pub subgrove_id: String,
    /// Key for the data entry.
    pub key: String,
    /// JSON-encoded data bytes. Bincode round-trips this as a length-prefixed
    /// `Vec<u8>`; server-side parses to `serde_json::Value` on demand.
    pub data: Vec<u8>,
    /// DID of the data owner.
    pub owner_did: String,
    /// Cryptographic signature from the owner.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to update existing data in a subgrove.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateDataTx {
    /// Subgrove containing the data.
    pub subgrove_id: String,
    /// Key of the data entry to update.
    pub key: String,
    /// JSON-encoded data bytes. See `StoreDataTx::data`.
    pub data: Vec<u8>,
    /// DID of the data owner (must match existing entry).
    pub owner_did: String,
    /// Cryptographic signature from the owner.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to delete data from a subgrove.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteDataTx {
    /// Subgrove containing the data.
    pub subgrove_id: String,
    /// Key of the data entry to delete.
    pub key: String,
    /// DID of the data owner (must match existing entry).
    pub owner_did: String,
    /// Cryptographic signature from the owner.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to link an Ethereum address to a Willow DID.
///
/// The ETH address is derived from a secp256k1 key already present in the
/// DID document.  The consensus handler verifies that the referenced key
/// actually produces the claimed address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkEthAddressTx {
    /// The Willow DID to link.
    pub did: String,
    /// The 20-byte Ethereum address to link.
    pub eth_address: [u8; 20],
    /// Must reference a `EcdsaSecp256k1VerificationKey2019` key in the DID doc.
    pub public_key_id: String,
    /// Cryptographic signature from the DID owner.
    pub signature: Vec<u8>,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to grant a subgrove encryption key to a DID.
///
/// Only the subgrove owner or an admin can submit this transaction.
/// The encrypted key grant contains the subgrove's symmetric key
/// wrapped for the grantee's public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantSubgroveKeyTx {
    /// Subgrove to grant access to.
    pub subgrove_id: String,
    /// The encrypted key grant for the grantee.
    pub encrypted_key_grant: crate::storage::EncryptedKeyGrant,
    /// DID of the sender (must be owner or admin).
    pub sender_did: String,
    /// Cryptographic signature from the sender.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to revoke a subgrove encryption key from a DID.
///
/// Only the subgrove owner or an admin can submit this transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeSubgroveKeyTx {
    /// Subgrove to revoke access from.
    pub subgrove_id: String,
    /// DID to revoke access from.
    pub revokee_did: String,
    /// DID of the sender (must be owner or admin).
    pub sender_did: String,
    /// Cryptographic signature from the sender.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to rotate the subgrove encryption key.
///
/// Replaces all existing key grants with new ones for the new epoch.
/// Only the subgrove owner can submit this transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateSubgroveKeyTx {
    /// Subgrove to rotate key for.
    pub subgrove_id: String,
    /// New key epoch (must be current_epoch + 1).
    pub new_epoch: u32,
    /// New encrypted key grants for all authorized DIDs.
    pub new_grants: Vec<crate::storage::EncryptedKeyGrant>,
    /// DID of the sender (must be owner).
    pub sender_did: String,
    /// Cryptographic signature from the sender.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to submit a state root commitment for a private subgrove.
///
/// The provider (indexer) submits the GroveDB root hash of their local data store
/// to consensus at the configured commitment frequency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateSubgroveCommitmentTx {
    /// Subgrove this commitment is for.
    pub subgrove_id: String,
    /// DID of the provider submitting the commitment.
    pub provider_did: String,
    /// GroveDB root hash of the provider's local data store.
    pub state_root: [u8; 32],
    /// Number of documents/entities stored.
    pub item_count: u64,
    /// Total storage size in bytes.
    pub storage_size: u64,
    /// Optional GKR proof for BlockchainIndexing private subgroves.
    /// Proves the latest batch of indexed data was correctly computed from source chain events.
    #[serde(default)]
    pub gkr_proof: Option<crate::consensus::indexing_transactions::GkrProofData>,
    /// Optional TEE attestation of the commitment.
    #[serde(default)]
    pub tee_attestation: Option<crate::tee::TeeAttestation>,
    /// Unix timestamp of this commitment.
    pub timestamp: u64,
    /// Cryptographic signature from the provider.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to store a file manifest on-chain.
///
/// The manifest contains metadata and cryptographic commitments (content hash,
/// chunk Merkle root) for a file stored off-chain on storage nodes.
/// Only writers on a FileStorage subgrove can submit this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreFileManifestTx {
    /// Subgrove to store the file manifest in (must be FileStorage mode).
    pub subgrove_id: String,
    /// Unique key for this file within the subgrove.
    pub file_key: String,
    /// Original filename.
    pub filename: String,
    /// MIME type (e.g., "image/png").
    pub content_type: String,
    /// Total file size in bytes.
    pub total_size: u64,
    /// SHA-256 hash of the complete file.
    pub content_hash: [u8; 32],
    /// Number of chunks.
    pub chunk_count: u32,
    /// Size of each chunk in bytes.
    pub chunk_size: u32,
    /// Merkle root of the chunk hashes.
    pub chunk_merkle_root: [u8; 32],
    /// DID of the file owner.
    pub owner_did: String,
    /// Optional encryption metadata (for private file subgroves).
    #[serde(default)]
    pub encryption: Option<crate::storage::FileEncryption>,
    /// Cryptographic signature from the owner.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to delete a file manifest from on-chain storage.
///
/// Only the file owner can delete a manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteFileManifestTx {
    /// Subgrove containing the file.
    pub subgrove_id: String,
    /// Key of the file to delete.
    pub file_key: String,
    /// DID of the file owner (must match existing manifest).
    pub owner_did: String,
    /// Cryptographic signature from the owner.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to register a storage node.
///
/// Storage nodes store file chunks and serve them to clients.
/// They must stake WILL tokens as economic security.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterStorageNodeTx {
    /// DID of the storage node operator.
    pub node_did: String,
    /// HTTP endpoint for uploads/downloads.
    pub endpoint: String,
    /// Advertised storage capacity in bytes.
    pub capacity_bytes: u64,
    /// Amount of WILL tokens to stake.
    #[serde(with = "crate::serde_helpers::u128_flexible")]
    pub stake_amount: u128,
    /// Cryptographic signature from the operator.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to submit a storage availability proof.
///
/// Storage nodes periodically prove they still hold file chunks
/// by responding to random challenges from validators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageAvailabilityProofTx {
    /// DID of the storage node.
    pub node_did: String,
    /// Subgrove ID.
    pub subgrove_id: String,
    /// File key being proven.
    pub file_key: String,
    /// Index of the challenged chunk.
    pub chunk_index: u32,
    /// SHA-256 hash of the chunk.
    pub chunk_hash: [u8; 32],
    /// Merkle proof from chunk hash to chunk_merkle_root.
    pub merkle_proof: Vec<[u8; 32]>,
    /// Cryptographic signature from the storage node.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to unregister a storage node.
///
/// Returns staked tokens via the unbonding process. Only the node
/// operator can unregister their own node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnregisterStorageNodeTx {
    /// DID of the storage node operator.
    pub node_did: String,
    /// Cryptographic signature from the operator.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to add a content hash to the blocklist (admin only).
///
/// Files with blocklisted content hashes are rejected at manifest submission
/// and purged from storage nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockContentHashTx {
    /// SHA-256 content hash to block.
    pub content_hash: [u8; 32],
    /// Reason for blocking.
    pub reason: String,
    /// DID of the admin submitting the block.
    pub admin_did: String,
    /// Cryptographic signature from the admin.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to remove a content hash from the blocklist (admin only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnblockContentHashTx {
    /// SHA-256 content hash to unblock.
    pub content_hash: [u8; 32],
    /// DID of the admin submitting the unblock.
    pub admin_did: String,
    /// Cryptographic signature from the admin.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to report content for governance review.
///
/// Any DID can submit a report. Reports are stored for governance review
/// and may result in a BlockContentHashTx from an admin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportContentTx {
    /// SHA-256 content hash being reported.
    pub content_hash: [u8; 32],
    /// Reason for the report.
    pub reason: String,
    /// DID of the reporter.
    pub reporter_did: String,
    /// Cryptographic signature from the reporter.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to record an ERC-8004 agent registration on an
/// Ethereum-compatible chain.
///
/// The DID must already have a linked ETH address (via `LinkEthAddressTx`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterErc8004AgentTx {
    /// The Willow DID of the agent.
    pub did: String,
    /// EVM chain ID (e.g. 1 for Ethereum mainnet, 8453 for Base).
    pub chain_id: u64,
    /// Address of the ERC-8004 registry contract.
    pub registry_address: [u8; 20],
    /// Agent ID assigned by the registry.
    pub agent_id: u64,
    /// URI pointing to the agent's registration JSON.
    pub agent_uri: String,
    /// Cryptographic signature from the DID owner.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

#[cfg(test)]
mod bincode_tests {
    //! Consensus deserializes `Transaction` via `bincode::deserialize`. The
    //! `u128_flexible` helper attached to tx amount fields must round-trip
    //! through bincode unchanged — covered for the helper itself in
    //! `serde_helpers::tests` and for the registration flow in
    //! `indexing_transactions::indexer_config::tests`. This module is the
    //! per-file regression guard for the token / staking / file-storage
    //! transactions in this file.
    use super::*;

    #[test]
    fn transfer_tx_bincode_round_trip() {
        let tx = TransferTx {
            from_did: "did:willow:alice".to_string(),
            to_did: "did:willow:bob".to_string(),
            amount: 100_000_000_000_000_000_000_000,
            memo: Some("test".to_string()),
            signature: vec![1, 2, 3],
            public_key_id: "did:willow:alice#key-1".to_string(),
            nonce: 1,
        };
        let bytes = bincode::serialize(&tx).expect("bincode serialize");
        let got: TransferTx = bincode::deserialize(&bytes).expect("bincode deserialize");
        assert_eq!(got.amount, tx.amount);
        assert_eq!(got.from_did, tx.from_did);
        assert_eq!(got.memo, tx.memo);
    }

    #[test]
    fn fund_subgrove_tx_bincode_round_trip() {
        let tx = FundSubgroveTx {
            subgrove_id: "sg-1".to_string(),
            amount: 100_000_000_000_000_000_000_000,
            from_did: "did:willow:alice".to_string(),
            signature: vec![1, 2, 3],
            public_key_id: "did:willow:alice#key-1".to_string(),
            nonce: 1,
        };
        let bytes = bincode::serialize(&tx).expect("bincode serialize");
        let got: FundSubgroveTx = bincode::deserialize(&bytes).expect("bincode deserialize");
        assert_eq!(got.amount, tx.amount);
    }

    #[test]
    fn register_storage_node_tx_bincode_round_trip() {
        let tx = RegisterStorageNodeTx {
            node_did: "did:willow:storage1".to_string(),
            endpoint: "http://storage.example.com".to_string(),
            capacity_bytes: 10_000_000_000,
            stake_amount: 100_000_000_000_000_000_000_000,
            signature: vec![1, 2, 3],
            public_key_id: "did:willow:storage1#key-1".to_string(),
            nonce: 1,
        };
        let bytes = bincode::serialize(&tx).expect("bincode serialize");
        let got: RegisterStorageNodeTx = bincode::deserialize(&bytes).expect("bincode deserialize");
        assert_eq!(got.stake_amount, tx.stake_amount);
    }
}
