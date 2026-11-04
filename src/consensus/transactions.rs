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

    // ⚠️ Append-only beyond this point. Bincode encodes variant tags by
    // declaration order; inserting earlier shifts every subsequent tag and
    // breaks historical tx decoding. Always add new variants at the end.
    /// Rotate the keys on an existing DID document. Signed by a key already
    /// in the current on-chain DID document's authentication set.
    UpdateDid(UpdateDidTx),
    /// Indexer claims a subgrove — adds the indexer DID to the subgrove's
    /// `active_indexers` list immediately, before any checkpoint or data
    /// submission.
    ClaimSubgroveIndexing(ClaimSubgroveIndexingTx),

    /// Submit an MCP-style receipt-batch anchor. Consensus enforces a strict
    /// per-DID anchor chain: exactly one genesis anchor per DID, every later
    /// anchor must extend the previous one by sequence and hash.
    SubmitAnchor(SubmitAnchorTx),

    /// Bootstrap the in-consensus Ethereum sync-committee light client from a
    /// trusted weak-subjectivity checkpoint. Admin-gated, one-time per network;
    /// see `crates/consensus/src/willow_cometbft/light_client_transactions.rs`.
    SubmitLightClientBootstrap(SubmitLightClientBootstrapTx),

    /// Advance the in-consensus light client's beacon anchors from a
    /// sync-committee-signed beacon update. Permissionless + self-authenticating
    /// (validity = the BLS signature + branch proofs verify against the tracked
    /// committee). See `light_client_transactions.rs`.
    SubmitBeaconUpdate(SubmitBeaconUpdateTx),

    /// Promote an already-stored block update to a higher authentication status
    /// by re-verifying its carried historical proof against the now-advanced
    /// in-consensus anchor. Permissionless + self-authenticating (validity = the
    /// proof chains the block's *stored* roots into a tracked anchor's beacon
    /// state). See `indexed_data_handler::promotion`.
    PromoteBlock(PromoteBlockTx),

    /// Complete a deferred-completeness block: re-run the anti-censorship
    /// completeness check on the already-stored submission against the
    /// now-advanced in-consensus anchor, flipping it to `Verified`.
    /// Permissionless + self-authenticating (validity = the carried proof + the
    /// stored submission verify against a tracked anchor). See
    /// `indexed_data_handler::completeness::complete_block`.
    CompleteBlock(CompleteBlockTx),

    /// Reclaim a completeness bond stranded on a reorg-orphaned block: release
    /// the indexer's locked bond once a carried proof shows the canonical block
    /// at the bonded block's number has a different hash than the stored
    /// submission. Permissionless + self-authenticating (validity = the proof
    /// chains the canonical block into the in-consensus finalized anchor and its
    /// hash differs from the stored one). See
    /// `indexed_data_handler::bond::reclaim_completeness_bond`.
    ReclaimCompletenessBond(ReclaimCompletenessBondTx),

    /// Replace an already-registered subgrove's manifest/config in place:
    /// recompute its `source_start_block` + contract addresses from the new
    /// manifest and bump its `deployment_epoch` so indexers wipe their local DB
    /// and re-index from the new start block. Owner-gated — the signer must equal
    /// the stored owner, over the `ReplaceSubgrove` message, whose `Config` line is the
    /// SHA-256 of this transaction's bincode with an empty signature.
    /// Reuses the [`RegisterSubgroveTx`] payload: only
    /// `subgrove_id`, `owner_did`, `description`, `schema`, `mode`,
    /// `template_config`, `confirmation_depth`, and the auth fields are
    /// consulted; `name`, `admins`, `initial_funding`, and `privacy` are ignored
    /// (a replace never re-funds or transfers ownership).
    ReplaceSubgrove(RegisterSubgroveTx),

    /// Indexer announces it is no longer indexing a subgrove — removes the
    /// indexer DID from the subgrove's `active_indexers` list (the inverse of
    /// `ClaimSubgroveIndexing`). Idempotent: releasing a subgrove the indexer
    /// isn't recorded on is a no-op.
    ReleaseSubgrove(ReleaseSubgroveTx),

    /// Toggle a subgrove's `cryptographic_completeness` opt-in. Owner-gated —
    /// signed over `UpdateSubgroveCryptographicCompleteness:{id}:{owner}:{enabled}:{nonce}`
    /// and the signer must equal the stored owner. When enabled, the indexer
    /// produces a receipts-trie completeness proof per block submission and
    /// validators verify it against the trusted `receipts_root`.
    UpdateSubgroveCryptographicCompleteness(UpdateSubgroveCryptographicCompletenessTx),

    /// Request a coverage attestation over a block range. Consensus recomputes
    /// `verify_checkpoint_range_coverage` INLINE (cap-enforced) from its OWN
    /// verifier records and persists a [`CoverageAttestation`] ONLY if the range
    /// is `Covered`; any `NotCovered` verdict — absence OR provable lie —
    /// rejects the tx and persists nothing. Permissionless: anyone may submit
    /// (signed + nonce'd purely for spam / replay control). An attestation
    /// existing in state therefore means consensus itself recomputed `Covered`.
    CoverageAttestation(CoverageAttestationTx),

    /// Rotate a validator's CometBFT consensus key. Signed by the validator's
    /// DID key over `RotateConsensusKey\nValidator: {did}\nNewPubkey: {b64}\nNonce: {n}`.
    /// On success the app updates its stored `ValidatorInfo.consensus_pubkey`
    /// and returns exactly two CometBFT validator updates from FinalizeBlock —
    /// the new key at the validator's current power and the old key at power 0
    /// — which CometBFT applies at height H+2. Both derive from the committed
    /// tx, committed state and the block's own last commit, never from config.
    RotateConsensusKey(RotateConsensusKeyTx),
}

impl Transaction {
    /// Stable kebab-style discriminator for metrics / logging.
    /// Add a new arm here whenever a variant is added — the match is
    /// exhaustive so the compiler enforces this.
    pub fn type_name(&self) -> &'static str {
        match self {
            Transaction::Transfer(_) => "transfer",
            Transaction::Stake(_) => "stake",
            Transaction::Unstake(_) => "unstake",
            Transaction::RegisterSubgrove(_) => "register_subgrove",
            Transaction::DeregisterSubgrove(_) => "deregister_subgrove",
            Transaction::FundSubgrove(_) => "fund_subgrove",
            Transaction::UpdateSubgroveReadPricing(_) => "update_read_pricing",
            Transaction::UpdateSubgroveFreeReaders(_) => "update_free_readers",
            Transaction::RegisterDid(_) => "register_did",
            Transaction::StoreData(_) => "store_data",
            Transaction::UpdateData(_) => "update_data",
            Transaction::DeleteData(_) => "delete_data",
            Transaction::RegisterIndexer(_) => "register_indexer",
            Transaction::IndexedBlockSubmission(_) => "indexed_block_submission",
            Transaction::SlashIndexer(_) => "slash_indexer",
            Transaction::CollectQueryFees(_) => "collect_query_fees",
            Transaction::HistoricalCheckpoint(_) => "historical_checkpoint",
            Transaction::AvailabilityProof(_) => "availability_proof",
            Transaction::WithdrawHistoricalAvailability(_) => "withdraw_historical_availability",
            Transaction::UpdateIndexerProfile(_) => "update_indexer_profile",
            Transaction::CreateOperatorEntity(_) => "create_operator_entity",
            Transaction::LinkIndexerToEntity(_) => "link_indexer_to_entity",
            Transaction::UnlinkIndexerFromEntity(_) => "unlink_indexer_from_entity",
            Transaction::RecordFundingSource(_) => "record_funding_source",
            Transaction::OpenBisectionDispute(_) => "open_bisection_dispute",
            Transaction::BisectionStep(_) => "bisection_step",
            Transaction::AdjudicateBisection(_) => "adjudicate_bisection",
            Transaction::SetDisputeAvailability(_) => "set_dispute_availability",
            Transaction::OpenCommitmentDispute(_) => "open_commitment_dispute",
            Transaction::RespondCommitmentDispute(_) => "respond_commitment_dispute",
            Transaction::AddApprovedEnclave(_) => "add_approved_enclave",
            Transaction::RemoveApprovedEnclave(_) => "remove_approved_enclave",
            Transaction::AddEnclaveAdmin(_) => "add_enclave_admin",
            Transaction::RemoveEnclaveAdmin(_) => "remove_enclave_admin",
            Transaction::GrantSubgroveKey(_) => "grant_subgrove_key",
            Transaction::RevokeSubgroveKey(_) => "revoke_subgrove_key",
            Transaction::RotateSubgroveKey(_) => "rotate_subgrove_key",
            Transaction::PrivateSubgroveCommitment(_) => "private_subgrove_commitment",
            Transaction::LinkEthAddress(_) => "link_eth_address",
            Transaction::RegisterErc8004Agent(_) => "register_erc8004_agent",
            Transaction::StoreFileManifest(_) => "store_file_manifest",
            Transaction::DeleteFileManifest(_) => "delete_file_manifest",
            Transaction::RegisterStorageNode(_) => "register_storage_node",
            Transaction::StorageAvailabilityProof(_) => "storage_availability_proof",
            Transaction::UnregisterStorageNode(_) => "unregister_storage_node",
            Transaction::BlockContentHash(_) => "block_content_hash",
            Transaction::UnblockContentHash(_) => "unblock_content_hash",
            Transaction::ReportContent(_) => "report_content",
            Transaction::UpdateDid(_) => "update_did",
            Transaction::ClaimSubgroveIndexing(_) => "claim_subgrove_indexing",
            Transaction::SubmitAnchor(_) => "submit_anchor",
            Transaction::SubmitLightClientBootstrap(_) => "submit_light_client_bootstrap",
            Transaction::SubmitBeaconUpdate(_) => "submit_beacon_update",
            Transaction::PromoteBlock(_) => "promote_block",
            Transaction::CompleteBlock(_) => "complete_block",
            Transaction::ReclaimCompletenessBond(_) => "reclaim_completeness_bond",
            Transaction::ReplaceSubgrove(_) => "replace_subgrove",
            Transaction::ReleaseSubgrove(_) => "release_subgrove",
            Transaction::UpdateSubgroveCryptographicCompleteness(_) => {
                "update_cryptographic_completeness"
            }
            Transaction::CoverageAttestation(_) => "coverage_attestation",
            Transaction::RotateConsensusKey(_) => "rotate_consensus_key",
        }
    }
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

/// Transaction to rotate a validator's CometBFT consensus public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateConsensusKeyTx {
    /// DID of the validator whose consensus key is being rotated.
    pub validator_did: String,
    /// New Ed25519 consensus public key, base64 (CometBFT `pub_key.value`).
    pub new_consensus_pubkey: String,
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
    /// Optional ZK-template binding (legacy; carried through for wire compatibility).
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
    /// Opt-in to browser-trustless receipts-trie completeness proofs.
    /// Appended last: txs are bincode-encoded (positional), so new fields go
    /// at the end — `#[serde(default)]` only protects JSON decoding.
    #[serde(default)]
    pub cryptographic_completeness: bool,
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

/// Transaction to toggle a subgrove's `cryptographic_completeness` opt-in.
///
/// Only the subgrove owner can submit this transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSubgroveCryptographicCompletenessTx {
    /// Subgrove to update.
    pub subgrove_id: String,
    /// DID of the subgrove owner making the change.
    pub owner_did: String,
    /// New value of the cryptographic-completeness opt-in flag.
    pub cryptographic_completeness: bool,
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

/// Transaction submitted by an indexer when it locally starts indexing a
/// subgrove. Bumps the on-chain `active_indexers` list for that subgrove
/// immediately, before any checkpoint or chain-tip submission lands —
/// solves the "dashboard shows Not Started but indexer is mid-backfill"
/// gap.
///
/// Idempotent: re-submitting for an already-claimed (subgrove, indexer)
/// pair is a no-op.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimSubgroveIndexingTx {
    /// Subgrove the indexer is claiming.
    pub subgrove_id: String,
    /// Indexer DID that's taking responsibility for indexing.
    pub indexer_did: String,
    /// Signature over a canonical message that includes subgrove_id, indexer_did, and nonce.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction submitted by an indexer when it stops indexing a subgrove —
/// the inverse of [`ClaimSubgroveIndexingTx`]. Removes the indexer DID from
/// the subgrove's `active_indexers` list so the dashboard's indexer count
/// reflects active coverage rather than every claim ever made.
///
/// Idempotent: releasing a subgrove the indexer isn't recorded on is a no-op.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseSubgroveTx {
    /// Subgrove the indexer is releasing.
    pub subgrove_id: String,
    /// Indexer DID relinquishing the subgrove.
    pub indexer_did: String,
    /// Signature over a canonical message that includes subgrove_id, indexer_did, and nonce.
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

/// Upper bounds enforced by the consensus validator on `SubmitAnchorTx`
/// fields. Keep per-anchor state bounded and validator work per tx capped.
pub const MAX_ANCHOR_ID_LEN: usize = 128;
pub const MAX_ANCHOR_RECEIPT_HASHES: usize = 1024;
pub const MAX_ANCHOR_HASH_HEX_LEN: usize = 128; // sha256 hex = 64; allow headroom
pub const MAX_ANCHOR_TIMESTAMP_LEN: usize = 64;

/// Sentinel `previous_anchor_hash` value for the genesis anchor of a fresh
/// receipt log. Matches the in-process sentinel used by willow-mcp's
/// receipt log.
pub const ANCHOR_GENESIS_SENTINEL: &str = "genesis";

/// Submit a receipt-batch anchor with chain-enforced per-DID monotonicity.
///
/// The chain validator enforces:
/// * Exactly one anchor with `is_genesis: true` per DID — second attempts
///   are rejected.
/// * Every non-genesis anchor's `sequence_range[0]` must equal the previous
///   anchor's `sequence_range[1] + 1` (no gaps, no overlaps).
/// * Every non-genesis anchor's `previous_anchor_hash` must equal the
///   previous anchor's `anchor_hash` (anchor chain integrity).
/// * The submitted `anchor_hash` must equal the canonical SHA-256 of the
///   anchor body (recomputed by the validator).
/// * The signature must verify against `public_key_id` for the submitting
///   `did`.
///
/// State touched: `system/anchor_heads/{did}` (head pointer per DID) and
/// `system/anchors/{did}/{anchor_id}` (persisted anchor body for verifiers
/// to walk the chain end-to-end).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitAnchorTx {
    /// DID of the anchor submitter (typically the MCP server's DID).
    pub did: String,
    /// Stable anchor identifier. Must be unique per DID.
    pub anchor_id: String,
    /// Inclusive [from, to] sequence range covered by this anchor.
    pub sequence_range: [u64; 2],
    /// Merkle root over the ordered `receipt_hashes`.
    pub merkle_root: String,
    /// Number of receipts covered (must equal `to - from + 1`).
    pub count: u64,
    /// Receipt hashes in the order they were anchored. The validator
    /// recomputes the Merkle root from this list.
    pub receipt_hashes: Vec<String>,
    /// ISO-8601 timestamp set by the submitter (advisory; chain time is
    /// authoritative via block height).
    pub timestamp: String,
    /// Hash of the previous anchor for this DID, or `ANCHOR_GENESIS_SENTINEL`
    /// for the first anchor of a fresh log.
    pub previous_anchor_hash: String,
    /// SHA-256 of the canonicalized anchor body. Validator recomputes and
    /// rejects on mismatch.
    pub anchor_hash: String,
    /// True iff this is the first anchor of a fresh log for `did`.
    pub is_genesis: bool,
    /// Cryptographic signature over `anchor_hash`.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Seeds the in-consensus Ethereum sync-committee light client (Phase 2B) from a
/// trusted beacon checkpoint. Admin-gated: the submitter must be an approved
/// governance admin (the `EnclaveRegistry` admin set). The carried committee is
/// authenticated against `checkpoint_state_root` via its SSZ Merkle branch
/// before being stored; the checkpoint root itself is the weak-subjectivity
/// trust input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitLightClientBootstrapTx {
    /// DID of the submitting governance admin.
    pub admin_did: String,
    /// The 512 current sync-committee pubkeys, flat (512 * 48 bytes).
    pub committee_pubkeys: Vec<u8>,
    /// The committee's 48-byte BLS aggregate pubkey.
    pub aggregate_pubkey: Vec<u8>,
    /// `current_sync_committee_branch`: one 32-byte sibling per state-tree level.
    pub committee_branch: Vec<[u8; 32]>,
    /// Beacon state root of the trusted checkpoint (the trust anchor).
    pub checkpoint_state_root: [u8; 32],
    /// Beacon slot of the checkpoint (selects the fork → committee gindex, and
    /// the sync-committee period).
    pub checkpoint_slot: u64,
    /// Eth2 genesis validators root (fixes the sync-committee signing domain).
    pub genesis_validators_root: [u8; 32],
    /// Signature over the canonical signing message by `admin_did`.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

impl SubmitLightClientBootstrapTx {
    /// Canonical message the `admin_did` signs. Binds the checkpoint root, its
    /// fork-selecting slot, the genesis validators root, and the nonce. CheckTx
    /// and the consensus handler MUST compute this identically.
    pub fn signing_message(&self) -> String {
        format!(
            "WILLOW_LIGHT_CLIENT_BOOTSTRAP_V1:{}:{}:{}:{}:{}",
            self.admin_did,
            hex::encode(self.checkpoint_state_root),
            self.checkpoint_slot,
            hex::encode(self.genesis_validators_root),
            self.nonce
        )
    }
}

/// A finalized `BeaconBlockHeader` + its `finality_branch`, carried by a
/// finality update so the validator can advance its finalized anchor. The
/// branch proves this header is `finalized_checkpoint.root` in the attested
/// beacon state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizedHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub body_root: [u8; 32],
    /// `finality_branch`: one 32-byte sibling per state-tree level.
    pub finality_branch: Vec<[u8; 32]>,
}

/// Next sync committee + its SSZ branch, carried by a periodic LightClientUpdate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextSyncCommittee {
    /// 512 BLS pubkeys, flat (512 × 48 bytes).
    pub pubkeys: Vec<u8>,
    pub aggregate_pubkey: Vec<u8>,
    /// `next_sync_committee_branch`: one 32-byte sibling per state-tree level.
    pub branch: Vec<[u8; 32]>,
}

/// Advances the in-consensus light client's beacon anchors from a
/// sync-committee-signed beacon update (`optimistic_update` / `finality_update`).
/// Permissionless and self-authenticating: validity is the sync-committee BLS
/// signature over the attested header verifying against the tracked committee
/// (+ the finality branch when present). The validator then advances the head
/// (and, with finality, finalized) anchor monotonically. No signer / nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitBeaconUpdateTx {
    // Attested `BeaconBlockHeader` (the value the sync committee signed).
    pub attested_slot: u64,
    pub attested_proposer_index: u64,
    pub attested_parent_root: [u8; 32],
    pub attested_state_root: [u8; 32],
    pub attested_body_root: [u8; 32],
    // Sync aggregate: `Bitvector[512]` participation (64 bytes) + 96-byte sig.
    pub sync_committee_bits: Vec<u8>,
    pub sync_committee_signature: Vec<u8>,
    /// Slot the aggregate was produced in (selects the signing fork version).
    pub signature_slot: u64,
    /// Present for finality updates: advances the finalized anchor.
    pub finalized: Option<FinalizedHeader>,
    /// Periodic LightClientUpdate: next period's committee + branch, for rotation.
    #[serde(default)]
    pub next_sync_committee: Option<NextSyncCommittee>,
}

/// Promotes an already-stored block update to a higher [`BlockAuthStatus`] by
/// re-verifying a `HistoricalHeaderProof` against the now-advanced in-consensus
/// anchor. Permissionless + self-authenticating: validity is the proof chaining
/// the block's *stored* receipts/transactions roots into a tracked anchor's
/// beacon state, so a promoter cannot substitute different roots. No signer /
/// nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromoteBlockTx {
    pub subgrove_id: String,
    pub block_number: u64,
    pub historical_header_proof: crate::indexer_node::consensus_submitter::HistoricalHeaderProof,
}

/// Completes a deferred-completeness block: the handler reads the stored pending
/// submission, re-runs the completeness anti-censorship check against the
/// now-advanced in-consensus anchor via the carried proof, and flips the block
/// to `Verified`. Permissionless + self-authenticating (proof only — the
/// submission data is already in state). No signer / nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteBlockTx {
    pub subgrove_id: String,
    pub block_number: u64,
    pub historical_header_proof: crate::indexer_node::consensus_submitter::HistoricalHeaderProof,
    /// DID paid the catcher's share if this settlement proves an omission and
    /// slashes the indexer's completeness bond (the remainder goes to treasury).
    /// Self-declared and unsigned — the submitter can only name where their own
    /// reward goes, never forge the slash itself (the omission is verified
    /// deterministically against the finalized anchor). Empty = no payee, so the
    /// whole slash goes to treasury. Irrelevant on the honest (release) path.
    #[serde(default)]
    pub beneficiary: String,
}

/// Reclaims a completeness bond stranded on a reorg-orphaned block: releases the
/// indexer's locked bond once the carried proof shows the *canonical*
/// (finalized-anchored) execution block at the bonded block's number has a
/// different hash than the stored submission. Permissionless +
/// self-authenticating (validity = the proof verifies against the in-consensus
/// finalized anchor and the hash differs). No signer / nonce — the bond is
/// released to the original indexer recorded in the bond, never to the
/// submitter, so there is nothing to forge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReclaimCompletenessBondTx {
    pub subgrove_id: String,
    pub block_number: u64,
    /// Proof that the canonical block at `block_number` has a different hash
    /// than the bonded submission stored for `(subgrove_id, block_number)`.
    pub orphan_proof: crate::indexer_node::consensus_submitter::CanonicalBlockProof,
}

/// Request a coverage attestation over `[start, end]` for `subgrove_id`.
///
/// Anyone may submit. Consensus recomputes `verify_checkpoint_range_coverage`
/// inline against its own verifier records (cap: `RANGE_COVERAGE_MAX_INLINE`,
/// 100_000) and persists a [`CoverageAttestation`] ONLY when the range is
/// `Covered`; any `NotCovered` verdict — absence or provable lie — rejects the
/// tx and persists nothing. Signed + nonce'd purely for spam / replay control,
/// mirroring every other tx.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageAttestationTx {
    /// Subgrove whose per-block verifier records are consulted.
    pub subgrove_id: String,
    /// First block of the attested range (inclusive).
    pub start: u64,
    /// Last block of the attested range (inclusive).
    pub end: u64,
    /// The v1 range commitment the submitter claims — must equal the recompute
    /// from the stored verifier records, else the range is `NotCovered`.
    pub commitment: [u8; 32],
    /// DID of the submitter (any registered DID; the tx is permissionless).
    pub submitter_did: String,
    /// Signature over the canonical attestation message.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Persisted coverage attestation. It exists in consensus state (and is thus
/// provable against the `app_hash`) ONLY because consensus itself recomputed
/// the range as `Covered`. Keyed range-exact via [`coverage_attestation_key`]
/// — a client asking a strict sub-range must NOT get a hit — so the future
/// multi-chunk tiling rule can rely on attestations being range-exact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageAttestation {
    /// Subgrove this attestation covers.
    pub subgrove_id: String,
    /// First block of the attested range (inclusive).
    pub start: u64,
    /// Last block of the attested range (inclusive).
    pub end: u64,
    /// The v1 range commitment consensus recomputed and matched.
    pub commitment: [u8; 32],
    /// Willow block height at which consensus recomputed + recorded this.
    pub attested_at_height: u64,
}

/// Top-level GroveDb tree the coverage attestations live under. This is the
/// SAME GroveDb whose root becomes the CometBFT `app_hash`, so a single-key
/// proof of an attestation roots to the committed app_hash. Shared between the
/// consensus writer and the api-server reader so both derive an identical path.
pub const COVERAGE_ATTESTATION_ROOT_TREE: &[u8] = b"indexed_data";
/// Sub-tree (under [`COVERAGE_ATTESTATION_ROOT_TREE`]) holding one child tree
/// per subgrove, each keyed by [`coverage_attestation_key`].
pub const COVERAGE_ATTESTATION_SUBTREE: &[u8] = b"coverage_attestations";

/// Range-exact 16-byte key: `start.to_be_bytes() || end.to_be_bytes()`.
/// Big-endian + fixed-width so any client rebuilds it deterministically from a
/// `/coverage/{sg}/{start}/{end}` URL and no `(start, end)` can prefix-collide
/// another (a strict sub-range hashes to a different key ⇒ no false hit).
pub fn coverage_attestation_key(start: u64, end: u64) -> [u8; 16] {
    let mut key = [0u8; 16];
    key[..8].copy_from_slice(&start.to_be_bytes());
    key[8..].copy_from_slice(&end.to_be_bytes());
    key
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

    /// `CompleteBlockTx.beneficiary` (the catcher's slash-reward payee) is a
    /// trailing bincode field; this guards that it survives the wire round-trip,
    /// including the empty-string default. An economic-critical field — a silent
    /// decode regression would misdirect or drop slash rewards.
    #[test]
    fn complete_block_tx_bincode_round_trip() {
        use crate::indexer_node::consensus_submitter::HistoricalHeaderProof;
        let proof = HistoricalHeaderProof {
            anchor_el_block: 0,
            anchor_beacon_root: [0u8; 32],
            anchor_state_root: [0u8; 32],
            anchor_eip4788_proof: vec![],
            past_beacon_slot: 1,
            past_beacon_block_root: [0u8; 32],
            block_root_to_state_root_branch: vec![],
            receipts_root_to_block_root_branch: vec![],
            transactions_root_to_block_root_branch: vec![],
            logs_bloom_to_block_root_branch: vec![],
            block_number_to_block_root_branch: vec![],
            block_hash_to_block_root_branch: vec![],
            parent_hash_to_block_root_branch: vec![],
        };
        let tx = CompleteBlockTx {
            subgrove_id: "sg".to_string(),
            block_number: 7,
            historical_header_proof: proof,
            beneficiary: "did:willow:catcher".to_string(),
        };
        let got: CompleteBlockTx = bincode::deserialize(&bincode::serialize(&tx).unwrap()).unwrap();
        assert_eq!(got.beneficiary, "did:willow:catcher");
        assert_eq!(got.block_number, 7);

        let tx2 = CompleteBlockTx {
            beneficiary: String::new(),
            ..tx
        };
        let got2: CompleteBlockTx =
            bincode::deserialize(&bincode::serialize(&tx2).unwrap()).unwrap();
        assert!(got2.beneficiary.is_empty());
    }

    /// `ReclaimCompletenessBondTx` + its embedded `CanonicalBlockProof` are
    /// bincode wire types; guard that all fields survive the round-trip (a
    /// silent decode regression would misverify orphan reclaims).
    #[test]
    fn reclaim_completeness_bond_tx_bincode_round_trip() {
        use crate::indexer_node::consensus_submitter::CanonicalBlockProof;
        let tx = ReclaimCompletenessBondTx {
            subgrove_id: "sg".to_string(),
            block_number: 21_000_000,
            orphan_proof: CanonicalBlockProof {
                canonical_beacon_slot: 8_100_000,
                canonical_beacon_block_root: [0x11; 32],
                canonical_block_hash: [0x22; 32],
                block_root_to_state_root_branch: vec![1, 2, 3],
                block_number_to_block_root_branch: vec![4, 5, 6],
                block_hash_to_block_root_branch: vec![7, 8, 9],
            },
        };
        let got: ReclaimCompletenessBondTx =
            bincode::deserialize(&bincode::serialize(&tx).unwrap()).unwrap();
        assert_eq!(got.subgrove_id, "sg");
        assert_eq!(got.block_number, 21_000_000);
        assert_eq!(got.orphan_proof.canonical_block_hash, [0x22; 32]);
        assert_eq!(got.orphan_proof.canonical_beacon_slot, 8_100_000);
        assert_eq!(
            got.orphan_proof.block_hash_to_block_root_branch,
            vec![7, 8, 9]
        );
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
    fn replace_subgrove_tx_bincode_round_trip() {
        // ReplaceSubgrove reuses the RegisterSubgroveTx payload; round-trip the
        // whole Transaction enum so the appended variant tag stays stable.
        let inner = RegisterSubgroveTx {
            subgrove_id: "sg-1".to_string(),
            name: String::new(),
            description: "replace".to_string(),
            schema: "type T @entity { id: ID! }".to_string(),
            owner_did: "did:willow:owner".to_string(),
            admins: vec![],
            initial_funding: None,
            checkpoint_verification: Default::default(),
            mode: default_data_storage_mode(),
            privacy: None,
            initial_owner_key_grant: None,
            template_config: None,
            confirmation_depth: 0,
            signature: vec![1, 2, 3],
            public_key_id: "did:willow:owner#key-1".to_string(),
            nonce: 7,
            cryptographic_completeness: false,
        };
        let tx = Transaction::ReplaceSubgrove(inner);
        let bytes = bincode::serialize(&tx).expect("bincode serialize");
        let got: Transaction = bincode::deserialize(&bytes).expect("bincode deserialize");
        match got {
            Transaction::ReplaceSubgrove(r) => {
                assert_eq!(r.subgrove_id, "sg-1");
                assert_eq!(r.nonce, 7);
            }
            other => panic!("expected ReplaceSubgrove, got {}", other.type_name()),
        }
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

    #[test]
    fn submit_anchor_tx_bincode_round_trip() {
        let tx = SubmitAnchorTx {
            did: "did:willow:mcp-server-1".to_string(),
            anchor_id: "anchor_1_100_abc12345".to_string(),
            sequence_range: [1, 100],
            merkle_root: "deadbeef".repeat(8),
            count: 100,
            receipt_hashes: vec!["aa".repeat(32), "bb".repeat(32)],
            timestamp: "2026-05-22T12:00:00Z".to_string(),
            previous_anchor_hash: ANCHOR_GENESIS_SENTINEL.to_string(),
            anchor_hash: "cc".repeat(32),
            is_genesis: true,
            signature: vec![1, 2, 3],
            public_key_id: "did:willow:mcp-server-1#key-1".to_string(),
            nonce: 1,
        };
        let bytes = bincode::serialize(&tx).expect("bincode serialize");
        let got: SubmitAnchorTx = bincode::deserialize(&bytes).expect("bincode deserialize");
        assert_eq!(got.sequence_range, tx.sequence_range);
        assert_eq!(got.receipt_hashes.len(), 2);
        assert!(got.is_genesis);
    }
}
