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

    // App transactions (with fees)
    /// Register a new application.
    RegisterApp(RegisterAppTx),
    /// Register a subgrove for an application.
    RegisterSubgrove(RegisterSubgroveTx),
    /// Fund an application's balance.
    FundApp(FundAppTx),
    /// Update read pricing for a subgrove.
    UpdateSubgroveReadPricing(UpdateSubgroveReadPricingTx),
    /// Update the free readers list for a subgrove.
    UpdateSubgroveFreeReaders(UpdateSubgroveFreeReadersTx),

    // Bridge transactions
    /// Submit proof of Ethereum stake.
    SubmitStakeProof(SubmitStakeProofTx),
    /// Request withdrawal to Ethereum.
    RequestWithdrawal(RequestWithdrawalTx),
    /// Submit batch of withdrawal proofs.
    SubmitWithdrawalBatch(SubmitWithdrawalBatchTx),

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
}

/// Transaction to transfer WILL tokens between accounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferTx {
    /// DID of the sender.
    pub from_did: String,
    /// DID of the recipient.
    pub to_did: String,
    /// Amount of WILL tokens to transfer.
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
    pub amount: u128,
    /// Cryptographic signature from the validator.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to register a new application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterAppTx {
    /// Unique identifier for the application.
    pub app_id: String,
    /// Human-readable name.
    pub name: String,
    /// Description of the application.
    pub description: String,
    /// Type/category of the application.
    pub app_type: String,
    /// DID of the application owner.
    pub owner_did: String,
    /// List of admin DIDs with elevated permissions.
    pub admins: Vec<String>,
    /// Optional initial funding amount (in smallest token unit) to atomically
    /// fund the app during registration, avoiding a separate FundApp transaction.
    #[serde(default)]
    pub initial_funding: Option<u128>,
    /// Cryptographic signature from the owner.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to register a subgrove for an application.
///
/// Supports two modes via the `mode` field:
/// - `DataStorage`: For off-chain structured data with verification
/// - `BlockchainIndexing`: For on-chain data indexing with WASM transformations
///
/// When `mode` is omitted during deserialization, defaults to `DataStorage`
/// with empty values for backward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterSubgroveTx {
    /// Unique identifier for the subgrove.
    pub subgrove_id: String,
    /// Parent application ID.
    pub app_id: String,
    /// JSON schema defining the data structure.
    pub schema: String,
    /// DID of the subgrove owner.
    pub owner_did: String,
    /// Checkpoint verification configuration.
    /// Optionally requires TEE attestation for checkpoint submissions.
    #[serde(default)]
    pub checkpoint_verification: super::indexing_transactions::CheckpointVerificationConfig,
    /// The subgrove mode: DataStorage or BlockchainIndexing.
    #[serde(default = "super::indexing_transactions::default_data_storage_mode")]
    pub mode: super::indexing_transactions::SubgroveMode,
    /// Optional privacy configuration for private subgroves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy: Option<crate::storage::PrivacyConfig>,
    /// Optional initial key grant for the owner (when privacy is enabled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_owner_key_grant: Option<crate::storage::EncryptedKeyGrant>,
    /// Cryptographic signature from the owner.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to fund an application's balance for storage fees.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundAppTx {
    /// Application to fund.
    pub app_id: String,
    /// Amount of WILL tokens to add.
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

/// Transaction to update read pricing configuration for a subgrove.
///
/// Only the subgrove owner can submit this transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSubgroveReadPricingTx {
    /// Parent application ID.
    pub app_id: String,
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
    /// Parent application ID.
    pub app_id: String,
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

/// Transaction to submit proof of Ethereum stake for bridge operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitStakeProofTx {
    /// RLP-encoded Ethereum block header.
    pub eth_block_header: Vec<u8>,
    /// Merkle Patricia Trie proof of receipt inclusion.
    pub receipt_proof: Vec<u8>,
    /// Index of the log in the transaction receipt.
    pub log_index: u64,
    /// Willow DID to receive the bridged tokens.
    pub willow_recipient: String,
    /// Optional additional finality proof.
    pub finality_proof: Option<Vec<u8>>,
    /// Cryptographic signature.
    pub signature: Vec<u8>,
}

/// Transaction to request withdrawal of tokens to Ethereum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestWithdrawalTx {
    /// Willow DID initiating the withdrawal.
    pub willow_sender: String,
    /// Ethereum address to receive the tokens.
    pub eth_recipient: [u8; 20],
    /// Amount of WILL tokens to withdraw.
    pub amount: u128,
    /// Cryptographic signature from the sender.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to submit a batch of validated withdrawals.
///
/// Multiple validator signatures are required to approve a withdrawal batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitWithdrawalBatchTx {
    /// Unique identifier for this batch.
    pub batch_id: [u8; 32],
    /// Merkle root of the withdrawal requests.
    pub merkle_root: [u8; 32],
    /// IDs of withdrawal requests included in this batch.
    pub withdrawal_requests: Vec<[u8; 32]>,
    /// Signatures from validators approving the batch.
    pub validator_signatures: Vec<Vec<u8>>,
    /// Cryptographic signature.
    pub signature: Vec<u8>,
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
    /// Application containing the subgrove.
    pub app_id: String,
    /// Subgrove to store data in.
    pub subgrove_id: String,
    /// Key for the data entry.
    pub key: String,
    /// JSON data to store.
    pub data: serde_json::Value,
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
    /// Application containing the subgrove.
    pub app_id: String,
    /// Subgrove containing the data.
    pub subgrove_id: String,
    /// Key of the data entry to update.
    pub key: String,
    /// New JSON data.
    pub data: serde_json::Value,
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
    /// Application containing the subgrove.
    pub app_id: String,
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
    /// Parent application ID.
    pub app_id: String,
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
    /// Parent application ID.
    pub app_id: String,
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
    /// Parent application ID.
    pub app_id: String,
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
    /// Parent application ID.
    pub app_id: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gkr_proof: Option<crate::consensus::indexing_transactions::GkrProofData>,
    /// Optional TEE attestation of the commitment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
