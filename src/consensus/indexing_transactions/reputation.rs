// ============================================================================
// Reputation Transactions
// ============================================================================

use serde::{Deserialize, Serialize};

/// Transaction to update an indexer's profile information.
///
/// Indexers can update their display information, declared infrastructure,
/// and other profile metadata. This information is stored in the reputation
/// system and helps with Sybil detection and transparency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateIndexerProfileTx {
    /// The indexer's DID.
    pub indexer_did: String,
    /// Display name (optional, max 100 chars).
    pub display_name: Option<String>,
    /// Description/bio (optional, max 500 chars).
    pub description: Option<String>,
    /// Website URL (optional).
    pub website: Option<String>,
    /// Logo/avatar IPFS hash (optional).
    pub logo_ipfs: Option<String>,
    /// Declared geographic region (e.g., "US", "EU", "APAC").
    pub declared_region: Option<String>,
    /// Declared infrastructure type.
    pub infrastructure_type: Option<String>,
    /// Cryptographic signature from the indexer.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to create an operator entity.
///
/// An operator entity allows an organization to group multiple indexers
/// under a single brand/identity. This is voluntary transparency that
/// helps with Sybil detection - indexers under the same entity are
/// clearly linked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOperatorEntityTx {
    /// Unique entity ID (must be unique across all entities).
    pub entity_id: String,
    /// Human-readable name (e.g., "Acme Indexing Co").
    pub name: String,
    /// Description (optional, max 500 chars).
    pub description: Option<String>,
    /// Website URL (optional).
    pub website: Option<String>,
    /// Logo IPFS hash (optional).
    pub logo_ipfs: Option<String>,
    /// Admin DID that controls this entity.
    pub admin_did: String,
    /// Cryptographic signature from the admin.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to link an indexer to an operator entity.
///
/// Both the indexer and the entity admin must sign this transaction
/// to prevent unauthorized linking. Once linked, the indexer's profile
/// will show the entity association and correlation flags will be set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkIndexerToEntityTx {
    /// The indexer's DID to link.
    pub indexer_did: String,
    /// The entity ID to link to.
    pub entity_id: String,
    /// Signature from the indexer.
    pub indexer_signature: Vec<u8>,
    /// ID of the indexer's public key.
    pub indexer_public_key_id: String,
    /// Signature from the entity admin.
    pub admin_signature: Vec<u8>,
    /// ID of the admin's public key.
    pub admin_public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to unlink an indexer from an operator entity.
///
/// Either the indexer or the entity admin can initiate this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlinkIndexerFromEntityTx {
    /// The indexer's DID to unlink.
    pub indexer_did: String,
    /// The entity ID to unlink from.
    pub entity_id: String,
    /// Who is initiating the unlink ("indexer" or "admin").
    pub initiated_by: String,
    /// Cryptographic signature from the initiator.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Transaction to record a funding source for an indexer.
///
/// This is typically called automatically when stake is deposited,
/// but can also be submitted manually to record off-chain funding
/// for transparency purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordFundingSourceTx {
    /// The indexer's DID.
    pub indexer_did: String,
    /// The funding source address.
    pub source_address: String,
    /// The chain the funding came from (e.g., "ethereum", "willow").
    pub chain: String,
    /// Transaction hash of the funding transaction.
    pub tx_hash: String,
    /// Amount funded (in wei).
    pub amount: u128,
    /// Cryptographic signature from the indexer.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Replay protection nonce.
    pub nonce: u64,
}
