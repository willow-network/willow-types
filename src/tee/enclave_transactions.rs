//! Enclave registry transaction types and related data structures.
//!
//! These are the transaction structs used for TEE enclave governance:
//! adding/removing approved enclaves and managing admin DIDs.

use serde::{Deserialize, Serialize};

use super::types::TeeType;

// ============================================================================
// Approved Enclave Info
// ============================================================================

/// Information about an approved enclave image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovedEnclaveInfo {
    /// TEE type (Nitro, SGX, etc.).
    pub tee_type: TeeType,

    /// Hash of the enclave image.
    /// - Nitro: PCR0 (48 bytes, hex-encoded)
    /// - SGX: MRENCLAVE (32 bytes, hex-encoded)
    pub enclave_hash: String,

    /// Human-readable name for the enclave.
    pub name: String,

    /// Description of the enclave's purpose.
    pub description: String,

    /// Version of the enclave software.
    pub version: String,

    /// DID of the entity that added this enclave.
    pub added_by: String,

    /// Unix timestamp when the enclave was approved.
    pub approved_at: u64,

    /// Block height when the enclave was approved.
    pub approved_at_block: u64,

    /// Whether the enclave is currently active.
    pub is_active: bool,

    /// Optional expiration timestamp as Unix epoch seconds (UTC).
    /// - `None`: Enclave approval never expires (permanent until manually revoked)
    /// - `Some(timestamp)`: Enclave is valid only while `current_time < expires_at` (exclusive upper bound)
    ///
    /// When an enclave expires, it will be rejected in verification even if still in the approved list.
    /// Expired enclaves can be re-approved with a new expiration or removed from the list.
    pub expires_at: Option<u64>,

    /// Git commit or release tag for audit trail.
    pub source_reference: Option<String>,

    /// Additional metadata.
    pub metadata: Option<serde_json::Value>,
}

// ============================================================================
// Enclave Index Entry
// ============================================================================

/// Entry in the enclave index, tracking all known enclaves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveIndexEntry {
    /// TEE type.
    pub tee_type: TeeType,
    /// Enclave hash (hex-encoded).
    pub enclave_hash: String,
    /// Whether the enclave is currently active.
    pub is_active: bool,
}

// ============================================================================
// Admin Info
// ============================================================================

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
    pub public_key_base58: Option<String>,
    /// Public key encoded in hex (optional).
    pub public_key_hex: Option<String>,
}

/// Information about an authorized admin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminInfo {
    /// Admin DID.
    pub did: String,
    /// Admin's public key for signature verification.
    pub public_key: PublicKey,
    /// Unix timestamp when the admin was added.
    pub added_at: u64,
    /// DID of who added this admin (for audit trail).
    pub added_by: Option<String>,
}

// ============================================================================
// Enclave Governance Transactions
// ============================================================================

/// Transaction to add an approved enclave.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddApprovedEnclaveTx {
    /// TEE type.
    pub tee_type: TeeType,
    /// Enclave image hash (hex-encoded).
    pub enclave_hash: String,
    /// Human-readable name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Software version.
    pub version: String,
    /// Optional source reference (git commit, release tag).
    pub source_reference: Option<String>,
    /// Optional expiration timestamp.
    pub expires_at: Option<u64>,
    /// DID of the admin adding this enclave.
    pub admin_did: String,
    /// Signature from the admin.
    pub signature: Vec<u8>,
    /// Nonce for replay protection.
    pub nonce: u64,
}

/// Transaction to remove (revoke) an approved enclave.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveApprovedEnclaveTx {
    /// TEE type.
    pub tee_type: TeeType,
    /// Enclave image hash to remove.
    pub enclave_hash: String,
    /// Reason for removal.
    pub reason: String,
    /// DID of the admin removing this enclave.
    pub admin_did: String,
    /// Signature from the admin.
    pub signature: Vec<u8>,
    /// Nonce for replay protection.
    pub nonce: u64,
}

/// Transaction to add a new TEE enclave registry admin.
///
/// Only existing admins can add new admins. The new admin's public key
/// will be fetched from their DID document during verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddEnclaveAdminTx {
    /// DID of the new admin to add.
    pub new_admin_did: String,
    /// Optional description for documentation.
    pub description: Option<String>,
    /// DID of the existing admin adding this new admin.
    pub admin_did: String,
    /// Signature from the existing admin.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Nonce for replay protection.
    pub nonce: u64,
}

/// Transaction to remove a TEE enclave registry admin.
///
/// Only existing admins can remove other admins. An admin cannot remove
/// themselves if they are the last remaining admin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveEnclaveAdminTx {
    /// DID of the admin to remove.
    pub admin_did_to_remove: String,
    /// Reason for removal.
    pub reason: String,
    /// DID of the admin performing the removal.
    pub admin_did: String,
    /// Signature from the admin.
    pub signature: Vec<u8>,
    /// ID of the public key used for signing.
    pub public_key_id: String,
    /// Nonce for replay protection.
    pub nonce: u64,
}
