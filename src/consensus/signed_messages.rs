//! The messages transactions are signed over for the kinds whose older messages left fields or
//! the nonce unsigned. The node accepts these forms from an activation height and the older forms
//! below it; a sender signs the form for the block its transaction will land in.
//!
//! Each message is lines joined by `\n` with no trailing newline: the kind first, then
//! `Label: value` lines, the nonce last. A text field holding a line break is refused, so the
//! lines read back one way only. Two shapes:
//!
//! - **Lines**, for kinds that SDKs and people sign: every field is written out
//!   ([`grant_subgrove_key`], [`rotate_subgrove_key`], [`unregister_storage_node`], and the
//!   moderation kinds).
//! - **Digest**, for kinds only Rust code sends (the indexer, the storage node, tools): `Signer`,
//!   then `Tx`, the lowercase hex SHA-256 of the transaction struct's bincode (bincode 1.x
//!   default) with an empty signature, so every field is bound, including fields added later
//!   ([`digest_form`]).
//!
//! Every first line differs from every other signed message's, so no signature carries across
//! kinds. RegisterSubgrove and ReplaceSubgrove sign their own first line, then `Subgrove`,
//! `Owner`, `Config` (the lowercase hex SHA-256 of the `RegisterSubgroveTx` bincode with an empty
//! signature), and `Nonce`.

use sha2::{Digest, Sha256};

use super::dispute_resolution::OpenCommitmentDisputeTx;
use super::transactions::*;
use crate::storage::EncryptedKeyGrant;

/// `Label: value`, refused when the value holds a line break.
pub fn field(label: &str, value: &str) -> Result<String, String> {
    if value.contains('\n') {
        return Err(format!(
            "{label} holds a line break, which a signed field can't"
        ));
    }
    Ok(format!("{label}: {value}"))
}

/// The lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `<kind>`, `Signer: <signer>`, `Tx: <hex SHA-256 of unsigned_bincode>`, `Nonce: <nonce>`.
pub fn digest_form(
    kind: &str,
    signer: &str,
    unsigned_bincode: &[u8],
    nonce: u64,
) -> Result<String, String> {
    Ok([
        kind.to_string(),
        field("Signer", signer)?,
        format!("Tx: {}", sha256_hex(unsigned_bincode)),
        format!("Nonce: {nonce}"),
    ]
    .join("\n"))
}

/// The bincode (1.x default) of `tx`, as it is hashed into a digest form.
fn unsigned_bincode<T: serde::Serialize>(tx: &T) -> Result<Vec<u8>, String> {
    bincode::serialize(tx).map_err(|e| format!("Failed to encode the transaction: {e}"))
}

macro_rules! digest_kinds {
    ($($(#[$doc:meta])* $fn_name:ident, $ty:ty, $kind:literal, $signer:ident;)*) => {
        $(
            $(#[$doc])*
            pub fn $fn_name(tx: &$ty) -> Result<String, String> {
                let mut unsigned = tx.clone();
                unsigned.signature = Vec::new();
                digest_form($kind, &tx.$signer, &unsigned_bincode(&unsigned)?, tx.nonce)
            }
        )*
    };
}

digest_kinds! {
    /// `RegisterIndexer` digest form, signed by `indexer_did`.
    register_indexer, RegisterIndexerTx, "RegisterIndexer", indexer_did;
    /// `HistoricalCheckpoint` digest form, signed by `indexer_did`.
    historical_checkpoint, HistoricalCheckpointTx, "HistoricalCheckpoint", indexer_did;
    /// `AvailabilityProof` digest form, signed by `indexer_did`.
    availability_proof, AvailabilityProofTx, "AvailabilityProof", indexer_did;
    /// `PrivateSubgroveCommitment` digest form, signed by `provider_did`.
    private_subgrove_commitment, PrivateSubgroveCommitmentTx, "PrivateSubgroveCommitment", provider_did;
    /// `UpdateIndexerProfile` digest form, signed by `indexer_did`.
    update_indexer_profile, UpdateIndexerProfileTx, "UpdateIndexerProfile", indexer_did;
    /// `OpenCommitmentDispute` digest form, signed by `challenger_did`.
    open_commitment_dispute, OpenCommitmentDisputeTx, "OpenCommitmentDispute", challenger_did;
    /// `RegisterStorageNode` digest form, signed by `node_did`.
    register_storage_node, RegisterStorageNodeTx, "RegisterStorageNode", node_did;
    /// `StorageAvailabilityProof` digest form, signed by `node_did`.
    storage_availability_proof, StorageAvailabilityProofTx, "StorageAvailabilityProof", node_did;
    /// `CreateOperatorEntity` digest form, signed by `admin_did`.
    create_operator_entity, CreateOperatorEntityTx, "CreateOperatorEntity", admin_did;
    /// `RecordFundingSource` digest form, signed by `indexer_did`.
    record_funding_source, RecordFundingSourceTx, "RecordFundingSource", indexer_did;
    /// `WithdrawHistoricalAvailability` digest form, signed by `indexer_did`.
    withdraw_historical_availability, WithdrawHistoricalAvailabilityTx, "WithdrawHistoricalAvailability", indexer_did;
}

/// The lines of one key grant, in order: `Grantee`, `GranteeKey`, `KeyEpoch`, `EphemeralKey`,
/// `EncryptedKey` (both lowercase hex of the exact bytes), `GrantedBy`, `GrantedAt`.
fn grant_lines(grant: &EncryptedKeyGrant) -> Result<Vec<String>, String> {
    Ok(vec![
        field("Grantee", &grant.grantee_did)?,
        field("GranteeKey", &grant.grantee_public_key_id)?,
        format!("KeyEpoch: {}", grant.key_epoch),
        format!("EphemeralKey: {}", hex::encode(&grant.ephemeral_public_key)),
        format!("EncryptedKey: {}", hex::encode(&grant.encrypted_key)),
        field("GrantedBy", &grant.granted_by)?,
        format!("GrantedAt: {}", grant.granted_at),
    ])
}

/// `GrantSubgroveKey`, `Subgrove`, `Sender`, the grant's lines, `Nonce`.
pub fn grant_subgrove_key(tx: &GrantSubgroveKeyTx) -> Result<String, String> {
    let mut lines = vec![
        "GrantSubgroveKey".to_string(),
        field("Subgrove", &tx.subgrove_id)?,
        field("Sender", &tx.sender_did)?,
    ];
    lines.extend(grant_lines(&tx.encrypted_key_grant)?);
    lines.push(format!("Nonce: {}", tx.nonce));
    Ok(lines.join("\n"))
}

/// `RotateSubgroveKey`, `Subgrove`, `Sender`, `NewEpoch`, `Grants` (the count), each grant's
/// lines in order, `Nonce`.
pub fn rotate_subgrove_key(tx: &RotateSubgroveKeyTx) -> Result<String, String> {
    let mut lines = vec![
        "RotateSubgroveKey".to_string(),
        field("Subgrove", &tx.subgrove_id)?,
        field("Sender", &tx.sender_did)?,
        format!("NewEpoch: {}", tx.new_epoch),
        format!("Grants: {}", tx.new_grants.len()),
    ];
    for grant in &tx.new_grants {
        lines.extend(grant_lines(grant)?);
    }
    lines.push(format!("Nonce: {}", tx.nonce));
    Ok(lines.join("\n"))
}

/// `UnregisterStorageNode`, `Node`, `Nonce`.
pub fn unregister_storage_node(tx: &UnregisterStorageNodeTx) -> Result<String, String> {
    Ok([
        "UnregisterStorageNode".to_string(),
        field("Node", &tx.node_did)?,
        format!("Nonce: {}", tx.nonce),
    ]
    .join("\n"))
}

/// `BlockContentHash`, `Admin`, `ContentHash` (lowercase hex), `Reason`, `Nonce`.
pub fn block_content_hash(tx: &BlockContentHashTx) -> Result<String, String> {
    Ok([
        "BlockContentHash".to_string(),
        field("Admin", &tx.admin_did)?,
        format!("ContentHash: {}", hex::encode(tx.content_hash)),
        field("Reason", &tx.reason)?,
        format!("Nonce: {}", tx.nonce),
    ]
    .join("\n"))
}

/// `UnblockContentHash`, `Admin`, `ContentHash` (lowercase hex), `Nonce`.
pub fn unblock_content_hash(tx: &UnblockContentHashTx) -> Result<String, String> {
    Ok([
        "UnblockContentHash".to_string(),
        field("Admin", &tx.admin_did)?,
        format!("ContentHash: {}", hex::encode(tx.content_hash)),
        format!("Nonce: {}", tx.nonce),
    ]
    .join("\n"))
}

/// `ReportContent`, `Reporter`, `ContentHash` (lowercase hex), `Reason`, `Nonce`.
pub fn report_content(tx: &ReportContentTx) -> Result<String, String> {
    Ok([
        "ReportContent".to_string(),
        field("Reporter", &tx.reporter_did)?,
        format!("ContentHash: {}", hex::encode(tx.content_hash)),
        field("Reason", &tx.reason)?,
        format!("Nonce: {}", tx.nonce),
    ]
    .join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(grantee: &str, epoch: u32) -> EncryptedKeyGrant {
        EncryptedKeyGrant {
            grantee_did: grantee.into(),
            key_epoch: epoch,
            grantee_public_key_id: format!("{grantee}#key-1"),
            ephemeral_public_key: vec![0x11; 32],
            encrypted_key: vec![0x22; 56],
            granted_by: "did:willow:a".into(),
            granted_at: 1_800_000_000,
        }
    }

    #[test]
    fn a_grant_binds_every_field() {
        let tx = GrantSubgroveKeyTx {
            subgrove_id: "private-1".into(),
            encrypted_key_grant: grant("did:willow:b", 2),
            sender_did: "did:willow:a".into(),
            signature: vec![1; 64],
            public_key_id: "did:willow:a#key-1".into(),
            nonce: 5,
        };
        let base = grant_subgrove_key(&tx).unwrap();
        assert_eq!(
            base,
            format!(
                "GrantSubgroveKey\nSubgrove: private-1\nSender: did:willow:a\nGrantee: did:willow:b\n\
                 GranteeKey: did:willow:b#key-1\nKeyEpoch: 2\nEphemeralKey: {}\nEncryptedKey: {}\n\
                 GrantedBy: did:willow:a\nGrantedAt: 1800000000\nNonce: 5",
                "11".repeat(32),
                "22".repeat(56)
            )
        );
        let mut changed = vec![];
        for edit in 0..7 {
            let mut t = tx.clone();
            let g = &mut t.encrypted_key_grant;
            match edit {
                0 => g.grantee_did.push('x'),
                1 => g.grantee_public_key_id.push('x'),
                2 => g.key_epoch += 1,
                3 => g.ephemeral_public_key[0] ^= 1,
                4 => g.encrypted_key.push(0),
                5 => g.granted_by.push('x'),
                _ => g.granted_at += 1,
            }
            changed.push(grant_subgrove_key(&t).unwrap());
        }
        assert!(changed.iter().all(|m| *m != base));
        let resigned = GrantSubgroveKeyTx {
            signature: vec![],
            ..tx.clone()
        };
        assert_eq!(grant_subgrove_key(&resigned).unwrap(), base);
    }

    #[test]
    fn a_rotation_binds_every_grant_and_their_count() {
        let tx = RotateSubgroveKeyTx {
            subgrove_id: "private-1".into(),
            new_epoch: 3,
            new_grants: vec![grant("did:willow:b", 3), grant("did:willow:c", 3)],
            sender_did: "did:willow:a".into(),
            signature: vec![],
            public_key_id: "did:willow:a#key-1".into(),
            nonce: 6,
        };
        let base = rotate_subgrove_key(&tx).unwrap();
        assert!(base.starts_with("RotateSubgroveKey\nSubgrove: private-1\nSender: did:willow:a\nNewEpoch: 3\nGrants: 2\nGrantee: did:willow:b\n"));
        assert!(base.ends_with("\nNonce: 6"));
        let mut fewer = tx.clone();
        fewer.new_grants.pop();
        let mut swapped = tx.clone();
        swapped.new_grants.swap(0, 1);
        let mut altered = tx.clone();
        altered.new_grants[1].encrypted_key[3] ^= 1;
        for t in [fewer, swapped, altered] {
            assert_ne!(rotate_subgrove_key(&t).unwrap(), base);
        }
    }

    #[test]
    fn a_digest_form_binds_every_field_but_the_signature() {
        let tx = RegisterStorageNodeTx {
            node_did: "did:willow:s".into(),
            endpoint: "https://storage.example".into(),
            capacity_bytes: 1 << 40,
            stake_amount: 5_000 * 10u128.pow(18),
            signature: vec![7; 64],
            public_key_id: "did:willow:s#key-1".into(),
            nonce: 9,
        };
        let base = register_storage_node(&tx).unwrap();
        let unsigned = RegisterStorageNodeTx {
            signature: vec![],
            ..tx.clone()
        };
        assert_eq!(
            base,
            format!(
                "RegisterStorageNode\nSigner: did:willow:s\nTx: {}\nNonce: 9",
                sha256_hex(&bincode::serialize(&unsigned).unwrap())
            )
        );
        assert_eq!(register_storage_node(&unsigned).unwrap(), base);
        for t in [
            RegisterStorageNodeTx {
                stake_amount: 1,
                ..tx.clone()
            },
            RegisterStorageNodeTx {
                public_key_id: "did:willow:s#key-2".into(),
                ..tx.clone()
            },
            RegisterStorageNodeTx {
                nonce: 10,
                ..tx.clone()
            },
        ] {
            assert_ne!(register_storage_node(&t).unwrap(), base);
        }
    }

    #[test]
    fn a_text_field_with_a_line_break_is_refused() {
        let tx = BlockContentHashTx {
            content_hash: [3; 32],
            reason: "spam\nNonce: 1".into(),
            admin_did: "did:willow:admin".into(),
            signature: vec![],
            public_key_id: "did:willow:admin#key-1".into(),
            nonce: 2,
        };
        let e = block_content_hash(&tx).unwrap_err();
        assert!(e.contains("Reason holds a line break"), "{e}");
        let tx = UnregisterStorageNodeTx {
            node_did: "did:willow:s\n".into(),
            signature: vec![],
            public_key_id: String::new(),
            nonce: 1,
        };
        assert!(unregister_storage_node(&tx).is_err());
    }
}
