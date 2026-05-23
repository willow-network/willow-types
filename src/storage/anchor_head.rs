use serde::{Deserialize, Serialize};

/// Per-DID anchor head record stored at `[SYSTEM, ANCHOR_HEADS, did]`.
///
/// Updated atomically with each accepted `SubmitAnchorTx`. Lets the
/// consensus validator answer "what's the latest anchor I've seen for
/// DID X?" in O(1) instead of scanning every anchor body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorHead {
    /// `anchor_hash` of the latest accepted anchor for this DID.
    pub anchor_hash: String,
    /// `sequence_range[1]` of the latest accepted anchor.
    pub sequence_to: u64,
    /// Stable identifier of the latest accepted anchor.
    pub anchor_id: String,
    /// True once a genesis anchor has been accepted for this DID — second
    /// genesis attempts are rejected.
    pub genesis_accepted: bool,
    /// Block height at which the latest anchor was accepted (advisory).
    pub block_height: u64,
}
