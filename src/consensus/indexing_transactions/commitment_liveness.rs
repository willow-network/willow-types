use serde::{Deserialize, Serialize};

/// Configuration for commitment liveness enforcement on private subgroves.
///
/// Mirrors the `HistoricalAvailabilityConfig` pattern but operates on
/// commitment windows rather than proof intervals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentLivenessConfig {
    /// Number of windows before enforcement begins after registration.
    #[serde(default = "default_grace_period_windows")]
    pub grace_period_windows: u32,

    /// Number of stale windows before slashing starts.
    #[serde(default = "default_stale_windows_until_slash")]
    pub stale_windows_until_slash: u32,

    /// Basis points of stake to slash per missed window during Slashing.
    /// 50 = 0.5% per window.
    #[serde(default = "default_slash_per_window_bps")]
    pub slash_per_window_bps: u32,

    /// Maximum cumulative slash in basis points before transitioning to Suspended.
    /// 2000 = 20%.
    #[serde(default = "default_max_slash_bps")]
    pub max_slash_bps: u32,

    /// Consecutive committed windows required to reactivate from Suspended.
    #[serde(default = "default_recovery_windows")]
    pub recovery_windows: u32,
}

fn default_grace_period_windows() -> u32 {
    3
}
fn default_stale_windows_until_slash() -> u32 {
    2
}
fn default_slash_per_window_bps() -> u32 {
    50 // 0.5%
}
fn default_max_slash_bps() -> u32 {
    2000 // 20%
}
fn default_recovery_windows() -> u32 {
    5
}

impl Default for CommitmentLivenessConfig {
    fn default() -> Self {
        Self {
            grace_period_windows: default_grace_period_windows(),
            stale_windows_until_slash: default_stale_windows_until_slash(),
            slash_per_window_bps: default_slash_per_window_bps(),
            max_slash_bps: default_max_slash_bps(),
            recovery_windows: default_recovery_windows(),
        }
    }
}

/// Liveness status for a private subgrove's commitment schedule.
///
/// Mirrors `AvailabilityStatus` from `historical_availability.rs`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CommitmentLivenessStatus {
    /// Initial period after registration. No enforcement.
    GracePeriod {
        /// Number of grace windows remaining.
        windows_remaining: u32,
    },
    /// Provider is committing within windows. Normal operation.
    Active,
    /// Provider missed window(s). Soft penalty: no epoch rewards.
    Stale {
        /// Consecutive missed windows while stale.
        consecutive_missed: u32,
    },
    /// Extended absence. Progressive slashing each missed window.
    Slashing {
        /// Total basis points slashed so far.
        total_slashed_bps: u32,
    },
    /// Max slash reached. Requires explicit reactivation.
    Suspended {
        /// Consecutive committed windows since suspension.
        consecutive_hits: u32,
    },
}

impl CommitmentLivenessStatus {
    /// Returns true if the provider should earn epoch rewards.
    pub fn is_eligible_for_rewards(&self) -> bool {
        matches!(
            self,
            CommitmentLivenessStatus::GracePeriod { .. } | CommitmentLivenessStatus::Active
        )
    }

    /// Record that a commitment was received in the current window.
    /// Transitions the status toward Active (or tracks recovery for Suspended).
    pub fn record_commitment(&mut self, config: &CommitmentLivenessConfig) {
        match self {
            CommitmentLivenessStatus::GracePeriod { .. } => {
                *self = CommitmentLivenessStatus::Active;
            }
            CommitmentLivenessStatus::Active => {
                // Already active, no change needed
            }
            CommitmentLivenessStatus::Stale { .. } => {
                *self = CommitmentLivenessStatus::Active;
            }
            CommitmentLivenessStatus::Slashing { .. } => {
                // Recovery from slashing — go back to Active (total_slashed preserved in schedule)
                *self = CommitmentLivenessStatus::Active;
            }
            CommitmentLivenessStatus::Suspended { consecutive_hits } => {
                *consecutive_hits += 1;
                if *consecutive_hits >= config.recovery_windows {
                    *self = CommitmentLivenessStatus::Active;
                }
            }
        }
    }

    /// Update status after a window closes without a commitment.
    /// Returns the basis points to slash (0 if no slashing).
    pub fn update_status(&mut self, config: &CommitmentLivenessConfig) -> u32 {
        match self {
            CommitmentLivenessStatus::GracePeriod { windows_remaining } => {
                if *windows_remaining <= 1 {
                    // Grace period expired without commitment
                    *self = CommitmentLivenessStatus::Stale {
                        consecutive_missed: 1,
                    };
                } else {
                    *windows_remaining -= 1;
                }
                0
            }
            CommitmentLivenessStatus::Active => {
                *self = CommitmentLivenessStatus::Stale {
                    consecutive_missed: 1,
                };
                0
            }
            CommitmentLivenessStatus::Stale { consecutive_missed } => {
                *consecutive_missed += 1;
                if *consecutive_missed > config.stale_windows_until_slash {
                    *self = CommitmentLivenessStatus::Slashing {
                        total_slashed_bps: config.slash_per_window_bps,
                    };
                    config.slash_per_window_bps
                } else {
                    0
                }
            }
            CommitmentLivenessStatus::Slashing { total_slashed_bps } => {
                let new_total = total_slashed_bps.saturating_add(config.slash_per_window_bps);
                if new_total >= config.max_slash_bps {
                    let slash_this_window = config.max_slash_bps.saturating_sub(*total_slashed_bps);
                    *self = CommitmentLivenessStatus::Suspended {
                        consecutive_hits: 0,
                    };
                    slash_this_window
                } else {
                    *total_slashed_bps = new_total;
                    config.slash_per_window_bps
                }
            }
            CommitmentLivenessStatus::Suspended { consecutive_hits } => {
                // Reset recovery progress on miss
                *consecutive_hits = 0;
                0
            }
        }
    }
}

/// Tracks the commitment schedule for a single private subgrove.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentSchedule {
    /// Composite key: "app_id:subgrove_id"
    pub subgrove_key: String,
    /// DID of the provider responsible for commitments.
    pub provider_did: String,
    /// Whether this is block-based or time-based windowing.
    pub window_type: CommitmentWindowType,
    /// Window size in blocks or seconds.
    pub window_size: u64,
    /// Start of the current window (block height or unix timestamp).
    pub window_start: u64,
    /// Whether a commitment has been received in the current window.
    pub committed_this_window: bool,
    /// Current liveness status.
    pub status: CommitmentLivenessStatus,
    /// Total windows missed (lifetime counter).
    pub total_missed: u32,
    /// Total windows committed (lifetime counter).
    pub total_committed: u32,
    /// Block height when the schedule was created.
    pub created_at_block: u64,
}

/// Whether commitment windows are measured in blocks or seconds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CommitmentWindowType {
    Blocks,
    Seconds,
}

impl CommitmentSchedule {
    /// Compute how many complete windows have elapsed since `window_start`.
    pub fn windows_elapsed(&self, current: u64) -> u64 {
        if current <= self.window_start || self.window_size == 0 {
            return 0;
        }
        (current - self.window_start) / self.window_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> CommitmentLivenessConfig {
        CommitmentLivenessConfig::default()
    }

    #[test]
    fn test_grace_period_no_enforcement() {
        let config = default_config();
        let mut status = CommitmentLivenessStatus::GracePeriod {
            windows_remaining: 3,
        };

        // Miss a window during grace — no slash, just decrement
        let slash = status.update_status(&config);
        assert_eq!(slash, 0);
        assert_eq!(
            status,
            CommitmentLivenessStatus::GracePeriod {
                windows_remaining: 2
            }
        );

        // Miss another
        let slash = status.update_status(&config);
        assert_eq!(slash, 0);
        assert_eq!(
            status,
            CommitmentLivenessStatus::GracePeriod {
                windows_remaining: 1
            }
        );
    }

    #[test]
    fn test_grace_to_stale_transition() {
        let config = default_config();
        let mut status = CommitmentLivenessStatus::GracePeriod {
            windows_remaining: 1,
        };

        let slash = status.update_status(&config);
        assert_eq!(slash, 0);
        assert_eq!(
            status,
            CommitmentLivenessStatus::Stale {
                consecutive_missed: 1
            }
        );
    }

    #[test]
    fn test_grace_to_active_on_commitment() {
        let config = default_config();
        let mut status = CommitmentLivenessStatus::GracePeriod {
            windows_remaining: 3,
        };

        status.record_commitment(&config);
        assert_eq!(status, CommitmentLivenessStatus::Active);
    }

    #[test]
    fn test_active_to_stale_on_miss() {
        let config = default_config();
        let mut status = CommitmentLivenessStatus::Active;

        let slash = status.update_status(&config);
        assert_eq!(slash, 0);
        assert_eq!(
            status,
            CommitmentLivenessStatus::Stale {
                consecutive_missed: 1
            }
        );
    }

    #[test]
    fn test_stale_to_slashing_progression() {
        let config = default_config(); // stale_windows_until_slash = 2
        let mut status = CommitmentLivenessStatus::Stale {
            consecutive_missed: 1,
        };

        // Second miss — still stale (consecutive_missed becomes 2, which equals threshold)
        let slash = status.update_status(&config);
        assert_eq!(slash, 0);
        assert_eq!(
            status,
            CommitmentLivenessStatus::Stale {
                consecutive_missed: 2
            }
        );

        // Third miss — exceeds threshold, transitions to Slashing
        let slash = status.update_status(&config);
        assert_eq!(slash, config.slash_per_window_bps);
        assert_eq!(
            status,
            CommitmentLivenessStatus::Slashing {
                total_slashed_bps: config.slash_per_window_bps
            }
        );
    }

    #[test]
    fn test_stale_recovery_on_commitment() {
        let config = default_config();
        let mut status = CommitmentLivenessStatus::Stale {
            consecutive_missed: 2,
        };

        status.record_commitment(&config);
        assert_eq!(status, CommitmentLivenessStatus::Active);
    }

    #[test]
    fn test_slashing_progressive_amounts() {
        let config = default_config(); // slash_per_window_bps = 50
        let mut status = CommitmentLivenessStatus::Slashing {
            total_slashed_bps: 50,
        };

        let slash = status.update_status(&config);
        assert_eq!(slash, 50);
        assert_eq!(
            status,
            CommitmentLivenessStatus::Slashing {
                total_slashed_bps: 100
            }
        );

        let slash = status.update_status(&config);
        assert_eq!(slash, 50);
        assert_eq!(
            status,
            CommitmentLivenessStatus::Slashing {
                total_slashed_bps: 150
            }
        );
    }

    #[test]
    fn test_slashing_max_cap_to_suspended() {
        let config = default_config(); // max_slash_bps = 2000
        let mut status = CommitmentLivenessStatus::Slashing {
            total_slashed_bps: 1980,
        };

        // Next miss would exceed max — caps and goes to Suspended
        let slash = status.update_status(&config);
        assert_eq!(slash, 20); // Only the remaining 20 bps
        assert_eq!(
            status,
            CommitmentLivenessStatus::Suspended {
                consecutive_hits: 0
            }
        );
    }

    #[test]
    fn test_slashing_recovery_on_commitment() {
        let config = default_config();
        let mut status = CommitmentLivenessStatus::Slashing {
            total_slashed_bps: 150,
        };

        status.record_commitment(&config);
        assert_eq!(status, CommitmentLivenessStatus::Active);
    }

    #[test]
    fn test_suspended_requires_consecutive_hits() {
        let config = CommitmentLivenessConfig {
            recovery_windows: 3,
            ..Default::default()
        };
        let mut status = CommitmentLivenessStatus::Suspended {
            consecutive_hits: 0,
        };

        // First commitment — not enough
        status.record_commitment(&config);
        assert_eq!(
            status,
            CommitmentLivenessStatus::Suspended {
                consecutive_hits: 1
            }
        );

        // Second commitment — still not enough
        status.record_commitment(&config);
        assert_eq!(
            status,
            CommitmentLivenessStatus::Suspended {
                consecutive_hits: 2
            }
        );

        // Third commitment — reactivated
        status.record_commitment(&config);
        assert_eq!(status, CommitmentLivenessStatus::Active);
    }

    #[test]
    fn test_suspended_miss_resets_recovery() {
        let config = default_config();
        let mut status = CommitmentLivenessStatus::Suspended {
            consecutive_hits: 3,
        };

        let slash = status.update_status(&config);
        assert_eq!(slash, 0); // No further slashing in Suspended
        assert_eq!(
            status,
            CommitmentLivenessStatus::Suspended {
                consecutive_hits: 0
            }
        );
    }

    #[test]
    fn test_schedule_windows_elapsed() {
        let schedule = CommitmentSchedule {
            subgrove_key: "app:sub".to_string(),
            provider_did: "did:test".to_string(),
            window_type: CommitmentWindowType::Blocks,
            window_size: 100,
            window_start: 50,
            committed_this_window: false,
            status: CommitmentLivenessStatus::Active,
            total_missed: 0,
            total_committed: 0,
            created_at_block: 50,
        };

        assert_eq!(schedule.windows_elapsed(50), 0); // At start
        assert_eq!(schedule.windows_elapsed(149), 0); // Still in first window
        assert_eq!(schedule.windows_elapsed(150), 1); // One window elapsed
        assert_eq!(schedule.windows_elapsed(349), 2); // Two windows elapsed
        assert_eq!(schedule.windows_elapsed(350), 3); // Three windows elapsed
    }
}
