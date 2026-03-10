//! Token unit constants and conversion utilities for the WILL token.
//!
//! The WILL token uses 18 decimal places (like Ethereum), meaning:
//! - 1 WILL = 1_000_000_000_000_000_000 wei (10^18)
//! - 0.001 WILL = 1_000_000_000_000_000 wei (10^15)
//!
//! This module provides constants and helper functions to avoid magic numbers
//! throughout the codebase.
//!
//! # Examples
//!
//! ```
//! use willow_types::token::units::*;
//!
//! // Use constants
//! let stake = 100 * ONE_KILO_WILL; // 100,000 WILL
//! let fee = ONE_MILLI_WILL; // 0.001 WILL
//!
//! // Use conversion functions
//! let amount = will(1000); // 1000 WILL in wei
//! let small_fee = milli_will(5); // 0.005 WILL in wei
//! ```

/// 1 WILL in wei (10^18)
pub const ONE_WILL: u128 = 1_000_000_000_000_000_000;

/// 1 milli-WILL (0.001 WILL) in wei (10^15)
pub const ONE_MILLI_WILL: u128 = 1_000_000_000_000_000;

/// 1 micro-WILL (0.000001 WILL) in wei (10^12)
pub const ONE_MICRO_WILL: u128 = 1_000_000_000_000;

/// 1 kilo-WILL (1,000 WILL) in wei (10^21)
pub const ONE_KILO_WILL: u128 = 1_000_000_000_000_000_000_000;

/// 1 mega-WILL (1,000,000 WILL) in wei (10^24)
pub const ONE_MEGA_WILL: u128 = 1_000_000_000_000_000_000_000_000;

/// Number of decimal places for WILL token
pub const WILL_DECIMALS: u8 = 18;

// ============================================================================
// Common stake amounts
// ============================================================================

/// Minimum indexer stake: 10,000 WILL
pub const MIN_INDEXER_STAKE: u128 = 10 * ONE_KILO_WILL;

/// Minimum validator stake: 100,000 WILL
pub const MIN_VALIDATOR_STAKE: u128 = 100 * ONE_KILO_WILL;

// ============================================================================
// Slashing constants
// ============================================================================

/// Fixed slash for validator double signing: 50,000 WILL (50% of fixed stake).
/// Double signing risks chain forks; severe but not full forfeiture since it
/// can happen from accidental misconfiguration.
pub const DOUBLE_SIGN_SLASH_AMOUNT: u128 = 50 * ONE_KILO_WILL;

// --- Indexer slashing: fixed amounts per violation ---

/// Operational: indexer unavailability (500 WILL per incident)
pub const SLASH_UNAVAILABILITY: u128 = 500 * ONE_WILL;

/// Operational: missed commitment window (500 WILL per incident)
pub const SLASH_COMMITMENT_LIVENESS: u128 = 500 * ONE_WILL;

/// Fraud: invalid Ethereum event proof (5,000 WILL)
pub const SLASH_INVALID_EVENT_PROOF: u128 = 5 * ONE_KILO_WILL;

/// Fraud: incorrect state computation (5,000 WILL)
pub const SLASH_INCORRECT_STATE: u128 = 5 * ONE_KILO_WILL;

/// Fraud: commitment integrity violation (5,000 WILL)
pub const SLASH_COMMITMENT_INTEGRITY: u128 = 5 * ONE_KILO_WILL;

/// Fraud: malicious behavior (10,000 WILL — full min indexer stake)
pub const SLASH_MALICIOUS_BEHAVIOR: u128 = 10 * ONE_KILO_WILL;

// ============================================================================
// Common fee amounts
// ============================================================================

/// Default epoch length in blocks.
pub const DEFAULT_EPOCH_LENGTH: u64 = 100;

/// Default reward per epoch per indexer: 0.1 WILL
pub const DEFAULT_REWARD_PER_EPOCH: u128 = 100 * ONE_MILLI_WILL;

/// Base re-execution fee: base_tx_cost + REEXECUTION_ESTIMATED_BYTES × cost_per_byte
/// = 24_000_000_000_000_000 + 1200 × 86_400_000_000_000 = 127_680_000_000_000_000
pub const BASE_REEXECUTION_FEE: u128 = 24_000_000_000_000_000 + 1200 * 86_400_000_000_000;

/// App registration fee: 1,000 WILL
pub const APP_REGISTRATION_FEE: u128 = ONE_KILO_WILL;

/// Subgrove deployment fee: 5,000 WILL
pub const SUBGROVE_DEPLOYMENT_FEE: u128 = 5 * ONE_KILO_WILL;

/// Minimum fee per query: 0.001 WILL
pub const MIN_FEE_PER_QUERY: u128 = ONE_MILLI_WILL;

/// Maximum fee per query: 1 WILL
pub const MAX_FEE_PER_QUERY: u128 = ONE_WILL;

// ============================================================================
// Conversion functions
// ============================================================================

/// Convert whole WILL tokens to wei.
///
/// # Examples
/// ```
/// use willow_types::token::units::will;
/// assert_eq!(will(1), 1_000_000_000_000_000_000);
/// assert_eq!(will(100), 100_000_000_000_000_000_000);
/// ```
#[inline]
pub const fn will(amount: u128) -> u128 {
    amount * ONE_WILL
}

/// Convert kilo-WILL (thousands) to wei.
///
/// # Examples
/// ```
/// use willow_types::token::units::kilo_will;
/// assert_eq!(kilo_will(1), 1_000_000_000_000_000_000_000); // 1,000 WILL
/// assert_eq!(kilo_will(100), 100_000_000_000_000_000_000_000); // 100,000 WILL
/// ```
#[inline]
pub const fn kilo_will(amount: u128) -> u128 {
    amount * ONE_KILO_WILL
}

/// Convert milli-WILL (thousandths) to wei.
///
/// # Examples
/// ```
/// use willow_types::token::units::milli_will;
/// assert_eq!(milli_will(1), 1_000_000_000_000_000); // 0.001 WILL
/// assert_eq!(milli_will(500), 500_000_000_000_000_000); // 0.5 WILL
/// ```
#[inline]
pub const fn milli_will(amount: u128) -> u128 {
    amount * ONE_MILLI_WILL
}

/// Convert micro-WILL (millionths) to wei.
///
/// # Examples
/// ```
/// use willow_types::token::units::micro_will;
/// assert_eq!(micro_will(1), 1_000_000_000_000); // 0.000001 WILL
/// ```
#[inline]
pub const fn micro_will(amount: u128) -> u128 {
    amount * ONE_MICRO_WILL
}

/// Convert wei to WILL (integer division, loses precision).
///
/// For display purposes, use `format_will` instead.
#[inline]
pub const fn wei_to_will(wei: u128) -> u128 {
    wei / ONE_WILL
}

/// Format a wei amount as a human-readable WILL string.
///
/// # Examples
/// ```
/// use willow_types::token::units::format_will;
/// assert_eq!(format_will(1_500_000_000_000_000_000), "1.500000000000000000 WILL");
/// assert_eq!(format_will(1_000_000_000_000_000), "0.001000000000000000 WILL");
/// ```
pub fn format_will(wei: u128) -> String {
    let whole = wei / ONE_WILL;
    let fraction = wei % ONE_WILL;
    format!("{}.{:018} WILL", whole, fraction)
}

/// Format a wei amount as a compact human-readable string (max 6 decimal places).
///
/// # Examples
/// ```
/// use willow_types::token::units::format_will_compact;
/// assert_eq!(format_will_compact(1_500_000_000_000_000_000), "1.5 WILL");
/// assert_eq!(format_will_compact(1_000_000_000_000_000), "0.001 WILL");
/// assert_eq!(format_will_compact(1_234_567_890_000_000_000), "1.234567 WILL");
/// ```
pub fn format_will_compact(wei: u128) -> String {
    let whole = wei / ONE_WILL;
    let fraction = wei % ONE_WILL;

    if fraction == 0 {
        format!("{} WILL", whole)
    } else {
        // Convert to string and trim trailing zeros
        let fraction_str = format!("{:018}", fraction);
        let trimmed = fraction_str.trim_end_matches('0');
        // Limit to 6 decimal places for readability
        let display = if trimmed.len() > 6 {
            &trimmed[..6]
        } else {
            trimmed
        };
        format!("{}.{} WILL", whole, display)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(ONE_WILL, 1_000_000_000_000_000_000);
        assert_eq!(ONE_MILLI_WILL, 1_000_000_000_000_000);
        assert_eq!(ONE_KILO_WILL, 1_000_000_000_000_000_000_000);
        assert_eq!(ONE_MEGA_WILL, 1_000_000_000_000_000_000_000_000);
    }

    #[test]
    fn test_will_conversion() {
        assert_eq!(will(1), ONE_WILL);
        assert_eq!(will(1000), 1000 * ONE_WILL);
        assert_eq!(will(0), 0);
    }

    #[test]
    fn test_kilo_will_conversion() {
        assert_eq!(kilo_will(1), ONE_KILO_WILL);
        assert_eq!(kilo_will(100), 100 * ONE_KILO_WILL);
        assert_eq!(kilo_will(10), MIN_INDEXER_STAKE);
    }

    #[test]
    fn test_milli_will_conversion() {
        assert_eq!(milli_will(1), ONE_MILLI_WILL);
        assert_eq!(milli_will(1000), ONE_WILL);
    }

    #[test]
    fn test_wei_to_will() {
        assert_eq!(wei_to_will(ONE_WILL), 1);
        assert_eq!(wei_to_will(ONE_KILO_WILL), 1000);
        assert_eq!(wei_to_will(ONE_MILLI_WILL), 0); // Truncates
    }

    #[test]
    fn test_format_will() {
        assert_eq!(format_will(ONE_WILL), "1.000000000000000000 WILL");
        assert_eq!(format_will(ONE_MILLI_WILL), "0.001000000000000000 WILL");
    }

    #[test]
    fn test_format_will_compact() {
        assert_eq!(format_will_compact(ONE_WILL), "1 WILL");
        assert_eq!(format_will_compact(ONE_MILLI_WILL), "0.001 WILL");
        assert_eq!(format_will_compact(1_500_000_000_000_000_000), "1.5 WILL");
        assert_eq!(format_will_compact(ONE_KILO_WILL), "1000 WILL");
    }

    #[test]
    fn test_stake_constants() {
        assert_eq!(MIN_INDEXER_STAKE, kilo_will(10));
        assert_eq!(MIN_VALIDATOR_STAKE, kilo_will(100));
    }
}
