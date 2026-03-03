//! Waku network configuration.
//!
//! Defines configuration for the Waku network including relay settings,
//! store protocol, filter protocol, and topic configuration.

use serde::{Deserialize, Serialize};
use std::time::Duration;

fn default_listen_addr() -> String {
    "0.0.0.0:7000".to_string()
}

/// Waku network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WakuConfig {
    /// Network ID to isolate from public Waku network.
    pub network_id: u32,
    /// Protocol ID prefix for Willow-specific Waku.
    pub protocol_id: String,
    /// Listen address (e.g., "0.0.0.0:7000").
    pub listen_addr: String,
    /// Enable Waku Store protocol for message persistence.
    pub enable_store: bool,
    /// Maximum messages to store per topic.
    pub store_capacity: usize,
    /// Message retention duration.
    pub store_retention: Duration,
    /// Enable Waku Filter protocol for light nodes.
    pub enable_filter: bool,
    /// Enable Waku Lightpush for resource-constrained nodes.
    pub enable_lightpush: bool,
    /// Relay protocol configuration.
    pub relay_config: RelayConfig,
    /// Topics configuration.
    pub topics: TopicsConfig,
}

/// GossipSub relay protocol configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Maximum message size in bytes.
    pub max_message_size: usize,
    /// Default TTL for messages.
    pub default_ttl: Duration,
    /// Enable message validation.
    pub enable_validation: bool,
    /// GossipSub D parameter (desired peers per topic).
    pub d: usize,
    /// GossipSub D_low parameter.
    pub d_low: usize,
    /// GossipSub D_high parameter.
    pub d_high: usize,
    /// Heartbeat interval.
    pub heartbeat_interval: Duration,
}

/// Willow topic configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicsConfig {
    /// Bridge coordination topic.
    pub bridge_topic: String,
    /// State sync topic.
    pub state_sync_topic: String,
    /// Validator metrics topic.
    pub metrics_topic: String,
    /// Validator status topic.
    pub status_topic: String,
}

impl Default for WakuConfig {
    fn default() -> Self {
        Self {
            network_id: 99999, // Willow-specific network ID
            protocol_id: "/willow-waku/2.0.0".to_string(),
            listen_addr: default_listen_addr(),
            enable_store: true,
            store_capacity: 10000,
            store_retention: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            enable_filter: true,
            enable_lightpush: true,
            relay_config: RelayConfig::default(),
            topics: TopicsConfig::default(),
        }
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_message_size: 1024 * 1024, // 1MB
            default_ttl: Duration::from_secs(60),
            enable_validation: true,
            d: 6,
            d_low: 4,
            d_high: 12,
            heartbeat_interval: Duration::from_secs(1),
        }
    }
}

impl Default for TopicsConfig {
    fn default() -> Self {
        Self {
            bridge_topic: "/willow/1/bridge/proto".to_string(),
            state_sync_topic: "/willow/1/state-sync/proto".to_string(),
            metrics_topic: "/willow/1/metrics/proto".to_string(),
            status_topic: "/willow/1/status/proto".to_string(),
        }
    }
}
