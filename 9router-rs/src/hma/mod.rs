pub mod bridge;
pub mod client;
pub mod manager;
pub mod tunnel;
pub mod wrangler;

use serde::{Deserialize, Deserializer, Serialize};
use std::net::Ipv4Addr;

/// Deserializes a JSON port field that may be null, a single integer, or an array of integers.
pub fn deserialize_port_list<'de, D>(deserializer: D) -> Result<Vec<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(u16),
        Many(Vec<u16>),
    }
    match Option::<OneOrMany>::deserialize(deserializer)? {
        None => Ok(Vec::new()),
        Some(OneOrMany::One(p)) => Ok(vec![p]),
        Some(OneOrMany::Many(v)) => Ok(v),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HmaGeoCity {
    pub location_city: String,
    pub location_key: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HmaGeoCountry {
    pub country_code: String,
    pub country: String,
    pub location_key: String,
    pub state: String,
    #[serde(default)]
    pub cities: Vec<HmaGeoCity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HmaWireGuardInfo {
    pub public_key: String,
    #[serde(default, deserialize_with = "deserialize_port_list")]
    pub wrangler_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HmaServer {
    pub ip: String,
    pub wireguard: Option<HmaWireGuardInfo>,
}

#[derive(Debug, Clone)]
pub struct WranglerResult {
    pub server_ip: Ipv4Addr,
    pub server_public_key: [u8; 32],
    pub client_private_key: [u8; 32],
    pub client_ip: Ipv4Addr,
    pub dns: Ipv4Addr,
    pub wg_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelState {
    Disconnected,
    Bootstrapping,
    Connected,
    Draining,
    Reconnecting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelMetrics {
    pub state: TunnelState,
    pub server_ip: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub location_key: Option<String>,
    pub exit_ip: Option<String>,
    pub last_handshake_age_secs: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub dropped_packets: u64,
    pub active_sockets: usize,
    pub dns_latency_ms: Option<u64>,
    pub dns_errors: u64,
}

impl Default for TunnelMetrics {
    fn default() -> Self {
        Self {
            state: TunnelState::Disconnected,
            server_ip: None,
            country: None,
            city: None,
            location_key: None,
            exit_ip: None,
            last_handshake_age_secs: None,
            tx_bytes: 0,
            rx_bytes: 0,
            dropped_packets: 0,
            active_sockets: 0,
            dns_latency_ms: None,
            dns_errors: 0,
        }
    }
}
