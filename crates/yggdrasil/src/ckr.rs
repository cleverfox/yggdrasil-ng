use std::net::IpAddr;

use ipnet::IpNet;
use route_manager::RouteManager;

use crate::address::{is_valid_address, is_valid_subnet};
use crate::config::TunnelRoutingConfig;

/// A single CKR route: CIDR prefix -> destination public key.
struct Route {
    prefix: IpNet,
    destination: [u8; 32],
}

/// CKR routing table. Maps IP subnets to Yggdrasil node public keys.
pub struct CryptoKey {
    yggdrasil_routing: bool,
    v4_routes: Vec<Route>,
    v6_routes: Vec<Route>,
}

impl CryptoKey {
    /// Build a CKR routing table from configuration.
    pub fn new(config: &TunnelRoutingConfig) -> Result<Self, String> {
        let mut v4_routes = Vec::new();
        let mut v6_routes = Vec::new();

        if !config.enable {
            return Ok(Self {
                yggdrasil_routing: config.yggdrasil_routing,
                v4_routes,
                v6_routes,
            });
        }

        for (pubkey_hex, cidrs) in &config.remote_subnets {
            let dest = parse_pubkey(pubkey_hex)?;
            for cidr in cidrs {
                let prefix: IpNet = cidr
                    .parse()
                    .map_err(|e| format!("invalid CIDR '{}': {}", cidr, e))?;

                match prefix {
                    IpNet::V6(_) => {
                        if is_yggdrasil_destination(prefix.addr()) {
                            return Err(format!(
                                "can't specify Yggdrasil destination as routed subnet: {}",
                                cidr
                            ));
                        }
                        if v6_routes.iter().any(|r| r.prefix == prefix) {
                            return Err(format!("duplicate remote subnet: {}", cidr));
                        }
                        v6_routes.push(Route {
                            prefix,
                            destination: dest,
                        });
                    }
                    IpNet::V4(_) => {
                        if v4_routes.iter().any(|r| r.prefix == prefix) {
                            return Err(format!("duplicate remote subnet: {}", cidr));
                        }
                        v4_routes.push(Route {
                            prefix,
                            destination: dest,
                        });
                    }
                }
            }
        }

        // Sort: most specific (longest prefix) first; ties broken by address.
        v4_routes.sort_by(sort_routes);
        v6_routes.sort_by(sort_routes);

        if !v6_routes.is_empty() {
            tracing::info!("Active CKR IPv6 routes:");
            for r in &v6_routes {
                tracing::info!("  {} via {}", r.prefix, hex::encode(r.destination));
            }
        }
        if !v4_routes.is_empty() {
            tracing::info!("Active CKR IPv4 routes:");
            for r in &v4_routes {
                tracing::info!("  {} via {}", r.prefix, hex::encode(r.destination));
            }
        }

        Ok(Self {
            yggdrasil_routing: config.yggdrasil_routing,
            v4_routes,
            v6_routes,
        })
    }

    /// Whether standard Yggdrasil address routing is enabled.
    pub fn yggdrasil_routing(&self) -> bool {
        self.yggdrasil_routing
    }

    /// Look up the destination public key for an IP address using
    /// longest-prefix-match. Returns `None` if no route matches.
    pub fn get_public_key_for_address(&self, addr: IpAddr) -> Option<[u8; 32]> {
        if let IpAddr::V6(_) = addr {
            if is_yggdrasil_destination(addr) {
                return None;
            }
        }

        let routes = match addr {
            IpAddr::V4(_) => &self.v4_routes,
            IpAddr::V6(_) => &self.v6_routes,
        };

        // Routes are sorted most-specific-first, so first match wins.
        for route in routes {
            if route.prefix.contains(&addr) {
                return Some(route.destination);
            }
        }

        None
    }
}

/// Check if an IP address falls within the Yggdrasil address space.
pub fn is_yggdrasil_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => false,
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let mut addr_bytes = [0u8; 16];
            addr_bytes.copy_from_slice(&octets);
            let mut subnet_bytes = [0u8; 8];
            subnet_bytes.copy_from_slice(&octets[..8]);
            is_valid_address(&addr_bytes) || is_valid_subnet(&subnet_bytes)
        }
    }
}

fn parse_pubkey(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes =
        hex::decode(hex_str).map_err(|e| format!("invalid public key hex '{}': {}", hex_str, e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "public key should be 32 bytes, got {} for '{}'",
            bytes.len(),
            hex_str
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Install system routes for all configured CKR subnets, pointing them
/// at the TUN interface so the OS sends that traffic into the tunnel.
/// Works on Linux, Windows, and macOS.
pub fn install_routes(config: &TunnelRoutingConfig, tun_name: &str) -> Result<(), String> {
    if !config.enable {
        return Ok(());
    }

    // Collect all unique CIDRs from the config
    let mut cidrs: Vec<IpNet> = Vec::new();
    for subnet_list in config.remote_subnets.values() {
        for cidr_str in subnet_list {
            let prefix: IpNet = cidr_str
                .parse()
                .map_err(|e| format!("invalid CIDR '{}': {}", cidr_str, e))?;
            if !cidrs.contains(&prefix) {
                cidrs.push(prefix);
            }
        }
    }

    if cidrs.is_empty() {
        return Ok(());
    }

    let mut manager =
        RouteManager::new().map_err(|e| format!("failed to create route manager: {}", e))?;

    for cidr in &cidrs {
        let route = route_manager::Route::new(cidr.network(), cidr.prefix_len())
            .with_if_name(tun_name.to_string());

        match manager.add(&route) {
            Ok(()) => {
                tracing::info!("Installed route: {} via {}", cidr, tun_name);
            }
            Err(e) => {
                tracing::warn!("Failed to install route {} via {}: {}", cidr, tun_name, e);
            }
        }
    }

    Ok(())
}

/// Remove previously installed CKR routes from the system routing table.
pub fn remove_routes(config: &TunnelRoutingConfig, tun_name: &str) {
    if !config.enable {
        return;
    }

    let mut cidrs: Vec<IpNet> = Vec::new();
    for subnet_list in config.remote_subnets.values() {
        for cidr_str in subnet_list {
            if let Ok(prefix) = cidr_str.parse::<IpNet>() {
                if !cidrs.contains(&prefix) {
                    cidrs.push(prefix);
                }
            }
        }
    }

    let mut manager = match RouteManager::new() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("Failed to create route manager for cleanup: {}", e);
            return;
        }
    };

    for cidr in &cidrs {
        let route = route_manager::Route::new(cidr.network(), cidr.prefix_len())
            .with_if_name(tun_name.to_string());
        if let Err(e) = manager.delete(&route) {
            tracing::debug!("Failed to remove route {}: {}", cidr, e);
        }
    }
}

/// Sort routes: longest prefix first, then by address for ties.
fn sort_routes(a: &Route, b: &Route) -> std::cmp::Ordering {
    let bits_a = a.prefix.prefix_len();
    let bits_b = b.prefix.prefix_len();
    // Reverse: longer prefix = higher priority = comes first
    match bits_b.cmp(&bits_a) {
        std::cmp::Ordering::Equal => a.prefix.addr().cmp(&b.prefix.addr()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_config(subnets: HashMap<String, Vec<String>>) -> TunnelRoutingConfig {
        TunnelRoutingConfig {
            enable: true,
            yggdrasil_routing: true,
            ipv4_address: String::new(),
            remote_subnets: subnets,
        }
    }

    fn dummy_key_hex() -> String {
        hex::encode([0x01u8; 32])
    }

    fn other_key_hex() -> String {
        hex::encode([0x02u8; 32])
    }

    #[test]
    fn test_empty_config() {
        let config = TunnelRoutingConfig::default();
        let ckr = CryptoKey::new(&config).unwrap();
        assert!(ckr.v4_routes.is_empty());
        assert!(ckr.v6_routes.is_empty());
    }

    #[test]
    fn test_disabled_config() {
        let mut subnets = HashMap::new();
        subnets.insert(dummy_key_hex(), vec!["10.0.0.0/24".to_string()]);
        let config = TunnelRoutingConfig {
            enable: false,
            yggdrasil_routing: true,
            ipv4_address: String::new(),
            remote_subnets: subnets,
        };
        let ckr = CryptoKey::new(&config).unwrap();
        assert!(ckr.v4_routes.is_empty());
    }

    #[test]
    fn test_ipv4_route_lookup() {
        let mut subnets = HashMap::new();
        subnets.insert(dummy_key_hex(), vec!["10.0.0.0/24".to_string()]);
        let ckr = CryptoKey::new(&make_config(subnets)).unwrap();

        let addr: IpAddr = "10.0.0.5".parse().unwrap();
        let key = ckr.get_public_key_for_address(addr);
        assert_eq!(key, Some([0x01u8; 32]));

        let miss: IpAddr = "192.168.0.1".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(miss), None);
    }

    #[test]
    fn test_ipv6_route_lookup() {
        let mut subnets = HashMap::new();
        subnets.insert(
            dummy_key_hex(),
            vec!["2001:db8::/32".to_string()],
        );
        let ckr = CryptoKey::new(&make_config(subnets)).unwrap();

        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(addr), Some([0x01u8; 32]));

        let miss: IpAddr = "2001:db9::1".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(miss), None);
    }

    #[test]
    fn test_longest_prefix_match() {
        let mut subnets = HashMap::new();
        subnets.insert(dummy_key_hex(), vec!["10.0.0.0/24".to_string()]);
        subnets.insert(other_key_hex(), vec!["10.0.0.0/25".to_string()]);
        let ckr = CryptoKey::new(&make_config(subnets)).unwrap();

        // 10.0.0.5 matches both /24 and /25, but /25 is more specific
        let addr: IpAddr = "10.0.0.5".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(addr), Some([0x02u8; 32]));

        // 10.0.0.200 only matches /24 (not in /25 range 10.0.0.0-127)
        let addr2: IpAddr = "10.0.0.200".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(addr2), Some([0x01u8; 32]));
    }

    #[test]
    fn test_yggdrasil_destination_rejected() {
        let mut subnets = HashMap::new();
        // 0200::/7 is Yggdrasil address space
        subnets.insert(dummy_key_hex(), vec!["200::/7".to_string()]);
        let result = CryptoKey::new(&make_config(subnets));
        assert!(result.is_err());
    }

    #[test]
    fn test_yggdrasil_address_lookup_returns_none() {
        let mut subnets = HashMap::new();
        subnets.insert(
            dummy_key_hex(),
            vec!["2001:db8::/32".to_string()],
        );
        let ckr = CryptoKey::new(&make_config(subnets)).unwrap();

        // A Yggdrasil address should return None even if it somehow matched
        let ygg_addr: IpAddr = "200::1".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(ygg_addr), None);
    }

    #[test]
    fn test_duplicate_route_rejected() {
        let mut subnets = HashMap::new();
        subnets.insert(
            dummy_key_hex(),
            vec!["10.0.0.0/24".to_string(), "10.0.0.0/24".to_string()],
        );
        let result = CryptoKey::new(&make_config(subnets));
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_cidr_rejected() {
        let mut subnets = HashMap::new();
        subnets.insert(dummy_key_hex(), vec!["not-a-cidr".to_string()]);
        let result = CryptoKey::new(&make_config(subnets));
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_pubkey_rejected() {
        let mut subnets = HashMap::new();
        subnets.insert("not-hex".to_string(), vec!["10.0.0.0/24".to_string()]);
        let result = CryptoKey::new(&make_config(subnets));
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_length_pubkey_rejected() {
        let mut subnets = HashMap::new();
        subnets.insert(
            hex::encode([0x01u8; 16]), // 16 bytes, not 32
            vec!["10.0.0.0/24".to_string()],
        );
        let result = CryptoKey::new(&make_config(subnets));
        assert!(result.is_err());
    }

    #[test]
    fn test_is_yggdrasil_destination() {
        // Yggdrasil addresses start with 0x02
        assert!(is_yggdrasil_destination("200::1".parse().unwrap()));
        // Yggdrasil subnets start with 0x03
        assert!(is_yggdrasil_destination("300::1".parse().unwrap()));
        // Regular IPv6
        assert!(!is_yggdrasil_destination("2001:db8::1".parse().unwrap()));
        // IPv4 is never Yggdrasil
        assert!(!is_yggdrasil_destination("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_multiple_subnets_per_key() {
        let mut subnets = HashMap::new();
        subnets.insert(
            dummy_key_hex(),
            vec![
                "10.0.0.0/24".to_string(),
                "192.168.1.0/24".to_string(),
                "2001:db8::/32".to_string(),
            ],
        );
        let ckr = CryptoKey::new(&make_config(subnets)).unwrap();

        assert_eq!(ckr.v4_routes.len(), 2);
        assert_eq!(ckr.v6_routes.len(), 1);

        assert!(ckr.get_public_key_for_address("10.0.0.1".parse().unwrap()).is_some());
        assert!(ckr.get_public_key_for_address("192.168.1.100".parse().unwrap()).is_some());
        assert!(ckr.get_public_key_for_address("2001:db8::1".parse().unwrap()).is_some());
    }

    #[test]
    fn test_route_sorting_order() {
        let mut subnets = HashMap::new();
        // Insert in non-sorted order
        subnets.insert(dummy_key_hex(), vec!["10.0.0.0/8".to_string()]);
        subnets.insert(other_key_hex(), vec!["10.0.0.0/16".to_string()]);
        let ckr = CryptoKey::new(&make_config(subnets)).unwrap();

        // /16 should come before /8 (more specific first)
        assert_eq!(ckr.v4_routes[0].prefix.prefix_len(), 16);
        assert_eq!(ckr.v4_routes[1].prefix.prefix_len(), 8);
    }
}
