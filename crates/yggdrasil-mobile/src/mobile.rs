//! Mobile FFI layer for Yggdrasil-ng.
//!
//! Exposes a UniFFI-compatible API that bridges the async Rust Core
//! with synchronous Android/iOS threads.

use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use tokio::sync::{broadcast, watch};

use yggdrasil::address::addr_for_key;
use yggdrasil::config;
use yggdrasil::core::Core;
use yggdrasil::ipv6rwc::ReadWriteCloser;
use yggdrasil::multicast::NetworkInterface;

// ── Tracing initialisation ──────────────────────────────────────────────────

fn init_tracing() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        use tracing_subscriber::EnvFilter;

        let env_filter =
            EnvFilter::new("ironwood=info,yggdrasil=info,yggdrasil_mobile=info,info");

        #[cfg(target_os = "android")]
        {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_android::layer("Yggdrasil").unwrap())
                .init();
        }
        #[cfg(not(target_os = "android"))]
        {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer())
                .init();
        }
    });
}

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum YggdrasilError {
    #[error("Config: {0}")]
    Config(String),
    #[error("Runtime: {0}")]
    Runtime(String),
    #[error("Io: {0}")]
    Io(String),
}

// ── UDL types ───────────────────────────────────────────────────────────────

pub struct MulticastInterfaceConfig {
    pub filter: String,
    pub beacon: bool,
    pub listen: bool,
    pub port: u16,
    pub priority: u8,
    pub password: String,
}

pub struct YggdrasilConfig {
    pub private_key: String,
    pub peers: Vec<String>,
    pub listen: Vec<String>,
    pub if_mtu: u64,
    pub multicast_interfaces: Vec<MulticastInterfaceConfig>,
    pub node_info_name: String,
    pub tunnel_routing: TunnelRoutingConfig,
}

pub struct CkrRemoteSubnet {
    pub public_key: String,
    pub cidrs: Vec<String>,
}

pub struct TunnelRoutingConfig {
    pub enable: bool,
    pub ipv4_address: String,
    pub remote_subnets: Vec<CkrRemoteSubnet>,
}

pub struct YggdrasilState {
    pub address: String,
    pub subnet: String,
    pub public_key: String,
    pub routing_entries: i64,
    pub peers_json: String,
    pub tree_json: String,
}

pub struct AndroidNetworkInterface {
    pub name: String,
    pub index: u32,
    pub addrs: Vec<String>,
}

pub trait YggdrasilStateListener: Send + Sync {
    fn on_connectivity_changed(&self, is_online: bool);
}

// ── Config conversion ───────────────────────────────────────────────────────

fn convert_config(cfg: &YggdrasilConfig) -> config::Config {
    let mut node_info = toml::map::Map::new();
    if !cfg.node_info_name.is_empty() {
        node_info.insert(
            "name".to_string(),
            toml::Value::String(cfg.node_info_name.clone()),
        );
    }

    let remote_subnets: std::collections::HashMap<String, Vec<String>> = cfg
        .tunnel_routing
        .remote_subnets
        .iter()
        .map(|r| (r.public_key.clone(), r.cidrs.clone()))
        .collect();

    config::Config {
        private_key: cfg.private_key.clone(),
        peers: cfg.peers.clone(),
        listen: cfg.listen.clone(),
        admin_listen: "none".to_string(),
        if_name: "none".to_string(),
        if_mtu: cfg.if_mtu,
        node_info: toml::Value::Table(node_info),
        node_info_privacy: false,
        allowed_public_keys: Vec::new(),
        multicast_interfaces: cfg
            .multicast_interfaces
            .iter()
            .map(|m| config::MulticastInterfaceConfig {
                filter: m.filter.clone(),
                beacon: m.beacon,
                listen: m.listen,
                port: m.port,
                priority: m.priority,
                password: m.password.clone(),
            })
            .collect(),
        tunnel_routing: config::TunnelRoutingConfig {
            enable: cfg.tunnel_routing.enable,
            // ckrYggdrasilRouting is always on for the Android app.
            yggdrasil_routing: true,
            ipv4_address: cfg.tunnel_routing.ipv4_address.clone(),
            remote_subnets,
            // Android's VpnService owns system routing; never let the core
            // try to install OS routes from the unprivileged app process.
            install_system_routes: false,
        },
    }
}

fn config_to_udl(cfg: &config::Config) -> YggdrasilConfig {
    let node_info_name = cfg
        .node_info
        .as_table()
        .and_then(|t| t.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    YggdrasilConfig {
        private_key: cfg.private_key.clone(),
        peers: cfg.peers.clone(),
        listen: cfg.listen.clone(),
        if_mtu: cfg.if_mtu,
        multicast_interfaces: cfg
            .multicast_interfaces
            .iter()
            .map(|m| MulticastInterfaceConfig {
                filter: m.filter.clone(),
                beacon: m.beacon,
                listen: m.listen,
                port: m.port,
                priority: m.priority,
                password: m.password.clone(),
            })
            .collect(),
        node_info_name,
        tunnel_routing: TunnelRoutingConfig {
            enable: false,
            ipv4_address: String::new(),
            remote_subnets: Vec::new(),
        },
    }
}

// ── Namespace functions ─────────────────────────────────────────────────────

pub fn generate_config() -> YggdrasilConfig {
    let cfg = config::Config::generate();
    config_to_udl(&cfg)
}

pub fn expand_ckr_cidrs(config: TunnelRoutingConfig) -> Vec<String> {
    if !config.enable {
        return Vec::new();
    }
    let mut out = Vec::new();
    for subnet in &config.remote_subnets {
        match yggdrasil::ckr::expand_cidrs(&subnet.cidrs) {
            Ok(prefixes) => {
                for p in prefixes {
                    let s = p.to_string();
                    if !out.contains(&s) {
                        out.push(s);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("expand_ckr_cidrs: {}", e);
            }
        }
    }
    out
}

pub fn get_version() -> String {
    format!(
        "{}.{}",
        yggdrasil::version::PROTOCOL_VERSION_MAJOR,
        yggdrasil::version::PROTOCOL_VERSION_MINOR,
    )
}

// ── Internal state ──────────────────────────────────────────────────────────

struct NodeState {
    core: Arc<Core>,
    rwc: Arc<ReadWriteCloser>,
    stop_tx: broadcast::Sender<()>,
}

// ── YggdrasilMobile ─────────────────────────────────────────────────────────

pub struct YggdrasilMobile {
    rt: Arc<tokio::runtime::Runtime>,
    state: Mutex<Option<NodeState>>,
    listener: Arc<dyn YggdrasilStateListener>,
    state_notify: watch::Sender<()>,
    state_rx: Mutex<watch::Receiver<()>>,
}

impl YggdrasilMobile {
    pub fn new(listener: Box<dyn YggdrasilStateListener>) -> Result<Self, YggdrasilError> {
        init_tracing();

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| YggdrasilError::Runtime(e.to_string()))?;

        let (state_notify, state_rx) = watch::channel(());

        Ok(Self {
            rt: Arc::new(rt),
            state: Mutex::new(None),
            listener: Arc::from(listener),
            state_notify,
            state_rx: Mutex::new(state_rx),
        })
    }

    pub fn start(&self, config: YggdrasilConfig) -> Result<(), YggdrasilError> {
        let rust_config = convert_config(&config);
        let signing_key = rust_config
            .signing_key()
            .map_err(|e| YggdrasilError::Config(e))?;

        let ckr_cfg = rust_config.tunnel_routing.clone();

        let core = self.rt.block_on(async {
            let core = Core::new(signing_key, rust_config);
            core.init_links().await;
            core.start().await;
            core
        });

        let rwc = ReadWriteCloser::new(core.clone(), core.mtu(), Some(&ckr_cfg));
        core.set_path_notify(rwc.clone());

        let (stop_tx, _) = broadcast::channel(1);

        // Spawn peer-event monitor
        {
            let cb = Arc::clone(&self.listener);
            let core_ref = Arc::clone(&core);
            let notify = self.state_notify.clone();
            let mut peer_rx = core.subscribe_peer_events();
            let mut stop_rx = stop_tx.subscribe();

            self.rt.spawn(async move {
                let mut is_online = false;
                loop {
                    tokio::select! {
                        _ = stop_rx.recv() => break,
                        result = peer_rx.recv() => {
                            match result {
                                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {
                                    let peers = core_ref.get_peers().await;
                                    let now_online = peers.iter().any(|p| p.up);
                                    if now_online != is_online {
                                        is_online = now_online;
                                        cb.on_connectivity_changed(now_online);
                                    }
                                    let _ = notify.send(());
                                }
                                Err(broadcast::error::RecvError::Closed) => break,
                            }
                        }
                    }
                }
            });
        }

        let mut guard = self.state.lock().unwrap();
        *guard = Some(NodeState {
            core,
            rwc,
            stop_tx,
        });

        Ok(())
    }

    pub fn recv_buffer(&self) -> Result<Vec<u8>, YggdrasilError> {
        let rwc = {
            let guard = self.state.lock().unwrap();
            guard
                .as_ref()
                .map(|s| Arc::clone(&s.rwc))
                .ok_or_else(|| YggdrasilError::Runtime("node not started".to_string()))?
        };

        let mut buf = vec![0u8; 65535];
        let n = self
            .rt
            .block_on(rwc.read(&mut buf))
            .map_err(|e| YggdrasilError::Io(e))?;

        buf.truncate(n);
        Ok(buf)
    }

    pub fn send_buffer(&self, buf: Vec<u8>) -> Result<(), YggdrasilError> {
        let rwc = {
            let guard = self.state.lock().unwrap();
            guard
                .as_ref()
                .map(|s| Arc::clone(&s.rwc))
                .ok_or_else(|| YggdrasilError::Runtime("node not started".to_string()))?
        };

        // Silently ignore write errors — the TUN sends all traffic through us,
        // including non-Yggdrasil packets that the RWC rightly rejects.
        // This matches the Go behavior: `_, _ = m.iprwc.Write(p[:length])`.
        let _ = self.rt.block_on(rwc.write(&buf));

        Ok(())
    }

    pub fn stop(&self) -> Result<(), YggdrasilError> {
        let node_state = {
            let mut guard = self.state.lock().unwrap();
            guard.take()
        };

        if let Some(ns) = node_state {
            let _ = ns.stop_tx.send(());
            self.rt.block_on(async {
                ns.core.close_multicast().await;
                let _ = ns.core.close().await;
            });
        }

        Ok(())
    }

    pub fn retry_peers_now(&self) {
        if let Some(ns) = self.state.lock().unwrap().as_ref() {
            let core = Arc::clone(&ns.core);
            self.rt.block_on(core.retry_peers_now());
        }
    }

    pub fn wait_for_state_update(&self, timeout_ms: u64) -> YggdrasilState {
        // Clone the receiver to avoid holding the Mutex across an await
        let mut rx = {
            let guard = self.state_rx.lock().unwrap();
            guard.clone()
        };

        self.rt.block_on(async {
            // Mark current value as seen, then wait for a change or timeout.
            rx.borrow_and_update();
            let _ = tokio::time::timeout(
                Duration::from_millis(timeout_ms),
                rx.changed(),
            )
            .await;
        });

        self.build_state_snapshot()
    }

    pub fn get_address_string(&self) -> String {
        self.with_core(|core| core.address().to_string())
            .unwrap_or_default()
    }

    pub fn get_subnet_string(&self) -> String {
        self.with_core(|core| core.subnet().to_string())
            .unwrap_or_default()
    }

    pub fn get_public_key_string(&self) -> String {
        self.with_core(|core| hex::encode(core.public_key()))
            .unwrap_or_default()
    }

    pub fn get_mtu(&self) -> i64 {
        self.with_core(|core| core.mtu() as i64).unwrap_or(0)
    }

    pub fn get_routing_entries(&self) -> i64 {
        let core = match self.state.lock().unwrap().as_ref() {
            Some(ns) => Arc::clone(&ns.core),
            None => return 0,
        };
        self.rt.block_on(core.routing_entries()) as i64
    }

    pub fn get_peers_json(&self) -> String {
        let core = match self.state.lock().unwrap().as_ref() {
            Some(ns) => Arc::clone(&ns.core),
            None => return "[]".to_string(),
        };
        let peers = self.rt.block_on(core.get_peers());
        peers_to_json(&peers)
    }

    pub fn get_tree_json(&self) -> String {
        let core = match self.state.lock().unwrap().as_ref() {
            Some(ns) => Arc::clone(&ns.core),
            None => return "[]".to_string(),
        };
        let tree = self.rt.block_on(core.get_tree());
        tree_to_json(&tree)
    }

    pub fn update_network_interfaces(&self, interfaces: Vec<AndroidNetworkInterface>) {
        if let Some(ns) = self.state.lock().unwrap().as_ref() {
            let ifaces: Vec<NetworkInterface> = interfaces
                .into_iter()
                .map(|i| NetworkInterface {
                    name: i.name,
                    index: i.index,
                    addrs: i
                        .addrs
                        .iter()
                        .filter_map(|a| a.parse::<Ipv6Addr>().ok())
                        .collect(),
                })
                .collect();
            ns.core.update_network_interfaces(ifaces);
        }
    }

    pub fn start_multicast(&self) {
        if let Some(ns) = self.state.lock().unwrap().as_ref() {
            let core = Arc::clone(&ns.core);
            self.rt.block_on(async {
                if let Err(e) = core.start_multicast().await {
                    tracing::warn!("Multicast peer discovery disabled: {}", e);
                }
            });
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn with_core<T>(&self, f: impl FnOnce(&Core) -> T) -> Option<T> {
        self.state.lock().unwrap().as_ref().map(|ns| f(&ns.core))
    }

    fn build_state_snapshot(&self) -> YggdrasilState {
        let core = match self.state.lock().unwrap().as_ref() {
            Some(ns) => Arc::clone(&ns.core),
            None => {
                return YggdrasilState {
                    address: String::new(),
                    subnet: String::new(),
                    public_key: String::new(),
                    routing_entries: 0,
                    peers_json: "[]".to_string(),
                    tree_json: "[]".to_string(),
                }
            }
        };

        let (routing_entries, peers, tree) = self.rt.block_on(async {
            let re = core.routing_entries().await;
            let peers = core.get_peers().await;
            let tree = core.get_tree().await;
            (re, peers, tree)
        });

        YggdrasilState {
            address: core.address().to_string(),
            subnet: core.subnet().to_string(),
            public_key: hex::encode(core.public_key()),
            routing_entries: routing_entries as i64,
            peers_json: peers_to_json(&peers),
            tree_json: tree_to_json(&tree),
        }
    }
}

// ── JSON serialization for peers/tree ───────────────────────────────────────

fn peers_to_json(peers: &[yggdrasil::links::LinkPeerInfo]) -> String {
    let json_peers: Vec<serde_json::Value> = peers
        .iter()
        .map(|p| {
            let ip = if p.key != [0u8; 32] {
                let addr = addr_for_key(&p.key);
                std::net::Ipv6Addr::from(addr.0).to_string()
            } else {
                String::new()
            };

            serde_json::json!({
                "URI": p.uri,
                "Up": p.up,
                "Inbound": p.inbound,
                "PublicKey": hex::encode(p.key),
                "Priority": p.priority,
                "RxBytes": p.rx_bytes,
                "TxBytes": p.tx_bytes,
                "RxRate": p.rx_rate,
                "TxRate": p.tx_rate,
                "UptimeSecs": p.uptime_secs,
                "Latency": p.latency_ms / 1000.0,
                "Cost": p.cost,
                "LastError": p.last_error,
                "IP": ip,
            })
        })
        .collect();

    serde_json::to_string(&json_peers).unwrap_or_else(|_| "[]".to_string())
}

fn tree_to_json(tree: &[ironwood::TreeEntry]) -> String {
    let json_tree: Vec<serde_json::Value> = tree
        .iter()
        .map(|e| {
            serde_json::json!({
                "Key": hex::encode(e.key),
                "Parent": hex::encode(e.parent),
                "Sequence": e.sequence,
            })
        })
        .collect();

    serde_json::to_string(&json_tree).unwrap_or_else(|_| "[]".to_string())
}
