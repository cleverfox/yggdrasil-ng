uniffi::include_scaffolding!("yggdrasil_mobile");

mod mobile;

pub use mobile::{
    AndroidNetworkInterface,
    CkrRemoteSubnet,
    MulticastInterfaceConfig,
    TunnelRoutingConfig,
    YggdrasilConfig,
    YggdrasilError,
    YggdrasilMobile,
    YggdrasilState,
    YggdrasilStateListener,
    generate_config,
    get_version,
    expand_ckr_cidrs,
};
