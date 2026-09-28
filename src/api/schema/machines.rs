use serde::{Deserialize, Serialize};

use crate::api::federation_store::Reachability;

use super::ServerCapabilities;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SavedMachineState {
    Disabled,
    Untrusted,
    CoordinatorDisabled,
    Coordinated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MachineEndpointStatus {
    Connecting,
    Online,
    Reconnecting,
    Attention,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FederationPollErrorClass {
    AuthenticationFailed,
    IdentityMismatch,
    Protocol,
    Transport,
}

/// Coordinator-side state of one saved peer's supervised Gram reverse gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum GramGatewayState {
    /// No gateway: Gram relay consent is absent, or the peer is not a pinned saved SSH peer.
    Off,
    /// An attempt (remote socket preflight and SSH reverse bind) is in progress.
    Starting,
    /// The reverse forward is established and the private local gateway is accepting.
    Up,
    /// The last attempt failed or its SSH forward exited; the next attempt is scheduled.
    Retrying {
        /// Consecutive failed attempts.
        attempt: u32,
        /// Whole seconds until the next attempt.
        next_in_secs: u64,
        /// Bounded description of the most recent failure.
        last_error: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoordinatorMachineStatus {
    pub profile_id: String,
    pub display_label: String,
    pub remote_session: String,
    pub saved_state: SavedMachineState,
    /// Policy presence is independent of whether the saved SSH profile is enabled.
    #[serde(default)]
    pub federation_configured: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_status: Option<MachineEndpointStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validated_machine_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_boot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_reachability: Option<Reachability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_class: Option<FederationPollErrorClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_protocol: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_capabilities: Option<ServerCapabilities>,
    pub stale: bool,
    /// Supervised Gram reverse gateway state for this saved machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gram_relay: Option<GramGatewayState>,
}
