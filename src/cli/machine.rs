use std::collections::BTreeMap;

use std::io::IsTerminal as _;

use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::style::{Attribute, SetAttribute};
use crossterm::{cursor, execute, terminal};
use serde::Serialize;

use super::machine_federation::{federate, unfederate};
use crate::api::client::ApiClient;
use crate::api::schema::{EmptyParams, Method, Request, ResponseResult};
use crate::client::endpoint::{EndpointCatalog, ProfileId, MAX_LABEL_BYTES};

const HELP: &str = "Usage:
  herdr machine list [--json]
  herdr machine status [<label-or-id>] [--json]
  herdr machine reconnect <label-or-id>
  herdr machine add <ssh-target> [--label <label>] [--remote-session <name>]
  herdr machine rename <profile-id> --label <label>
  herdr machine grant <profile-id> <agent-terminal-id> --observe|--interact [--observe-peer ID] [--interact-peer ID]
  herdr machine revoke <profile-id> <agent-terminal-id>
  herdr machine remove <profile-id>
  herdr machine enable <profile-id>
  herdr machine disable <profile-id>
  herdr machine federate <label-or-id> [--migrate-all-legacy]
  herdr machine unfederate <label-or-id>

Add prepares the remote Herdr installation and starts its server before saving.
Missing or incompatible installations require approval in an interactive terminal.
Changes apply automatically to open local Herdr clients.
Removing or disabling a machine leaves its remote sessions running.
Saved machines contain only a label, SSH target, explicit Herdr session, and enabled state.
Reverse grants are OFF by default. Set federation.reverse_coordinator_machine_id
on the trusted remote to this coordinator's install id; SSH streamlocal -R must
be permitted. Same-user processes on that remote can spoof a granted pane id.
Grants are not process isolation and never confer Gram/admin/server powers.
SSH credentials and key material remain owned by OpenSSH.";

#[derive(Serialize)]
struct MachineListRow<'a> {
    id: &'a str,
    label: &'a str,
    target: &'a str,
    session: &'a str,
    enabled: bool,
    selected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    federation_expected_machine_id: Option<&'a str>,
}

pub(super) fn run_machine_command(args: &[String]) -> std::io::Result<i32> {
    match args.first().map(String::as_str) {
        Some("list") => list(&args[1..]),
        Some("status") => status(&args[1..]),
        Some("reconnect") => reconnect(&args[1..]),
        Some("add") => add(&args[1..]),
        Some("rename") => rename(&args[1..]),
        Some("grant") => grant(&args[1..]),
        Some("revoke") => revoke(&args[1..]),
        Some("remove") => remove(&args[1..]),
        Some("enable") => set_enabled(&args[1..], true),
        Some("disable") => set_enabled(&args[1..], false),
        Some("federate") => federate(&args[1..]),
        Some("unfederate") => unfederate(&args[1..]),
        Some("help" | "--help" | "-h") => {
            println!("{HELP}");
            Ok(0)
        }
        _ => {
            eprintln!("{HELP}");
            Ok(2)
        }
    }
}

fn grant(args: &[String]) -> std::io::Result<i32> {
    let [profile, terminal_id, options @ ..] = args else {
        eprintln!("{HELP}");
        return Ok(2);
    };
    let profile_id = match ProfileId::parse(profile.clone()) {
        Ok(id) => id,
        Err(error) => {
            eprintln!("{error}");
            return Ok(2);
        }
    };
    let config = crate::config::Config::load().config;
    let Some(policy) = config.federation.saved_machines.get(&profile_id) else {
        eprintln!("profile has no pinned federation.saved_machines policy; a saved SSH profile alone grants nothing");
        return Ok(1);
    };
    if !config.federation.coordinator {
        eprintln!("federation coordinator is disabled");
        return Ok(1);
    }
    let mut observe = false;
    let mut interact = false;
    let mut observe_peers = Vec::new();
    let mut interact_peers = Vec::new();
    let mut index = 0;
    while index < options.len() {
        match options[index].as_str() {
            "--observe" => observe = true,
            "--interact" => interact = true,
            "--observe-peer" | "--interact-peer" => {
                let Some(value) = options.get(index + 1) else {
                    eprintln!("peer option requires an alias");
                    return Ok(2);
                };
                if options[index] == "--observe-peer" {
                    observe_peers.push(value.clone());
                } else {
                    interact_peers.push(value.clone());
                }
                index += 1;
            }
            other => {
                eprintln!("unknown grant option: {other}");
                return Ok(2);
            }
        }
        index += 1;
    }
    if (!observe && (!interact || !observe_peers.is_empty()))
        || (!interact && !interact_peers.is_empty())
    {
        eprintln!("grant requires --observe or --interact; peer permissions require their respective capability");
        return Ok(2);
    }
    if observe_peers.iter().chain(&interact_peers).any(|peer| {
        peer.as_str() == profile.as_str()
            || (!config
                .federation
                .saved_machines
                .keys()
                .any(|id| id.as_str() == peer.as_str())
                && !config
                    .federation
                    .peers
                    .iter()
                    .any(|item| item.alias == *peer))
    }) {
        eprintln!("a peer alias is unknown or refers to the caller machine");
        return Ok(2);
    }
    let Some(local_id) = terminal_id.strip_prefix(&format!("{profile}/")) else {
        eprintln!("agent-terminal-id must be machine qualified as {profile}/<remote-terminal-id>");
        return Ok(2);
    };
    let roster = match ApiClient::local().request(Request {
        id: "cli:machine:grant:list".into(),
        method: Method::AgentList(crate::api::schema::AgentListParams::default()),
    }) {
        Ok(roster) => roster,
        Err(error) => {
            eprintln!("cannot verify live selected agent: {error}");
            return Ok(1);
        }
    };
    let ResponseResult::AgentList { agents, .. } = roster.result else {
        eprintln!("agent roster unavailable");
        return Ok(1);
    };
    let Some(agent) = agents.into_iter().find(|agent| {
        agent.machine_id.as_deref() == Some(profile)
            && agent.terminal_id == *terminal_id
            && agent.origin_machine_id.as_deref() == Some(&policy.expected_machine_id)
            && agent.reachability == Some(crate::api::federation_store::Reachability::Reachable)
    }) else {
        eprintln!(
            "selected agent is offline, stale, or machine identity does not match the saved pin"
        );
        return Ok(1);
    };
    let Some(session) = agent.agent_session else {
        eprintln!("selected agent has no stable harness session identity yet");
        return Ok(1);
    };
    if agent.archived.is_some() || agent.session_transfer.is_some() {
        eprintln!("selected agent is archived or transferring; grant refused");
        return Ok(1);
    }
    let mut grants = policy.agent_grants.clone();
    grants.retain(|grant| grant.terminal_id != local_id);
    grants.push(crate::config::FederationAgentGrant {
        terminal_id: local_id.to_owned(),
        session,
        name: agent.name.map(|name| {
            name.strip_prefix(&format!("{profile}/"))
                .unwrap_or(&name)
                .to_owned()
        }),
        observe,
        interact,
        observe_peers,
        interact_peers,
    });
    save_agent_grants(&profile_id, &grants)?;
    println!("granted {terminal_id} on pinned machine {}; remote opt-in requires federation.reverse_coordinator_machine_id = \"{}\"; same-user processes can spoof this pane id", policy.expected_machine_id, crate::persist::machine::get_or_create());
    reload_grants()
}

fn revoke(args: &[String]) -> std::io::Result<i32> {
    let [profile, terminal_id] = args else {
        eprintln!("{HELP}");
        return Ok(2);
    };
    let profile_id = match ProfileId::parse(profile.clone()) {
        Ok(id) => id,
        Err(error) => {
            eprintln!("{error}");
            return Ok(2);
        }
    };
    let config = crate::config::Config::load().config;
    let Some(policy) = config.federation.saved_machines.get(&profile_id) else {
        eprintln!("no pinned federation policy for profile");
        return Ok(1);
    };
    let local_id = terminal_id
        .strip_prefix(&format!("{profile}/"))
        .unwrap_or(terminal_id);
    let mut grants = policy.agent_grants.clone();
    grants.retain(|grant| grant.terminal_id != local_id);
    if grants.len() == policy.agent_grants.len() {
        eprintln!("no grant for that terminal id");
        return Ok(1);
    }
    save_agent_grants(&profile_id, &grants)?;
    println!("revoked {profile}/{local_id}; reloading coordinator");
    reload_grants()
}

fn reload_grants() -> std::io::Result<i32> {
    match super::send_request(&Request {
        id: "cli:machine:grants:reload".into(),
        method: Method::ServerReloadConfig(EmptyParams::default()),
    }) {
        Ok(response) => super::print_response(&response),
        Err(error) => {
            eprintln!("grant saved, but coordinator reload failed: {error}; run `herdr server reload-config` before relying on this change");
            Ok(1)
        }
    }
}

fn save_agent_grants(
    profile: &ProfileId,
    grants: &[crate::config::FederationAgentGrant],
) -> std::io::Result<()> {
    fn quoted(value: &str) -> String {
        toml::Value::String(value.to_owned()).to_string()
    }
    fn peers(values: &[String]) -> String {
        format!(
            "[{}]",
            values
                .iter()
                .map(|value| quoted(value))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
    let rendered = grants
        .iter()
        .map(|grant| {
            let kind = serde_json::to_value(grant.session.kind).expect("serializable session kind");
            let kind = kind.as_str().expect("string session kind");
            let mut fields = vec![
                format!("terminal_id = {}", quoted(&grant.terminal_id)),
                format!(
                    "session = {{ source = {}, agent = {}, kind = {}, value = {} }}",
                    quoted(&grant.session.source),
                    quoted(&grant.session.agent),
                    quoted(kind),
                    quoted(&grant.session.value)
                ),
                format!("observe = {}", grant.observe),
                format!("interact = {}", grant.interact),
                format!("observe_peers = {}", peers(&grant.observe_peers)),
                format!("interact_peers = {}", peers(&grant.interact_peers)),
            ];
            if let Some(name) = &grant.name {
                fields.push(format!("name = {}", quoted(name)));
            }
            format!("{{ {} }}", fields.join(", "))
        })
        .collect::<Vec<_>>();
    let value = format!("[{}]", rendered.join(", "));
    let path = crate::config::config_path();
    let original = std::fs::read_to_string(&path)?;
    let bare_section = format!("federation.saved_machines.{profile}");
    let section = if original
        .lines()
        .any(|line| line.trim() == format!("[{bare_section}]"))
    {
        bare_section
    } else {
        format!("federation.saved_machines.\"{profile}\"")
    };
    toml::from_str::<toml::Value>(&original)
        .map_err(|cause| std::io::Error::new(std::io::ErrorKind::InvalidData, cause))?;
    let updated = crate::config::upsert_section_value(&original, &section, "agent_grants", &value);
    toml::from_str::<toml::Value>(&updated)
        .map_err(|cause| std::io::Error::new(std::io::ErrorKind::InvalidData, cause))?;
    crate::config::update_file_at_checked(&path, "federation agent grants", |current| {
        if current != original {
            return Err(
                "config changed while selecting the live agent; retry the grant command".into(),
            );
        }
        Ok(updated)
    })
    .map_err(std::io::Error::other)
}

fn list(args: &[String]) -> std::io::Result<i32> {
    let json = match args {
        [] => false,
        [flag] if flag == "--json" => true,
        _ => {
            eprintln!("usage: herdr machine list [--json]");
            return Ok(2);
        }
    };
    let catalog = load_catalog()?;
    let config = crate::config::Config::load().config;
    let rows = machine_list_rows(&catalog, &config.federation.saved_machines);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).map_err(std::io::Error::other)?
        );
        return Ok(0);
    }
    if rows.is_empty() {
        println!("No saved SSH machines.");
        return Ok(0);
    }
    for row in rows {
        let state = if row.enabled { "enabled" } else { "disabled" };
        println!(
            "{}\t{}\t{}\t{}\t{}",
            row.id, row.label, row.target, row.session, state
        );
    }
    Ok(0)
}

#[derive(Serialize)]
struct MachineStatusRow<'a> {
    id: &'a str,
    label: &'a str,
    status: &'static str,
    error: Option<String>,
    /// The local server's coordinator view of this saved machine (endpoint,
    /// federation, Gram relay). Absent when no local server answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    coordinator: Option<serde_json::Value>,
}

/// The local server's `machine.status`, or `None` when no server is running or
/// it cannot answer. A fresh SSH check does not need a server, so this is only
/// added detail.
fn coordinator_machine_status(
) -> Option<BTreeMap<String, crate::api::schema::CoordinatorMachineStatus>> {
    let response = ApiClient::local()
        .request(Request {
            id: "machine-status".into(),
            method: Method::MachineStatus(EmptyParams {}),
        })
        .ok()?;
    match response.result {
        ResponseResult::MachineStatus { machines } => Some(machines),
        _ => None,
    }
}

fn status(args: &[String]) -> std::io::Result<i32> {
    let mut json = false;
    let mut selector = None;
    for arg in args {
        if arg == "--json" && !json {
            json = true;
        } else if !arg.starts_with('-') && selector.is_none() {
            selector = Some(arg.as_str());
        } else {
            eprintln!("usage: herdr machine status [<label-or-id>] [--json]");
            return Ok(2);
        }
    }
    let catalog = load_catalog()?;
    let profiles = match selector {
        Some(selector) => match super::target::resolve_machine(&catalog.ssh, selector) {
            Ok(profile) => vec![profile],
            Err(error) => {
                eprintln!("{error}");
                return Ok(2);
            }
        },
        None => catalog.ssh.iter().collect(),
    };
    let mut coordinator = coordinator_machine_status().unwrap_or_default();
    let mut rows = Vec::with_capacity(profiles.len());
    let mut details = Vec::with_capacity(profiles.len());
    for profile in profiles {
        let (status, error) = if !profile.enabled {
            ("disabled", None)
        } else {
            match crate::remote::check_saved_ssh(&profile.target, &profile.session) {
                Ok(()) => ("reachable", None),
                Err(error) => {
                    let message = error.to_string();
                    let status = if crate::remote::ssh_error_requires_authentication(&message) {
                        "auth required"
                    } else {
                        "error"
                    };
                    (status, Some(message))
                }
            }
        };
        let machine = coordinator.remove(profile.id.as_str());
        let coordinator_json = machine
            .as_ref()
            .map(|machine| {
                let mut value = serde_json::to_value(machine).map_err(std::io::Error::other)?;
                if machine.saved_state == crate::api::schema::SavedMachineState::Untrusted {
                    value["next_action"] =
                        format!("herdr machine federate {}", machine.profile_id).into();
                }
                Ok::<_, std::io::Error>(value)
            })
            .transpose()?;
        rows.push(MachineStatusRow {
            id: profile.id.as_str(),
            label: &profile.label,
            status,
            error,
            coordinator: coordinator_json,
        });
        details.push(machine);
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).map_err(std::io::Error::other)?
        );
    } else {
        for (row, machine) in rows.iter().zip(&details) {
            println!("{}\t{}\t{}", row.id, row.label, row.status);
            if let Some(error) = &row.error {
                println!("  {}", error.escape_debug());
            }
            if let Some(machine) = machine {
                print_coordinator_status(machine);
            }
        }
        if rows.is_empty() {
            println!("No saved SSH machines.");
        }
    }
    Ok(i32::from(rows.iter().any(|row| row.error.is_some())))
}

/// The coordinator's view of one saved machine, under its SSH check line:
/// saved-profile, endpoint/TUI, and federation health kept separate.
fn print_coordinator_status(machine: &crate::api::schema::CoordinatorMachineStatus) {
    let endpoint = machine
        .endpoint_status
        .map(|status| format!("{status:?}").to_lowercase())
        .unwrap_or_else(|| "unavailable".into());
    let federation = machine
        .federation_reachability
        .map(|status| format!("{status:?}").to_lowercase())
        .unwrap_or_else(|| "not_started".into());
    println!(
        "  saved: {}  endpoint: {}  federation: {}  machine id: {}",
        format!("{:?}", machine.saved_state).to_lowercase(),
        endpoint,
        federation,
        machine.validated_machine_id.as_deref().unwrap_or("-"),
    );
    if machine.remote_boot_id.is_some()
        || machine.remote_version.is_some()
        || machine.remote_protocol.is_some()
        || machine.remote_capabilities.is_some()
    {
        println!(
            "  remote: boot={} version={} protocol={} capabilities={}",
            machine.remote_boot_id.as_deref().unwrap_or("-"),
            machine.remote_version.as_deref().unwrap_or("-"),
            machine
                .remote_protocol
                .map_or_else(|| "-".into(), |value| value.to_string()),
            machine
                .remote_capabilities
                .as_ref()
                .map_or_else(|| "-".into(), |value| format!("{value:?}").to_lowercase()),
        );
    }
    if let Some(error) = machine.last_error_class {
        println!("  last error: {}", format!("{error:?}").to_lowercase());
    }
    if machine.saved_state == crate::api::schema::SavedMachineState::Untrusted {
        println!("  next: herdr machine federate {}", machine.profile_id);
    }
    if machine.stale {
        println!("  cached federation data is stale");
    }
    if let Some(state) = &machine.gram_relay {
        println!("  gram relay: {}", gram_gateway_summary(state));
    }
}

pub(crate) fn gram_gateway_summary(state: &crate::api::schema::GramGatewayState) -> String {
    use crate::api::schema::GramGatewayState;
    match state {
        GramGatewayState::Off => "off".into(),
        GramGatewayState::Starting => "starting".into(),
        GramGatewayState::Up => "up".into(),
        GramGatewayState::Retrying {
            attempt,
            next_in_secs,
            last_error,
        } => format!("retrying (attempt {attempt}, next in {next_in_secs}s): {last_error}"),
    }
}

fn machine_list_rows<'a>(
    catalog: &'a EndpointCatalog,
    policies: &'a BTreeMap<ProfileId, crate::config::FederationSavedMachinePolicy>,
) -> Vec<MachineListRow<'a>> {
    catalog
        .ssh
        .iter()
        .map(|profile| MachineListRow {
            id: profile.id.as_str(),
            label: &profile.label,
            target: &profile.target,
            session: &profile.session,
            enabled: profile.enabled,
            selected: catalog.selected_profile.as_ref() == Some(&profile.id),
            federation_expected_machine_id: policies
                .get(&profile.id)
                .map(|policy| policy.expected_machine_id.as_str()),
        })
        .collect()
}

fn reconnect(args: &[String]) -> std::io::Result<i32> {
    use std::io::IsTerminal;
    let [selector] = args else {
        eprintln!("usage: herdr machine reconnect <label-or-id>");
        return Ok(2);
    };
    let catalog = load_catalog()?;
    let profile = match super::target::resolve_machine(&catalog.ssh, selector) {
        Ok(profile) => profile,
        Err(error) => {
            eprintln!("{error}");
            return Ok(2);
        }
    };
    if !std::io::stdin().is_terminal() {
        eprintln!("reconnect requires an interactive terminal; use herdr machine status for noninteractive checks");
        return Ok(2);
    }
    let mut authentication = crate::remote::ssh_authentication_command(&profile.target)?;
    if !authentication.command.status()?.success() {
        eprintln!("SSH authentication failed; the saved machine was not changed.");
        return Ok(1);
    }
    crate::remote::check_saved_ssh(&profile.target, &profile.session)?;
    println!(
        "Machine {} is reachable. Open Herdr clients retry within 30 seconds.",
        profile.id
    );
    Ok(0)
}

#[derive(Debug, PartialEq, Eq)]
struct AddArgs {
    target: String,
    label: Option<String>,
    session: Option<String>,
}

fn parse_add_args(args: &[String]) -> Result<AddArgs, String> {
    let args = super::expand_equals_args(args, &["--label", "--remote-session"]);
    let mut target = None;
    let mut label = None;
    let mut session = None;
    let mut index = 0;
    while index < args.len() {
        let (name, value) = match args[index].as_str() {
            "--label" | "--remote-session" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(format!("missing value for {}", args[index]));
                };
                index += 2;
                (args[index - 2].as_str(), value.clone())
            }
            positional if !positional.starts_with('-') && target.is_none() => {
                target = Some(positional.to_owned());
                index += 1;
                continue;
            }
            unknown => {
                return Err(format!("unknown machine add option: {unknown}"));
            }
        };
        match name {
            "--label" if label.is_none() => label = Some(value),
            "--remote-session" if session.is_none() => session = Some(value),
            "--remote-session" => {
                return Err("--remote-session can only be specified once".into());
            }
            "--label" => {
                return Err("--label can only be specified once".into());
            }
            _ => unreachable!("validated machine add option"),
        }
    }
    let target = target.ok_or_else(|| {
        "usage: herdr machine add <ssh-target> [--label <label>] [--remote-session <name>]"
            .to_owned()
    })?;
    Ok(AddArgs {
        target,
        label,
        session,
    })
}

/// Names the machine after the SSH host, plus the session when it is not the default.
fn default_label(target: &str, session: &str) -> String {
    let url = target
        .strip_prefix("ssh://")
        .map(|authority| authority.trim_end_matches('/'));
    let authority = url.unwrap_or(target);
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match (url, host.strip_prefix('[')) {
        (Some(_), Some(bracketed)) => bracketed.split_once(']').map_or(host, |(ip, _)| ip),
        (Some(_), None) => host.split_once(':').map_or(host, |(host, _)| host),
        (None, _) => host,
    };
    if session == crate::session::DEFAULT_SESSION_NAME {
        host.to_owned()
    } else {
        format!("{host}/{session}")
    }
}

fn check_default_label(catalog: &EndpointCatalog, label: &str) -> Result<(), String> {
    if label.len() > MAX_LABEL_BYTES {
        return Err(format!(
            "default machine name '{label}' is longer than {MAX_LABEL_BYTES} bytes; pass --label to choose a name"
        ));
    }
    if catalog.ssh.iter().any(|profile| profile.label == label) {
        return Err(format!(
            "a machine named '{label}' already exists; pass --label to choose another name"
        ));
    }
    Ok(())
}

fn add(args: &[String]) -> std::io::Result<i32> {
    let AddArgs {
        target,
        label,
        session,
    } = match parse_add_args(args) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("{error}");
            return Ok(2);
        }
    };
    let mut setup = None;
    let session =
        if session.is_none() && std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
            let discovered = (|| {
                let connection = crate::remote::SavedSshSetup::connect(&target)?;
                let sessions = connection.running_sessions()?;
                let session = select_remote_session(&sessions, &target)?;
                setup = Some(connection);
                Ok::<_, std::io::Error>(session)
            })();
            match discovered {
                Ok(session) => session,
                Err(error) => {
                    eprintln!("error: {error}; machine was not saved");
                    crate::remote::print_saved_ssh_error_hint(&error, &target);
                    return Ok(1);
                }
            }
        } else {
            session.unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned())
        };
    let label_is_default = label.is_none();
    let label = label.unwrap_or_else(|| default_label(&target, &session));
    let mut catalog = load_catalog()?;
    if label_is_default {
        if let Err(error) = check_default_label(&catalog, &label) {
            eprintln!("error: {error}");
            return Ok(2);
        }
    }
    match catalog.add_ssh(label.clone(), &target, session.clone()) {
        Ok(_) => {}
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    }
    let metadata = match setup
        .map(Ok)
        .unwrap_or_else(|| crate::remote::SavedSshSetup::connect(&target))
        .and_then(|setup| setup.prepare(&session))
    {
        Ok(metadata) => metadata,
        Err(error) => {
            eprintln!("error: {error}; machine was not saved");
            crate::remote::print_saved_ssh_error_hint(&error, &target);
            return Ok(1);
        }
    };
    // Setup can wait for human approval. Do not overwrite catalog edits made meanwhile.
    let mut catalog = load_catalog().map_err(|error| {
        std::io::Error::other(format!(
            "remote prepared, but machine was not saved: {error}"
        ))
    })?;
    if label_is_default {
        if let Err(error) = check_default_label(&catalog, &label) {
            eprintln!("error: {error}; machine was not saved");
            return Ok(2);
        }
    }
    let id = match catalog.add_ssh(label, &target, &session) {
        Ok(id) => id,
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    };
    store_catalog(&catalog).map_err(|error| {
        std::io::Error::other(format!(
            "remote prepared, but machine was not saved: {error}"
        ))
    })?;
    if let Some(metadata) = metadata {
        crate::client::endpoint::SshMetadataCache::new(id.as_str(), &target, &session)?
            .store(&metadata);
    }
    println!("Saved SSH machine {id}. Remote server is ready.");
    println!("Open Herdr clients connect automatically.");
    Ok(0)
}

fn select_remote_session(sessions: &[String], target: &str) -> std::io::Result<String> {
    match sessions {
        [] => return Ok(crate::session::DEFAULT_SESSION_NAME.to_owned()),
        [session] => return Ok(session.clone()),
        _ => {}
    }

    let _raw_mode = RawModeGuard::enable()?;
    let mut output = std::io::stderr();
    let mut selected = 0;
    render_remote_session_picker(&mut output, target, sessions, selected, false)?;
    loop {
        let Event::Key(key) = crossterm::event::read()? else {
            continue;
        };
        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            continue;
        }
        match key.code {
            KeyCode::Up => selected = selected.checked_sub(1).unwrap_or(sessions.len() - 1),
            KeyCode::Down => selected = (selected + 1) % sessions.len(),
            KeyCode::Enter => return Ok(sessions[selected].clone()),
            KeyCode::Esc => break,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
            _ => continue,
        }
        render_remote_session_picker(&mut output, target, sessions, selected, true)?;
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::Interrupted,
        "remote session selection cancelled",
    ))
}

struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> std::io::Result<Self> {
        terminal::enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

fn render_remote_session_picker(
    output: &mut impl std::io::Write,
    target: &str,
    sessions: &[String],
    selected: usize,
    redraw: bool,
) -> std::io::Result<()> {
    if redraw {
        execute!(output, cursor::MoveUp((sessions.len() + 2) as u16))?;
    }
    execute!(output, terminal::Clear(terminal::ClearType::CurrentLine))?;
    write!(output, "Running sessions on {target}:\r\n")?;
    for (index, session) in sessions.iter().enumerate() {
        execute!(output, terminal::Clear(terminal::ClearType::CurrentLine))?;
        if index == selected {
            execute!(output, SetAttribute(Attribute::Bold))?;
            write!(output, "> {session}")?;
            execute!(output, SetAttribute(Attribute::Reset))?;
            write!(output, "\r\n")?;
        } else {
            write!(output, "  {session}\r\n")?;
        }
    }
    execute!(output, terminal::Clear(terminal::ClearType::CurrentLine))?;
    write!(output, "↑/↓ select · Enter confirm · Esc cancel\r\n")?;
    output.flush()
}

fn rename(args: &[String]) -> std::io::Result<i32> {
    let args = super::expand_equals_args(args, &["--label"]);
    let [raw_id, flag, label] = args.as_slice() else {
        eprintln!("usage: herdr machine rename <profile-id> --label <label>");
        return Ok(2);
    };
    if flag != "--label" {
        eprintln!("usage: herdr machine rename <profile-id> --label <label>");
        return Ok(2);
    }
    let id = match ProfileId::parse(raw_id.clone()) {
        Ok(id) => id,
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    };
    let mut catalog = load_catalog()?;
    match catalog.rename_ssh(&id, label) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("machine profile {id} was not found");
            return Ok(1);
        }
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    }
    store_catalog(&catalog)?;
    println!("Renamed SSH machine {id}.");
    Ok(0)
}

fn remove(args: &[String]) -> std::io::Result<i32> {
    let Some(id) = one_profile_id(args, "usage: herdr machine remove <profile-id>")? else {
        return Ok(2);
    };
    let mut catalog = load_catalog()?;
    let previous_selection = catalog.selected_profile.clone();
    let metadata_cache = catalog
        .ssh
        .iter()
        .find(|profile| profile.id == id)
        .map(|profile| {
            crate::client::endpoint::SshMetadataCache::new(
                id.as_str(),
                &profile.target,
                &profile.session,
            )
        })
        .transpose()?;
    if !catalog.remove_ssh(&id) {
        eprintln!("machine profile {id} was not found");
        return Ok(1);
    }
    store_catalog(&catalog)?;
    if let Some(cache) = metadata_cache {
        cache.invalidate();
    }
    if catalog.selected_profile != previous_selection {
        catalog.store_selection().map_err(std::io::Error::other)?;
    }
    println!("Removed SSH machine {id}.");
    Ok(0)
}

fn set_enabled(args: &[String], enabled: bool) -> std::io::Result<i32> {
    let action = if enabled { "enable" } else { "disable" };
    let usage = format!("usage: herdr machine {action} <profile-id>");
    let Some(id) = one_profile_id(args, &usage)? else {
        return Ok(2);
    };
    let mut catalog = load_catalog()?;
    let previous_selection = catalog.selected_profile.clone();
    if !catalog.set_enabled(&id, enabled) {
        eprintln!("machine profile {id} was not found");
        return Ok(1);
    }
    store_catalog(&catalog)?;
    if catalog.selected_profile != previous_selection {
        catalog.store_selection().map_err(std::io::Error::other)?;
    }
    println!(
        "{} SSH machine {id}.",
        if enabled { "Enabled" } else { "Disabled" }
    );
    Ok(0)
}

fn one_profile_id(args: &[String], usage: &str) -> std::io::Result<Option<ProfileId>> {
    let [raw] = args else {
        eprintln!("{usage}");
        return Ok(None);
    };
    match ProfileId::parse(raw.clone()) {
        Ok(id) => Ok(Some(id)),
        Err(error) => {
            eprintln!("error: {error}");
            Ok(None)
        }
    }
}

fn load_catalog() -> std::io::Result<EndpointCatalog> {
    EndpointCatalog::load().map_err(std::io::Error::other)
}

fn store_catalog(catalog: &EndpointCatalog) -> std::io::Result<()> {
    catalog.store_profiles().map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_parser_preserves_values_across_argument_orders() {
        for (args, session) in [
            (vec!["--label", "coder", "workstation.coder"], None),
            (vec!["workstation.coder", "--label", "coder"], None),
            (
                vec![
                    "--remote-session",
                    "agents",
                    "workstation.coder",
                    "--label",
                    "coder",
                ],
                Some("agents"),
            ),
            (
                vec![
                    "--label=coder",
                    "--remote-session=agents",
                    "workstation.coder",
                ],
                Some("agents"),
            ),
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert_eq!(
                parse_add_args(&args).unwrap(),
                AddArgs {
                    target: "workstation.coder".into(),
                    label: Some("coder".into()),
                    session: session.map(str::to_owned),
                },
                "{args:?}"
            );
        }
    }

    #[test]
    fn add_parser_leaves_label_unset_without_flag() {
        let parsed = parse_add_args(&["workstation.coder".to_owned()]).unwrap();
        assert_eq!(parsed.label, None);
        assert_eq!(parsed.session, None);
    }

    #[test]
    fn default_label_uses_ssh_host_and_non_default_session() {
        for (target, session, label) in [
            ("workbox", "default", "workbox"),
            ("dev@workbox", "default", "workbox"),
            ("workbox", "agents", "workbox/agents"),
            ("ssh://workbox", "default", "workbox"),
            ("ssh://dev@workbox:2222", "default", "workbox"),
            ("ssh://dev@[::1]:2222", "agents", "::1/agents"),
            ("ssh://dev@workbox/", "default", "workbox"),
            ("ssh://dev@workbox:2222/", "agents", "workbox/agents"),
        ] {
            assert_eq!(default_label(target, session), label, "{target} {session}");
        }
    }

    #[test]
    fn default_label_must_be_unique_and_fit() {
        let mut catalog = EndpointCatalog::default();
        catalog.add_ssh("workbox", "workbox", "default").unwrap();

        assert!(check_default_label(&catalog, "workbox/agents").is_ok());
        let duplicate = check_default_label(&catalog, "workbox").unwrap_err();
        assert!(duplicate.contains("--label"), "{duplicate}");
        let long = check_default_label(&catalog, &"h".repeat(MAX_LABEL_BYTES + 1)).unwrap_err();
        assert!(long.contains("--label"), "{long}");
    }

    #[test]
    fn add_parser_rejects_incomplete_duplicate_and_extra_arguments() {
        for args in [
            vec![],
            vec!["--label", "coder"],
            vec!["workstation.coder", "--label"],
            vec!["workstation.coder", "--label", "coder", "--remote-session"],
            vec!["--label", "coder", "--label", "other", "workstation.coder"],
            vec![
                "workstation.coder",
                "--label",
                "coder",
                "--remote-session",
                "a",
                "--remote-session",
                "b",
            ],
            vec!["--label", "coder", "workstation.coder", "other-host"],
            vec!["--unknown", "workstation.coder", "--label", "coder"],
            vec!["--label", "--remote-session", "agents", "workstation.coder"],
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert!(parse_add_args(&args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn profile_id_parser_rejects_target_text() {
        assert!(one_profile_id(&["build.example".into()], "usage")
            .unwrap()
            .is_none());
    }

    #[test]
    fn list_rows_do_not_have_credential_fields() {
        let encoded = serde_json::to_string(&MachineListRow {
            id: "0123456789abcdef0123456789abcdef",
            label: "Build",
            target: "dev@build",
            session: "agents",
            enabled: true,
            selected: false,
            federation_expected_machine_id: None,
        })
        .unwrap();
        assert!(!encoded.contains("password"));
        assert!(!encoded.contains("key"));
    }

    #[test]
    fn federation_policy_follows_profile_identity_not_label_or_target() {
        let mut catalog = EndpointCatalog::default();
        let profile_id = catalog.add_ssh("Build", "dev@build", "agents").unwrap();
        let mut policies = BTreeMap::new();
        policies.insert(
            profile_id.clone(),
            crate::config::FederationSavedMachinePolicy {
                expected_machine_id: "machine_build".into(),
                agent_grants: Vec::new(),
            },
        );

        catalog.rename_ssh(&profile_id, "Renamed").unwrap();
        let rows = machine_list_rows(&catalog, &policies);
        assert_eq!(rows[0].id, profile_id.as_str());
        assert_eq!(rows[0].label, "Renamed");
        assert_eq!(
            rows[0].federation_expected_machine_id,
            Some("machine_build")
        );

        assert_eq!(
            serde_json::to_value(&rows).unwrap()[0]["federation_expected_machine_id"],
            "machine_build"
        );
        assert!(catalog.remove_ssh(&profile_id));
        let replacement = catalog.add_ssh("Renamed", "dev@build", "agents").unwrap();
        assert_ne!(replacement, profile_id);
        assert_eq!(
            machine_list_rows(&catalog, &policies)[0].federation_expected_machine_id,
            None
        );
    }
}
