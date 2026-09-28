//! Guest principal gate: an explicit allowlist bound to one agent grant.
//! Everything else answers `guest_forbidden`. Prompts are labeled, the
//! terminal is view-only, and streams close with `guest_paused` when the
//! agent leaves the foreground or `guest_revoked` on revoke.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::{
    dispatch_to_app_with_timeout, error_response_json, finish_wait_response, handle_request,
    pane_output_stream, prompt_agent, write_text_line_allow_disconnect, ApiRequestSender,
    ConnectionPrincipal, EventHub,
};
use crate::api::schema::{
    AgentInfo, GramPostParams, GramUploadChunkParams, GuestAgentProbeParams, GuestAuditEvent,
    GuestAuditFile, GuestGrantInfo, Method, Request, ResponseResult, SuccessResponse,
};
use crate::api::transport::ApiStream;
use crate::guest::GuestPrincipal;

/// Prompt text cap, before the label is prefixed.
const PROMPT_MAX_BYTES: usize = 32 * 1024;
/// How often a guest stream re-checks revocation and the live-agent check.
pub(super) const WATCH_INTERVAL: Duration = Duration::from_millis(250);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct GuestContext {
    api_tx: ApiRequestSender,
    event_hub: EventHub,
    running: Arc<AtomicBool>,
}

static CONTEXT: Mutex<Option<GuestContext>> = Mutex::new(None);

/// Called once the API server is up, so `serve` can run guest connections.
pub(super) fn install_context(
    api_tx: ApiRequestSender,
    event_hub: EventHub,
    running: Arc<AtomicBool>,
) {
    *CONTEXT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(GuestContext {
        api_tx,
        event_hub,
        running,
    });
}

/// Run one guest API connection. The stream closes when this returns.
pub(crate) fn serve_guest_stream(
    principal: GuestPrincipal,
    stream: std::os::unix::net::UnixStream,
) {
    let context = CONTEXT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let Some(context) = context else {
        tracing::warn!("guest connection before the API server started; closing");
        return;
    };
    if let Err(err) = serve_guest_with(
        &context.api_tx,
        &context.event_hub,
        &context.running,
        principal,
        stream,
    ) {
        tracing::debug!(err = %err, "guest connection ended with an error");
    }
}

fn serve_guest_with(
    api_tx: &ApiRequestSender,
    event_hub: &EventHub,
    running: &Arc<AtomicBool>,
    principal: GuestPrincipal,
    stream: std::os::unix::net::UnixStream,
) -> std::io::Result<()> {
    let stream = ApiStream::Local(crate::ipc::LocalStream::from(
        interprocess::os::unix::uds_local_socket::Stream::from(stream),
    ));
    // Guests never drive outbound federation routing.
    super::handle_principal_connection(
        stream,
        api_tx,
        event_hub,
        running,
        None,
        None,
        ConnectionPrincipal::Guest(principal),
        &HashMap::new(),
    )
}

/// The agent a probe resolved plus the `agent.prompt` live-agent check, or
/// the app's error line.
pub(super) fn probe_target(
    api_tx: &ApiRequestSender,
    terminal_id: Option<&str>,
    target: Option<&str>,
) -> Result<(AgentInfo, bool), String> {
    let response = dispatch_to_app_with_timeout(
        Request {
            id: "guest:probe".into(),
            method: Method::GuestAgentProbe(GuestAgentProbeParams {
                terminal_id: terminal_id.map(str::to_string),
                target: target.map(str::to_string),
            }),
        },
        api_tx,
        Some(PROBE_TIMEOUT),
    );
    match serde_json::from_str::<SuccessResponse>(&response) {
        Ok(SuccessResponse {
            result: ResponseResult::GuestAgentProbed { agent, running },
            ..
        }) => Ok((agent, running)),
        _ => Err(response),
    }
}

/// Same rule as the reverse-agent grants: same pane, name and harness
/// session, local, not archived and not transferring.
fn grant_matches(grant: &GuestGrantInfo, agent: &AgentInfo) -> bool {
    grant.terminal_id == agent.terminal_id
        && grant.agent_name == agent.name
        && agent.agent_session.as_ref() == Some(&grant.agent_session)
        && agent.machine_id.is_none()
        && agent.archived.is_none()
        && agent.session_transfer.is_none()
}

enum GrantState {
    Live(AgentInfo),
    Paused(AgentInfo),
    Gone,
}

impl GrantState {
    /// The granted agent, if it still matches, and whether it is running.
    fn into_parts(self) -> (Option<AgentInfo>, bool) {
        match self {
            Self::Live(agent) => (Some(agent), true),
            Self::Paused(agent) => (Some(agent), false),
            Self::Gone => (None, false),
        }
    }
}

fn grant_state(guest: &GuestPrincipal, api_tx: &ApiRequestSender) -> GrantState {
    match probe_target(api_tx, Some(&guest.grant.terminal_id), None) {
        Ok((agent, running)) if grant_matches(&guest.grant, &agent) => {
            if running {
                GrantState::Live(agent)
            } else {
                GrantState::Paused(agent)
            }
        }
        _ => GrantState::Gone,
    }
}

/// A target names the grant only by its terminal id, agent name, or the
/// pane id the agent currently occupies. Alias-qualified and other panes'
/// ids never match.
fn names_grant(target: &str, guest: &GuestPrincipal, agent: Option<&AgentInfo>) -> bool {
    target == guest.grant.terminal_id
        || guest.grant.agent_name.as_deref() == Some(target)
        || agent.is_some_and(|agent| agent.pane_id == target)
}

/// The only agent fields a guest sees. Titles, cwd, ids of other scopes,
/// session references, tokens and account details stay with the owner.
#[derive(serde::Serialize)]
struct GuestAgentView<'a> {
    terminal_id: &'a str,
    pane_id: &'a str,
    name: Option<&'a str>,
    agent: Option<&'a str>,
    display_agent: Option<&'a str>,
    agent_status: &'a crate::api::schema::AgentStatus,
    guest_running: bool,
}

fn guest_view(agent: &AgentInfo, running: bool) -> serde_json::Value {
    serde_json::to_value(GuestAgentView {
        terminal_id: &agent.terminal_id,
        pane_id: &agent.pane_id,
        name: agent.name.as_deref(),
        agent: agent.agent.as_deref(),
        display_agent: agent.display_agent.as_deref(),
        agent_status: &agent.agent_status,
        guest_running: running,
    })
    .unwrap_or_default()
}

/// Revoked in this process (live registry) or in the store, which another
/// daemon sharing it may have written.
fn is_revoked(guest: &GuestPrincipal, live: &crate::guest::LiveSession) -> bool {
    live.revoked() || crate::guest::store::is_revoked(&guest.dir, &guest.guest_id)
}

fn guest_error(id: &str, code: &str) -> String {
    let message = match code {
        "guest_paused" => "the shared agent is not running",
        "guest_revoked" => "guest access was revoked",
        _ => "guests may not call this method",
    };
    error_response_json(id.to_string(), code, message.to_string())
}

fn success_value(id: &str, result: serde_json::Value) -> String {
    serde_json::json!({"id": id, "result": result}).to_string()
}

pub(super) fn serve_request(
    mut stream: ApiStream,
    request: Request,
    guest: &GuestPrincipal,
    api_tx: &ApiRequestSender,
    event_hub: &EventHub,
    running: &Arc<AtomicBool>,
) -> std::io::Result<()> {
    let id = request.id.clone();
    let method = crate::api::api_method_name(&request.method);
    let live = crate::guest::register_live(&guest.guest_id);
    if is_revoked(guest, &live) {
        return write_text_line_allow_disconnect(&mut stream, &guest_error(&id, "guest_revoked"));
    }
    let forbidden = |stream: &mut ApiStream| {
        guest.audit(GuestAuditEvent::Denied, Some(method), None, None);
        write_text_line_allow_disconnect(stream, &guest_error(&id, "guest_forbidden"))
    };
    let paused = |stream: &mut ApiStream| {
        guest.audit(GuestAuditEvent::Paused, Some(method), None, None);
        write_text_line_allow_disconnect(stream, &guest_error(&id, "guest_paused"))
    };
    match request.method {
        Method::Ping(params) => {
            let response = handle_request(
                Request {
                    id,
                    method: Method::Ping(params),
                },
                api_tx,
                None,
                None,
                None,
            );
            write_text_line_allow_disconnect(&mut stream, &response)
        }
        Method::AgentList(_) => {
            let (agent, running) = grant_state(guest, api_tx).into_parts();
            let agents: Vec<_> = agent
                .map(|agent| guest_view(&agent, running))
                .into_iter()
                .collect();
            let result = serde_json::json!({"type": "agent_list", "agents": agents});
            write_text_line_allow_disconnect(&mut stream, &success_value(&id, result))
        }
        Method::AgentGet(target) => {
            let (agent, running) = grant_state(guest, api_tx).into_parts();
            if !names_grant(&target.target, guest, agent.as_ref()) {
                return forbidden(&mut stream);
            }
            let Some(agent) = agent else {
                return paused(&mut stream);
            };
            let result =
                serde_json::json!({"type": "agent_info", "agent": guest_view(&agent, running)});
            write_text_line_allow_disconnect(&mut stream, &success_value(&id, result))
        }
        Method::PaneStream(mut params) => {
            let (agent, is_live) = grant_state(guest, api_tx).into_parts();
            if !names_grant(&params.pane_id, guest, agent.as_ref()) {
                return forbidden(&mut stream);
            }
            let Some(agent) = agent.filter(|_| is_live) else {
                return paused(&mut stream);
            };
            // View-only: no viewer id, so no width lease and no resize path.
            params.pane_id = agent.pane_id;
            params.viewer_id = None;
            // Asked before every frame: the live revoke flag and a fresh grant
            // probe each time; the store at most every WATCH_INTERVAL.
            let mut last_store_check = Instant::now();
            let mut watch = |closed: bool| -> Option<String> {
                let store_due = last_store_check.elapsed() >= WATCH_INTERVAL;
                if store_due {
                    last_store_check = Instant::now();
                }
                if live.revoked() || (store_due && is_revoked(guest, &live)) {
                    return Some(guest_error(&id, "guest_revoked"));
                }
                if closed || !matches!(grant_state(guest, api_tx), GrantState::Live(_)) {
                    guest.audit(GuestAuditEvent::Paused, Some(method), None, None);
                    return Some(guest_error(&id, "guest_paused"));
                }
                None
            };
            pane_output_stream::serve_watched(
                stream,
                id.clone(),
                params,
                api_tx,
                running,
                Some(&mut watch),
            )
        }
        Method::AgentPrompt(mut params) => {
            if params.text.len() > PROMPT_MAX_BYTES {
                return write_text_line_allow_disconnect(
                    &mut stream,
                    &error_response_json(
                        id,
                        "invalid_params",
                        "guest prompts are limited to 32 KiB".into(),
                    ),
                );
            }
            let (agent, is_live) = grant_state(guest, api_tx).into_parts();
            if !names_grant(&params.target, guest, agent.as_ref()) {
                return forbidden(&mut stream);
            }
            let Some(agent) = agent.filter(|_| is_live) else {
                return paused(&mut stream);
            };
            guest.audit(
                GuestAuditEvent::Prompt,
                Some(method),
                Some(params.text.clone()),
                None,
            );
            params.target = agent.pane_id;
            params.text = format!("{}{}", guest.label(), params.text);
            let response =
                prompt_agent(id.clone(), params, &mut stream, api_tx, event_hub, running)?;
            finish_wait_response(&mut stream, response, &id, method, false)
        }
        Method::GramUploadChunk(params) => {
            // The file limits are enforced by the store; this bounds the decode.
            let max_encoded = crate::persist::gram_files::MAX_CHUNK_BYTES.div_ceil(3) * 4;
            if params.data_base64.len() > max_encoded {
                return write_text_line_allow_disconnect(
                    &mut stream,
                    &error_response_json(id, "invalid_params", "upload chunk is too large".into()),
                );
            }
            if !matches!(grant_state(guest, api_tx), GrantState::Live(_)) {
                return paused(&mut stream);
            }
            let request = Request {
                id,
                method: Method::GramUploadChunk(GramUploadChunkParams {
                    upload_id: guest_upload_id(guest, &params.upload_id),
                    ..params
                }),
            };
            let response = dispatch_to_app_with_timeout(request, api_tx, None);
            write_text_line_allow_disconnect(&mut stream, &response)
        }
        Method::GramPost(params) => {
            let (agent, is_live) = grant_state(guest, api_tx).into_parts();
            let Some(agent_name) = agent.filter(|_| is_live).map(|agent| agent.name) else {
                return paused(&mut stream);
            };
            if params.to.is_some() && params.to != agent_name {
                return forbidden(&mut stream);
            }
            let text = params.text.clone();
            let file = params.file.map(|mut file| {
                file.upload_id = guest_upload_id(guest, &file.upload_id);
                file
            });
            let request = Request {
                id: id.clone(),
                method: Method::GramPost(GramPostParams {
                    text: params.text,
                    to: agent_name,
                    file,
                    from: Some(guest.label().trim_end_matches(": ").to_string()),
                }),
            };
            let response = dispatch_to_app_with_timeout(request, api_tx, None);
            audit_post(guest, method, text, &response);
            write_text_line_allow_disconnect(&mut stream, &response)
        }
        _ => forbidden(&mut stream),
    }
}

/// Guests stage uploads in their own namespace, so they cannot append to or
/// attach an owner's staged upload.
fn guest_upload_id(guest: &GuestPrincipal, upload_id: &str) -> String {
    format!("guest-{}-{upload_id}", guest.guest_id)
}

fn audit_post(guest: &GuestPrincipal, method: &str, text: String, response: &str) {
    let Ok(SuccessResponse {
        result: ResponseResult::GramSent { message, .. },
        ..
    }) = serde_json::from_str::<SuccessResponse>(response)
    else {
        return;
    };
    let text = (!text.trim().is_empty()).then_some(text);
    match message.file {
        Some(file) => guest.audit(
            GuestAuditEvent::Upload,
            Some(method),
            text,
            Some(GuestAuditFile {
                name: file.name,
                size: file.size,
                sha256: file.sha256,
            }),
        ),
        None => guest.audit(GuestAuditEvent::Prompt, Some(method), text, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc as std_mpsc;
    use std::thread::JoinHandle;

    use serde_json::{json, Value};

    use crate::api::ApiRequestMessage;
    use crate::app::App;
    use crate::guest::link::host::{Admission as LinkAdmission, GuestHost, HostInfo, LinkState};
    use crate::guest::link::tests::{Device, StubRelay};
    use crate::guest::link::GuestLink;
    use crate::guest::store::tests::TempDir;
    use crate::guest::store::{now_ms, RevokeTarget};
    use crate::guest::{admit_in, Admission};

    type Control = Box<dyn FnOnce(&mut App) + Send>;

    /// A real `App` on its own thread with two named agents: the granted
    /// `llm-opt` and `other-agent` on another pane.
    struct Harness {
        api_tx: ApiRequestSender,
        event_hub: EventHub,
        running: Arc<AtomicBool>,
        control: std_mpsc::Sender<Control>,
        pty: std_mpsc::Receiver<(usize, bytes::Bytes)>,
        pane_ids: Vec<String>,
        dir: TempDir,
        thread: Option<JoinHandle<()>>,
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.running.store(false, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn start(tag: &str) -> Harness {
        let (api_tx, mut api_rx) = tokio::sync::mpsc::unbounded_channel::<ApiRequestMessage>();
        let (control_tx, control_rx) = std_mpsc::channel::<Control>();
        let (pty_tx, pty_rx) = std_mpsc::channel();
        let (ids_tx, ids_rx) = std_mpsc::channel();
        let running = Arc::new(AtomicBool::new(true));
        let app_running = Arc::clone(&running);
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap();
            let _guard = runtime.enter();
            let (_unused, app_rx) = tokio::sync::mpsc::unbounded_channel();
            let mut app = App::new(
                &crate::config::Config::default(),
                crate::app::AppPolicy::TEST,
                None,
                app_rx,
                EventHub::default(),
            );
            app.state.workspaces = vec![
                crate::workspace::Workspace::test_new("agent"),
                crate::workspace::Workspace::test_new("other"),
            ];
            app.state.ensure_test_terminals();
            app.state.active = Some(0);
            let mut ptys = Vec::new();
            let mut ids = Vec::new();
            for (ws_idx, name) in [(0, "llm-opt"), (1, "other-agent")] {
                let pane = app.state.workspaces[ws_idx].tabs[0].root_pane;
                let terminal_id = app.state.workspaces[ws_idx].tabs[0].panes[&pane]
                    .attached_terminal_id
                    .clone();
                let terminal = app.state.terminals.get_mut(&terminal_id).unwrap();
                terminal.set_agent_name(name.into());
                terminal.set_detected_state(
                    Some(crate::detect::Agent::Pi),
                    crate::detect::AgentState::Idle,
                );
                terminal.set_persisted_agent_session(crate::agent_resume::PersistedAgentSession {
                    source: "herdr".into(),
                    agent: "pi".into(),
                    session_ref: crate::agent_resume::AgentSessionRef::id(format!(
                        "session-{ws_idx}"
                    ))
                    .unwrap(),
                });
                let (runtime, rx) = crate::terminal::TerminalRuntime::test_with_channel(80, 24);
                app.state.insert_test_runtime(pane, runtime);
                ptys.push(rx);
                ids.push(app.public_pane_id(ws_idx, pane).unwrap());
            }
            ids_tx.send(ids).unwrap();
            while app_running.load(Ordering::Acquire) {
                while let Ok(control) = control_rx.try_recv() {
                    control(&mut app);
                }
                for (index, rx) in ptys.iter_mut().enumerate() {
                    while let Ok(bytes) = rx.try_recv() {
                        let _ = pty_tx.send((index, bytes));
                    }
                }
                match api_rx.try_recv() {
                    Ok(message) if matches!(message.request.method, Method::AgentPrompt(_)) => {
                        app.handle_deferred_agent_api_request(message.request, message.respond_to);
                    }
                    Ok(message) => {
                        let response = app.handle_api_request(message.request);
                        let _ = message.respond_to.send(response);
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(2)),
                }
            }
        });
        let pane_ids = ids_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        Harness {
            api_tx,
            event_hub: EventHub::default(),
            running,
            control: control_tx,
            pty: pty_rx,
            pane_ids,
            dir: TempDir::new(tag),
            thread: Some(thread),
        }
    }

    impl Harness {
        /// An invite to agent `index`, created through the store.
        fn invite(&self, index: usize, name: &str) -> crate::guest::store::NewInvite {
            let (agent, running) = probe_target(&self.api_tx, None, Some(&self.pane_ids[index]))
                .expect("probe the granted agent");
            assert!(running, "the granted agent passes the live-agent check");
            let grant = GuestGrantInfo {
                terminal_id: agent.terminal_id,
                agent_name: agent.name,
                agent_session: agent.agent_session.expect("session"),
            };
            crate::guest::store::create_invite(
                &self.dir.0,
                name,
                grant,
                "Jerry",
                "Jerry's Mac Studio",
                3600,
                now_ms(),
            )
            .unwrap()
        }

        /// Invite through the store and accept it through `admit`, as the
        /// relay link would.
        fn admit(&self) -> GuestPrincipal {
            self.admit_to(0)
        }

        /// Accept a new invite for agent `index` from the same device.
        fn admit_to(&self, index: usize) -> GuestPrincipal {
            let invite = self.invite(index, "plotarmordev");
            let hello = json!({"v": 1, "invite_id": invite.record.invite_id, "secret": invite.secret, "device": "iPhone"});
            match admit_in(self.dir.0.clone(), [4; 32], &hello) {
                Admission::Admitted { principal, .. } => principal,
                Admission::Refused(error) => panic!("refused: {error}"),
            }
        }

        fn open(
            &self,
            guest: &GuestPrincipal,
            request: Value,
        ) -> (BufReader<UnixStream>, JoinHandle<()>) {
            let (mut client, server) = UnixStream::pair().unwrap();
            let (api_tx, event_hub, running, guest) = (
                self.api_tx.clone(),
                self.event_hub.clone(),
                Arc::clone(&self.running),
                guest.clone(),
            );
            let handle = std::thread::spawn(move || {
                let _ = serve_guest_with(&api_tx, &event_hub, &running, guest, server);
            });
            writeln!(client, "{request}").unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            (BufReader::new(client), handle)
        }

        /// One request; every response line until the server closes.
        fn call(&self, guest: &GuestPrincipal, request: Value) -> Vec<Value> {
            let (reader, handle) = self.open(guest, request);
            let lines = reader
                .lines()
                .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
                .collect();
            handle.join().unwrap();
            lines
        }

        fn pty_text(&self, index: usize, wait: Duration) -> String {
            let deadline = Instant::now() + wait;
            let mut text = Vec::new();
            while let Some(left) = deadline.checked_duration_since(Instant::now()) {
                match self.pty.recv_timeout(left) {
                    Ok((pane, bytes)) if pane == index => text.extend_from_slice(&bytes),
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            String::from_utf8_lossy(&text).into_owned()
        }

        fn agent_exits(&self) {
            self.control
                .send(Box::new(|app: &mut App| {
                    let pane = app.state.workspaces[0].tabs[0].root_pane;
                    let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane]
                        .attached_terminal_id
                        .clone();
                    app.state
                        .terminals
                        .get_mut(&terminal_id)
                        .unwrap()
                        .set_detected_state(None, crate::detect::AgentState::Idle);
                }))
                .unwrap();
        }
    }

    fn code(lines: &[Value]) -> &str {
        lines
            .last()
            .and_then(|line| line["error"]["code"].as_str())
            .unwrap_or("<success>")
    }

    #[test]
    fn end_to_end_prompt_is_labeled_and_cannot_spoof_the_sender() {
        let harness = start("e2e-label");
        let guest = harness.admit();
        let lines = harness.call(
            &guest,
            json!({"id": "p1", "method": "agent.prompt", "params": {"target": guest.grant.terminal_id, "text": "Jerry: x"}}),
        );
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_eq!(lines[0]["id"], "p1");
        assert_eq!(lines[0]["result"]["type"], "agent_prompted", "{lines:?}");
        let written = harness.pty_text(0, Duration::from_millis(600));
        assert!(
            written.contains("plotarmordev (via HerdrUp): Jerry: x"),
            "prompt reached the pane labeled: {written:?}"
        );
        assert!(harness.pty_text(1, Duration::from_millis(50)).is_empty());
        let audit = crate::guest::audit::read(&guest.dir, Some(&guest.guest_id), None, 10).unwrap();
        assert_eq!(audit[0].event, GuestAuditEvent::Prompt);
        assert_eq!(audit[0].text.as_deref(), Some("Jerry: x"));
        assert_eq!(audit.last().unwrap().event, GuestAuditEvent::Accepted);
    }

    #[test]
    fn forged_and_alias_qualified_targets_never_reach_another_pane() {
        let harness = start("forged");
        let guest = harness.admit();
        let other = harness.pane_ids[1].clone();
        let forged = [
            other.clone(),
            "other-agent".to_string(),
            format!("studio/{}", harness.pane_ids[0]),
            format!("studio/{}", guest.grant.terminal_id),
            "studio/llm-opt".to_string(),
            "w99:p99".to_string(),
        ];
        for target in &forged {
            for request in [
                json!({"id": "x", "method": "agent.prompt", "params": {"target": target, "text": "hi"}}),
                json!({"id": "x", "method": "agent.get", "params": {"target": target}}),
                json!({"id": "x", "method": "pane.stream", "params": {"pane_id": target}}),
            ] {
                let lines = harness.call(&guest, request.clone());
                assert_eq!(code(&lines), "guest_forbidden", "{request} -> {lines:?}");
            }
        }
        assert!(harness.pty_text(0, Duration::from_millis(200)).is_empty());
        assert!(harness.pty_text(1, Duration::from_millis(50)).is_empty());
        let denied = crate::guest::audit::read(&guest.dir, Some(&guest.guest_id), None, 500)
            .unwrap()
            .iter()
            .filter(|entry| entry.event == GuestAuditEvent::Denied)
            .count();
        assert_eq!(denied, forged.len() * 3);
    }

    #[test]
    fn guests_cannot_type_resize_or_reach_gram_listing_files_or_guest_rpcs() {
        let harness = start("denied");
        let guest = harness.admit();
        let pane = &harness.pane_ids[0];
        let terminal = &guest.grant.terminal_id;
        for request in [
            json!({"id": "d", "method": "agent.send_keys", "params": {"target": terminal, "keys": ["enter"]}}),
            json!({"id": "d", "method": "pane.send_text", "params": {"pane_id": pane, "text": "rm -rf /"}}),
            json!({"id": "d", "method": "pane.send_keys", "params": {"pane_id": pane, "keys": ["enter"]}}),
            json!({"id": "d", "method": "pane.send_input", "params": {"pane_id": pane, "text": "x"}}),
            json!({"id": "d", "method": "pane.set_pty_size", "params": {"pane_id": pane, "cols": 20, "rows": 5}}),
            json!({"id": "d", "method": "pane.input.stream", "params": {"pane_id": pane}}),
            json!({"id": "d", "method": "gram.list", "params": {}}),
            json!({"id": "d", "method": "gram.get_file", "params": {"id": "gram-1"}}),
            json!({"id": "d", "method": "guest.list", "params": {}}),
            json!({"id": "d", "method": "guest.invite.create", "params": {"target": terminal, "name": "friend", "owner_name": "Jerry", "machine_label": "Mac"}}),
            json!({"id": "d", "method": "guest.revoke", "params": {"guest_id": guest.guest_id}}),
            json!({"id": "d", "method": "guest.audit", "params": {}}),
            json!({"id": "d", "method": "server.stop", "params": {}}),
        ] {
            let lines = harness.call(&guest, request.clone());
            assert_eq!(code(&lines), "guest_forbidden", "{request} -> {lines:?}");
        }
        assert!(harness.pty_text(0, Duration::from_millis(200)).is_empty());
        assert!(!crate::guest::store::is_revoked(
            &guest.dir,
            &guest.guest_id
        ));
    }

    #[test]
    fn agent_list_shows_only_the_grant_and_pauses_when_the_agent_exits() {
        let harness = start("list");
        let guest = harness.admit();
        let list = harness.call(
            &guest,
            json!({"id": "l", "method": "agent.list", "params": {}}),
        );
        let agents = list[0]["result"]["agents"].as_array().unwrap().clone();
        assert_eq!(agents.len(), 1, "{list:?}");
        assert_eq!(agents[0]["terminal_id"], guest.grant.terminal_id.as_str());
        assert_eq!(agents[0]["guest_running"], true);
        assert_eq!(
            harness.call(
                &guest,
                json!({"id": "g", "method": "agent.get", "params": {"target": "llm-opt"}})
            )[0]["result"]["agent"]["guest_running"],
            true
        );

        harness.agent_exits();
        std::thread::sleep(Duration::from_millis(50));
        let list = harness.call(
            &guest,
            json!({"id": "l", "method": "agent.list", "params": {}}),
        );
        let agents = list[0]["result"]["agents"].as_array().unwrap();
        assert!(
            agents.is_empty() || agents[0]["guest_running"] == false,
            "{list:?}"
        );
        let prompt = harness.call(
            &guest,
            json!({"id": "p", "method": "agent.prompt", "params": {"target": "llm-opt", "text": "hi"}}),
        );
        assert_eq!(code(&prompt), "guest_paused");
        let stream = harness.call(
            &guest,
            json!({"id": "s", "method": "pane.stream", "params": {"pane_id": guest.grant.terminal_id}}),
        );
        assert_eq!(code(&stream), "guest_paused");
        assert!(harness.pty_text(0, Duration::from_millis(200)).is_empty());
    }

    #[test]
    fn oversized_prompts_are_refused_before_delivery() {
        let harness = start("cap");
        let guest = harness.admit();
        let lines = harness.call(
            &guest,
            json!({"id": "p", "method": "agent.prompt", "params": {"target": "llm-opt", "text": "x".repeat(PROMPT_MAX_BYTES + 1)}}),
        );
        assert_eq!(code(&lines), "invalid_params");
        assert!(harness.pty_text(0, Duration::from_millis(200)).is_empty());
    }

    /// Open the granted stream and read up to its `stream_started` ack.
    fn open_stream(
        harness: &Harness,
        guest: &GuestPrincipal,
    ) -> (BufReader<UnixStream>, JoinHandle<()>) {
        let (mut reader, handle) = harness.open(
            guest,
            json!({"id": "s", "method": "pane.stream", "params": {"pane_id": guest.grant.terminal_id, "viewer_id": "v"}}),
        );
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let first: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(first["result"]["type"], "stream_started", "{first}");
        (reader, handle)
    }

    /// Read frames until the error line that ends the stream, then EOF.
    fn stream_end(reader: &mut BufReader<UnixStream>) -> Value {
        loop {
            let mut line = String::new();
            assert!(
                reader.read_line(&mut line).unwrap() > 0,
                "stream ended without an error line"
            );
            let value: Value = serde_json::from_str(&line).unwrap();
            if value.get("error").is_some() {
                let mut rest = String::new();
                assert_eq!(
                    reader.read_line(&mut rest).unwrap(),
                    0,
                    "EOF after the error line"
                );
                return value;
            }
        }
    }

    #[test]
    fn a_live_stream_pauses_within_a_second_of_the_agent_exiting() {
        let harness = start("pause");
        let guest = harness.admit();
        let (mut reader, handle) = open_stream(&harness, &guest);
        let exited_at = Instant::now();
        harness.agent_exits();
        let end = stream_end(&mut reader);
        assert_eq!(end["error"]["code"], "guest_paused");
        assert_eq!(end["id"], "s");
        assert!(
            exited_at.elapsed() < Duration::from_secs(1),
            "{:?}",
            exited_at.elapsed()
        );
        handle.join().unwrap();
        let audit = crate::guest::audit::read(&guest.dir, Some(&guest.guest_id), None, 5).unwrap();
        assert_eq!(audit[0].event, GuestAuditEvent::Paused);
    }

    #[test]
    fn revoke_closes_a_live_stream_and_refuses_later_requests() {
        let harness = start("revoke");
        let guest = harness.admit();
        let (mut reader, handle) = open_stream(&harness, &guest);
        let closed =
            crate::guest::revoke_at(harness.dir.0.clone(), RevokeTarget::Guest(&guest.guest_id))
                .unwrap();
        assert_eq!(closed, Some(1));
        let end = stream_end(&mut reader);
        assert_eq!(end["error"]["code"], "guest_revoked");
        handle.join().unwrap();
        let ping = harness.call(&guest, json!({"id": "p", "method": "ping", "params": {}}));
        assert_eq!(code(&ping), "guest_revoked");
    }

    #[test]
    fn guest_agent_views_expose_only_the_safe_fields() {
        let harness = start("projection");
        let guest = harness.admit();
        let allowed: std::collections::BTreeSet<&str> = [
            "terminal_id",
            "pane_id",
            "name",
            "agent",
            "display_agent",
            "agent_status",
            "guest_running",
        ]
        .into();
        let list = harness.call(
            &guest,
            json!({"id": "l", "method": "agent.list", "params": {}}),
        );
        let get = harness.call(
            &guest,
            json!({"id": "g", "method": "agent.get", "params": {"target": "llm-opt"}}),
        );
        for agent in [&list[0]["result"]["agents"][0], &get[0]["result"]["agent"]] {
            let keys: std::collections::BTreeSet<&str> = agent
                .as_object()
                .unwrap_or_else(|| panic!("agent object: {list:?} {get:?}"))
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(keys, allowed, "{agent}");
            assert_eq!(agent["name"], "llm-opt");
            assert_eq!(agent["pane_id"], harness.pane_ids[0].as_str());
        }
    }

    /// Open the granted stream and read past the ack and the reset seed, so
    /// the next line is whatever the stream sends after that.
    fn open_stream_past_seed(
        harness: &Harness,
        guest: &GuestPrincipal,
    ) -> (BufReader<UnixStream>, JoinHandle<()>) {
        let (mut reader, handle) = open_stream(harness, guest);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let seed: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(seed["frame"], "reset", "{seed}");
        (reader, handle)
    }

    /// The very next line is the closing error, then EOF: no frame first.
    fn next_is_close(reader: &mut BufReader<UnixStream>) -> Value {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        assert!(value.get("error").is_some(), "a frame followed: {value}");
        let mut rest = String::new();
        assert_eq!(
            reader.read_line(&mut rest).unwrap(),
            0,
            "EOF after the error"
        );
        value
    }

    fn write_output(harness: &Harness) {
        crate::api::output_registry::lookup(&harness.pane_ids[0])
            .expect("the granted pane has a live output ring")
            .append(b"owner-only output\r\n");
    }

    #[test]
    fn no_frame_follows_a_pause_even_with_output_pending() {
        let harness = start("pause-frame");
        let guest = harness.admit();
        let (mut reader, handle) = open_stream_past_seed(&harness, &guest);
        harness.agent_exits();
        write_output(&harness);
        assert_eq!(next_is_close(&mut reader)["error"]["code"], "guest_paused");
        handle.join().unwrap();
    }

    #[test]
    fn no_frame_follows_a_revoke_even_with_output_pending() {
        let harness = start("revoke-frame");
        let guest = harness.admit();
        let (mut reader, handle) = open_stream_past_seed(&harness, &guest);
        crate::guest::revoke_at(harness.dir.0.clone(), RevokeTarget::Guest(&guest.guest_id))
            .unwrap();
        write_output(&harness);
        assert_eq!(next_is_close(&mut reader)["error"]["code"], "guest_revoked");
        handle.join().unwrap();
    }

    #[test]
    fn a_new_invite_on_the_same_device_closes_the_old_grants_stream() {
        let harness = start("replace-stream");
        let first = harness.admit_to(0);
        let (mut reader, handle) = open_stream(&harness, &first);
        let second = harness.admit_to(1);
        assert_ne!(first.guest_id, second.guest_id);
        assert_eq!(stream_end(&mut reader)["error"]["code"], "guest_revoked");
        handle.join().unwrap();
        let ping = harness.call(&first, json!({"id": "p", "method": "ping", "params": {}}));
        assert_eq!(code(&ping), "guest_revoked");
    }

    #[test]
    fn uploads_and_posts_need_a_running_agent_and_an_active_grant() {
        let harness = start("gram-state");
        let guest = harness.admit();
        let upload = json!({"id": "u", "method": "gram.upload_chunk", "params": {"upload_id": "up-1", "offset": 0, "data_base64": "aGk="}});
        let post =
            json!({"id": "g", "method": "gram.post", "params": {"text": "hello", "to": "llm-opt"}});
        harness.agent_exits();
        std::thread::sleep(Duration::from_millis(50));
        for request in [&upload, &post] {
            let lines = harness.call(&guest, request.clone());
            assert_eq!(code(&lines), "guest_paused", "{request} -> {lines:?}");
        }
        crate::guest::revoke_at(harness.dir.0.clone(), RevokeTarget::Guest(&guest.guest_id))
            .unwrap();
        for request in [&upload, &post] {
            let lines = harness.call(&guest, request.clone());
            assert_eq!(code(&lines), "guest_revoked", "{request} -> {lines:?}");
        }
    }

    #[test]
    fn ping_is_allowed() {
        let harness = start("ping");
        let guest = harness.admit();
        let lines = harness.call(&guest, json!({"id": "p", "method": "ping", "params": {}}));
        assert_eq!(lines[0]["result"]["type"], "pong", "{lines:?}");
    }

    /// The guest store in the harness's directory and its real `App`, behind
    /// the real relay link. Only the directory and API context differ from
    /// the daemon's `DaemonGuestHost`.
    struct StoreHost {
        dir: std::path::PathBuf,
        relay_url: String,
        api_tx: ApiRequestSender,
        event_hub: EventHub,
        running: Arc<AtomicBool>,
    }

    impl GuestHost for StoreHost {
        type Principal = GuestPrincipal;

        fn host_info(&self) -> std::io::Result<HostInfo> {
            let (host, node_secret) = crate::guest::store::load_host(&self.dir)?;
            Ok(HostInfo {
                host_id: host.host_id,
                relay_secret: host.relay_secret,
                node_secret,
                relay_url: self.relay_url.clone(),
            })
        }

        fn link_wanted(&self) -> bool {
            crate::guest::store::link_wanted_in(&self.dir, now_ms())
        }

        fn admit(&self, device_pub: [u8; 32], hello: &Value) -> LinkAdmission<GuestPrincipal> {
            admit_in(self.dir.clone(), device_pub, hello).into()
        }

        fn serve(&self, principal: GuestPrincipal, stream: UnixStream) {
            let _ = serve_guest_with(
                &self.api_tx,
                &self.event_hub,
                &self.running,
                principal,
                stream,
            );
        }

        fn set_link_status(&self, _: LinkState, _: Option<String>) {}

        fn subscribe_changes(&self) -> std_mpsc::Receiver<()> {
            crate::guest::subscribe_changes()
        }
    }

    #[test]
    fn guest_through_the_relay_link_prompts_the_agent_until_revoked() {
        let harness = start("guest-link-e2e");
        let dir = harness.dir.0.clone();
        let (identity, node_secret) = crate::guest::store::load_host(&dir).unwrap();
        let invite = harness.invite(0, "plotarmordev");
        // Another pending invite keeps the link wanted after the revoke.
        harness.invite(0, "second-guest");

        let stub = StubRelay::new();
        let host = Arc::new(StoreHost {
            dir: dir.clone(),
            relay_url: stub.url.clone(),
            api_tx: harness.api_tx.clone(),
            event_hub: harness.event_hub.clone(),
            running: Arc::clone(&harness.running),
        });
        let _link = GuestLink::start(host).unwrap();
        let mut relay = stub.accept_host(&identity.host_id, &identity.relay_secret);

        let device = Device {
            secret: [0x17; 32],
            host_pub: crate::guest::store::x25519_public(&node_secret),
            host_id: identity.host_id.clone(),
        };
        let accept = json!({"v": 1, "invite_id": invite.record.invite_id, "secret": invite.secret, "device": "iPhone"});
        let (reply, guest) = device.connect(&mut relay, 41, &accept);
        assert_eq!(reply["ok"], true, "{reply}");
        assert_eq!(reply["name"], "plotarmordev");
        assert_eq!(reply["agent"]["name"], "llm-opt");
        let guest_id = reply["guest_id"].as_str().unwrap().to_owned();

        // One request line in, the response line out, then CLOSE.
        let mut guest = guest.unwrap();
        let prompt = json!({"id": "p1", "method": "agent.prompt", "params": {"target": "llm-opt", "text": "ship it"}});
        guest.send(&mut relay, &format!("{prompt}\n"));
        let (line, _) = guest.recv_line(&mut relay);
        let response: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["result"]["type"], "agent_prompted", "{response}");
        assert_eq!(relay.closed(41), "");
        let written = harness.pty_text(0, Duration::from_secs(2));
        assert!(
            written.contains("plotarmordev (via HerdrUp): ship it"),
            "the labeled prompt reached the agent's PTY: {written:?}"
        );

        // A returning guest streams the pane until revoked; the link then
        // closes the session.
        let (reply, guest) = device.connect(&mut relay, 42, &json!({"v": 1}));
        assert_eq!(reply["guest_id"], guest_id.as_str(), "{reply}");
        let mut guest = guest.unwrap();
        let stream = json!({"id": "s", "method": "pane.stream", "params": {"pane_id": "llm-opt"}});
        guest.send(&mut relay, &format!("{stream}\n"));
        let (line, _) = guest.recv_line(&mut relay);
        let started: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(started["result"]["type"], "stream_started", "{started}");

        crate::guest::revoke_at(dir, RevokeTarget::Guest(&guest_id)).unwrap();
        let end = loop {
            let (line, _) = guest.recv_line(&mut relay);
            let value: Value = serde_json::from_str(&line).unwrap();
            if value.get("error").is_some() {
                break value;
            }
        };
        assert_eq!(end["error"]["code"], "guest_revoked", "{end}");
        assert_eq!(relay.closed(42), "");

        // The revoked device is refused at the handshake.
        let (reply, guest) = device.connect(&mut relay, 43, &json!({"v": 1}));
        assert_eq!(reply, json!({"ok": false, "error": "revoked"}));
        assert!(guest.is_none());
        assert_eq!(relay.closed(43), "revoked");
        assert!(harness.pty_text(0, Duration::from_millis(200)).is_empty());
    }
}
