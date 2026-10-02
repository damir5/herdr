//! `herdr pair` — put a phone on this machine by scanning a QR.
//!
//! The problem this solves is the first screen of the app: it asks for a host, a user and
//! an ed25519 private key pasted from the clipboard, which means generating a key on a
//! computer before the app is usable at all. This command replaces that with one scan.
//!
//! WHAT IT DOES NOT DO: it never generates, transports or sees a private key. The phone
//! makes its own keypair and sends only the public half; this command appends that to
//! `~/.ssh/authorized_keys`. The QR carries a single-use token plus public facts, so a
//! photograph of it is worthless once redeemed.

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::pair_qr::{open_qr_with, PairingQrFile};
use crate::pairing;

/// How long a pairing window stays open. Long enough to walk to another room and find the
/// app; short enough that an unattended terminal is not a standing invitation.
const DEFAULT_TTL: Duration = Duration::from_secs(300);
const SSH_READY_TIMEOUT: Duration = Duration::from_secs(2);

struct PairOptions {
    ttl: Duration,
    open_qr: bool,
    qr_file: Option<PathBuf>,
    json: bool,
}

pub(super) fn run_pair_command(args: &[String]) -> std::io::Result<i32> {
    let mut lan = false;
    let mut ttl = DEFAULT_TTL;
    let mut port: u16 = 0; // 0 = let the OS choose
    let mut open_qr = false;
    let mut qr_file: Option<PathBuf> = None;
    let mut json = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" | "help" => {
                print_help();
                return Ok(0);
            }
            "--lan" => lan = true,
            "--open" => open_qr = true,
            "--json" => json = true,
            "--qr-file" => {
                i += 1;
                match args.get(i).filter(|value| !value.is_empty()) {
                    Some(path) => qr_file = Some(PathBuf::from(path)),
                    None => {
                        eprintln!("--qr-file takes a file path");
                        return Ok(2);
                    }
                }
            }
            "--ttl" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<u64>().ok()) {
                    Some(secs) if secs > 0 && secs <= 3600 => ttl = Duration::from_secs(secs),
                    _ => {
                        eprintln!("--ttl takes seconds, 1..3600");
                        return Ok(2);
                    }
                }
            }
            "--port" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<u16>().ok()) {
                    Some(p) => port = p,
                    None => {
                        eprintln!("--port takes a port number");
                        return Ok(2);
                    }
                }
            }
            other => {
                eprintln!("unknown option {other:?}");
                if !args.iter().any(|arg| arg == "--json") {
                    print_help();
                }
                return Ok(2);
            }
        }
        i += 1;
    }

    if json && open_qr {
        eprintln!("--json and --open cannot be combined");
        return Ok(2);
    }

    // Decide where to listen BEFORE anything else. Every refusal here is a refusal to put
    // a pre-authentication endpoint somewhere it should not be, so it happens before a
    // token exists, before a socket is opened, and before anything is printed.
    let lan_addr = if lan {
        match crate::platform::private_lan_ipv4() {
            Ok(address) => address,
            Err(err) => {
                eprintln!("herdr pair: {err}");
                return Ok(1);
            }
        }
    } else {
        None
    };
    let tailscale_result = pairing::detect_tailscale_address();
    let tailscale = match tailscale_result {
        Ok(address) => Some(address),
        Err(pairing::TailscaleDetectionError::InvalidOutput) => {
            eprintln!(
                "herdr pair: {}",
                pairing::TailscaleDetectionError::InvalidOutput
            );
            return Ok(1);
        }
        Err(_err) if lan && lan_addr.is_some() => None,
        Err(err) if lan => {
            eprintln!(
                "herdr pair: no RFC1918 private LAN address was found. Tailscale was also unavailable: {err}"
            );
            return Ok(1);
        }
        Err(err) => {
            eprintln!("herdr pair: {err}");
            return Ok(1);
        }
    };
    let bind_ip = match pairing::choose_bind_address(tailscale, lan_addr) {
        Ok(addr) => addr,
        Err(refusal) => {
            eprintln!("herdr pair: {refusal}");
            return Ok(1);
        }
    };

    // A pairing succeeds only if the app can SSH to the machine afterwards and pin the
    // key it sees. Prove both facts before minting or exposing a code. The old path emitted
    // `fp: ""` and an "UNKNOWN" label, even though Herdrup correctly refuses that payload.
    let fingerprint = match ssh_readiness(bind_ip) {
        Ok(fingerprint) => fingerprint,
        Err(SshReadinessError::NotListening { address, cause }) => {
            eprintln!(
                "herdr pair: SSH is not accepting connections at {address}: {cause}. {}",
                crate::platform::ssh_pairing_setup_hint()
            );
            return Ok(1);
        }
        Err(SshReadinessError::MissingHostKey { address }) => {
            eprintln!(
                "herdr pair: SSH is reachable at {address}, but its host-key fingerprint could not be read. Pairing stopped because Herdrup requires a pinned host identity. {}",
                crate::platform::ssh_pairing_setup_hint()
            );
            return Ok(1);
        }
    };

    let listener = match std::net::TcpListener::bind((bind_ip, port)) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("herdr pair: could not bind {bind_ip}: {err}");
            return Ok(1);
        }
    };
    let keys = pairing::authorized_keys_path(&home_dir());
    run_pair_listener(
        &listener,
        fingerprint,
        if tailscale.is_some() {
            "Tailscale"
        } else {
            "private LAN (--lan)"
        },
        PairOptions {
            ttl,
            open_qr,
            qr_file,
            json,
        },
        &keys,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    )
}

fn run_pair_listener<'a>(
    listener: &TcpListener,
    fingerprint: String,
    network: &str,
    options: PairOptions,
    keys: &Path,
    stdout: &'a mut dyn Write,
    stderr: &'a mut dyn Write,
) -> std::io::Result<i32> {
    let local = listener.local_addr()?;

    let token = pairing::PairingToken::generate()?;
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "root".into());
    let payload = pairing::PairingPayload {
        v: pairing::PAIRING_PAYLOAD_VERSION,
        host: local.ip().to_string(),
        port: local.port(),
        user: user.clone(),
        token: token.as_str().to_string(),
        fp: fingerprint.clone(),
    };

    let qr = if options.json {
        None
    } else {
        match pairing::render_qr_terminal(&payload.to_json()) {
            Ok(qr) => Some(qr),
            Err(err) => {
                writeln!(stderr, "herdr pair: {err}")?;
                return Ok(1);
            }
        }
    };
    let svg = if options.open_qr || options.qr_file.is_some() {
        match pairing::render_qr_svg(&payload.to_json()) {
            Ok(svg) => Some(svg),
            Err(err) => {
                writeln!(stderr, "herdr pair: {err}")?;
                return Ok(1);
            }
        }
    } else {
        None
    };
    let qr_artifact = match svg.as_deref() {
        Some(svg) => match PairingQrFile::create(svg, options.qr_file.as_deref()) {
            Ok(file) => Some(file),
            Err(err) => {
                writeln!(stderr, "herdr pair: could not write the QR image: {err}")?;
                return Ok(1);
            }
        },
        None => None,
    };
    let open_warning = if options.open_qr {
        qr_artifact
            .as_ref()
            .and_then(|file| open_qr_with(file.path(), crate::platform::open_path))
    } else {
        None
    };

    if options.json {
        writeln!(stdout, "{}", payload.to_json())?;
        stdout.flush()?;
    }
    {
        let out = if options.json {
            &mut *stderr
        } else {
            &mut *stdout
        };
        if let Some(qr) = qr {
            writeln!(out)?;
            writeln!(out, "{qr}")?;
            writeln!(out, "  Scan this in herdrup to connect this machine.")?;
            writeln!(out)?;
        }
        writeln!(out, "  address    {local}")?;
        writeln!(out, "  user       {user}")?;
        writeln!(out, "  host key   {fingerprint}")?;
        if let Some(file) = &qr_artifact {
            writeln!(out, "  QR image   {}", file.path().display())?;
        }
        if let Some(warning) = &open_warning {
            writeln!(out, "  warning    {warning}")?;
        }
        writeln!(out, "  network    {network}")?;
        writeln!(out, "  expires    in {}s", options.ttl.as_secs())?;
        writeln!(out)?;
        writeln!(
            out,
            "  The QR carries a single-use code, never a key. Your phone"
        )?;
        writeln!(
            out,
            "  generates its own keypair and sends only the public half."
        )?;
        writeln!(out)?;
        out.flush()?;
    }

    let outcome = pairing::serve_one_pairing(
        listener,
        token,
        keys,
        Instant::now() + options.ttl,
        |event| {
            let _ = writeln!(stderr, "  {event}");
        },
    )?;

    let out = if options.json { stderr } else { stdout };
    let exit = match outcome {
        pairing::PairingOutcome::Paired { added } => {
            writeln!(out)?;
            if added {
                writeln!(
                    out,
                    "  Paired. The phone's key was added to {}.",
                    keys.display()
                )?;
            } else {
                writeln!(
                    out,
                    "  Paired. That key was already authorized; nothing changed."
                )?;
            }
            writeln!(
                out,
                "  To revoke it later, remove the line marked {:?} from that file.",
                pairing::AUTHORIZED_KEYS_MARKER
            )?;
            0
        }
        pairing::PairingOutcome::TimedOut => {
            writeln!(out)?;
            writeln!(
                out,
                "  Pairing window closed — nobody scanned it. Run herdr pair again."
            )?;
            1
        }
        pairing::PairingOutcome::GaveUp => {
            writeln!(out)?;
            writeln!(
                out,
                "  Too many failed attempts; stopping. Run herdr pair again for a new code."
            )?;
            1
        }
    };
    out.flush()?;
    Ok(exit)
}

fn home_dir() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/root"))
}

#[derive(Debug, PartialEq, Eq)]
enum SshReadinessError {
    NotListening { address: SocketAddr, cause: String },
    MissingHostKey { address: SocketAddr },
}

fn ssh_readiness(bind_ip: Ipv4Addr) -> Result<String, SshReadinessError> {
    ssh_readiness_with(
        bind_ip,
        |address, timeout| {
            TcpStream::connect_timeout(&address, timeout)
                .map(drop)
                .map_err(|err| err.to_string())
        },
        pairing::ssh_host_key_fingerprint,
    )
}

fn ssh_readiness_with(
    bind_ip: Ipv4Addr,
    connect: impl FnOnce(SocketAddr, Duration) -> Result<(), String>,
    fingerprint: impl FnOnce() -> Option<String>,
) -> Result<String, SshReadinessError> {
    let address = SocketAddr::from((bind_ip, 22));
    connect(address, SSH_READY_TIMEOUT)
        .map_err(|cause| SshReadinessError::NotListening { address, cause })?;
    fingerprint().ok_or(SshReadinessError::MissingHostKey { address })
}

/// Render the SAME help clap builds for `herdr pair --help`, taken from `spec.rs`.
///
/// `--help` never reaches this function: because `pair` IS registered in the spec,
/// `write_requested_help` resolves it and prints clap's long help directly. This path
/// serves `herdr pair help` and the unknown-option case. Rendering the spec rather than
/// a second hand-written string is what keeps those two from drifting apart.
///
/// (`accounts` is the counter-example: absent from the spec, so `write_requested_help`
/// returns false — `path.len() == 1` — and its own `print_help` runs. That works, but it
/// costs the command its place in shell completions and in the root usage list, both of
/// which are generated from the spec.)
fn print_help() {
    let mut root = super::spec::command();
    root.build();
    if let Some(pair) = root.find_subcommand_mut("pair") {
        let _ = pair.print_help();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::sync::mpsc;

    struct FlushedOutput {
        bytes: Vec<u8>,
        ready: Option<mpsc::Sender<Vec<u8>>>,
    }

    impl Write for FlushedOutput {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            if let Some(ready) = self.ready.take() {
                ready.send(self.bytes.clone()).expect("payload reader");
            }
            Ok(())
        }
    }

    fn drive_json_pairing(requests: usize, existing_key: bool) -> (i32, String) {
        use base64::Engine as _;

        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let dir = std::env::temp_dir().join(format!(
            "herdr-pair-json-{}",
            pairing::PairingToken::generate()
                .expect("test directory suffix")
                .as_str()
        ));
        let keys = pairing::authorized_keys_path(&dir);
        let public_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH";
        if existing_key {
            pairing::append_authorized_key(&keys, public_key).expect("seed test key");
        }
        let fingerprint = format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode([3u8; 32])
        );
        let server_keys = keys.clone();
        let server_fingerprint = fingerprint.clone();
        let (ready, payload_line) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let mut stdout = FlushedOutput {
                bytes: Vec::new(),
                ready: Some(ready),
            };
            let mut stderr = Vec::new();
            let exit = run_pair_listener(
                &listener,
                server_fingerprint,
                "test loopback",
                PairOptions {
                    ttl: if requests == 0 {
                        Duration::from_millis(200)
                    } else {
                        Duration::from_secs(5)
                    },
                    open_qr: false,
                    qr_file: None,
                    json: true,
                },
                &server_keys,
                &mut stdout,
                &mut stderr,
            )
            .expect("serve pairing");
            (exit, stdout.bytes, stderr)
        });

        let line = payload_line
            .recv_timeout(Duration::from_secs(2))
            .expect("payload must be flushed before listening");
        let line = String::from_utf8(line).expect("UTF-8 payload");
        assert_eq!(line.lines().count(), 1);
        assert!(line.ends_with('\n'));
        let fields: serde_json::Value = serde_json::from_str(&line).expect("payload JSON");
        let mut names = fields
            .as_object()
            .expect("payload object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        names.sort_unstable();
        assert_eq!(names, ["fp", "host", "port", "token", "user", "v"]);
        // Drover's parser requires these six typed fields, version 1, a nonempty target
        // and token, and a SHA256 fingerprint with exactly 32 decoded bytes.
        let payload: pairing::PairingPayload = serde_json::from_str(&line).expect("typed payload");
        assert_eq!(payload.v, 1);
        assert_eq!(payload.host, address.ip().to_string());
        assert_eq!(payload.port, address.port());
        assert_ne!(payload.port, 0);
        assert!(!payload.user.is_empty());
        assert!(!payload.token.is_empty());
        assert_eq!(payload.fp, fingerprint);
        assert_eq!(
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(payload.fp.strip_prefix("SHA256:").expect("SHA256 prefix"))
                .expect("base64 fingerprint")
                .len(),
            32
        );
        assert_eq!(line, format!("{}\n", payload.to_json()));

        for _ in 0..requests {
            let mut stream = TcpStream::connect((payload.host.as_str(), payload.port))
                .expect("connect using printed payload");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("response timeout");
            let request = serde_json::json!({
                "type": "pair.redeem",
                "token": if requests == 1 { payload.token.as_str() } else { "wrong-token" },
                "public_key": public_key,
                "device": "test phone",
            });
            writeln!(stream, "{request}").expect("send redemption");
            stream.flush().expect("flush redemption");
            let mut reply = String::new();
            BufReader::new(stream)
                .read_line(&mut reply)
                .expect("pairing reply");
            let reply: serde_json::Value = serde_json::from_str(&reply).expect("reply JSON");
            assert_eq!(
                reply["type"],
                if requests == 1 {
                    "pair.ok"
                } else {
                    "pair.error"
                }
            );
        }
        let (exit, stdout, stderr) = server.join().expect("pairing server");
        assert_eq!(
            stdout,
            line.as_bytes(),
            "stdout must contain only the payload after pairing ends"
        );
        let stderr = String::from_utf8(stderr).expect("UTF-8 status");
        assert!(stderr.contains("address"));
        if requests == 1 {
            let authorized = std::fs::read_to_string(&keys).expect("test authorized_keys");
            assert_eq!(authorized.lines().count(), 1);
            assert!(authorized.starts_with(public_key));
            if !existing_key {
                assert!(authorized.contains("herdr-pair:test phone"));
            }
        } else {
            assert!(!keys.exists(), "failed pairing must not authorize a key");
        }
        if dir.exists() {
            std::fs::remove_dir_all(dir).expect("remove test keys");
        }
        (exit, stderr)
    }

    #[test]
    fn json_payload_is_flushed_and_redeems_without_extra_stdout() {
        for existing_key in [false, true] {
            let (exit, status) = drive_json_pairing(1, existing_key);
            assert_eq!(exit, 0);
            assert!(status.contains(if existing_key {
                "already authorized"
            } else {
                "key was added"
            }));
        }
    }

    #[test]
    fn json_timeout_and_failed_attempts_leave_stdout_at_one_line() {
        let (exit, status) = drive_json_pairing(0, false);
        assert_eq!(exit, 1);
        assert!(status.contains("Pairing window closed"));
        let (exit, status) = drive_json_pairing(20, false);
        assert_eq!(exit, 1);
        assert!(status.contains("Too many failed attempts"));
    }

    #[test]
    fn ssh_must_listen_before_the_fingerprint_is_read() {
        let fingerprint_called = std::cell::Cell::new(false);
        let result = ssh_readiness_with(
            "100.64.1.2".parse().expect("address"),
            |_address, _timeout| Err("connection refused".into()),
            || {
                fingerprint_called.set(true);
                Some("SHA256:should-not-be-read".into())
            },
        );
        assert!(matches!(
            result,
            Err(SshReadinessError::NotListening { .. })
        ));
        assert!(!fingerprint_called.get());
    }

    #[test]
    fn ssh_without_a_fingerprint_is_refused() {
        let result = ssh_readiness_with(
            "100.64.1.2".parse().expect("address"),
            |_address, timeout| {
                assert_eq!(timeout, SSH_READY_TIMEOUT);
                Ok(())
            },
            || None,
        );
        assert_eq!(
            result,
            Err(SshReadinessError::MissingHostKey {
                address: "100.64.1.2:22".parse().expect("socket address")
            })
        );
    }

    #[test]
    fn ssh_readiness_returns_the_exact_fingerprint() {
        let result = ssh_readiness_with(
            "100.64.1.2".parse().expect("address"),
            |address, _timeout| {
                assert_eq!(address, "100.64.1.2:22".parse().expect("socket address"));
                Ok(())
            },
            || Some("SHA256:exact".into()),
        );
        assert_eq!(result, Ok("SHA256:exact".into()));
    }

    #[test]
    fn qr_file_requires_a_path_before_any_network_work() {
        let exit = run_pair_command(&["--qr-file".into()]).expect("command result");
        assert_eq!(exit, 2);
    }
}
