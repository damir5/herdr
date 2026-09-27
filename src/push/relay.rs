//! Delivery through the publisher-run HerdrUp push relay (`POST <relay_url>/v1/send`).
//!
//! Used when this host has no APNs key of its own. The relay holds the key and
//! resolves the device from an opaque sealed capability (`hpr1.…`) that the app
//! obtained at enrollment. The daemon never parses the capability; it only sends
//! it back. Like [`super::apns`], delivery shells out to curl and passes the url,
//! headers and body on stdin, so neither the capability nor the message text
//! appears on argv.

use super::apns;

/// Prefix of a sealed relay capability.
const CAPABILITY_PREFIX: &str = "hpr1.";
/// Upper bound on a stored capability, so a garbage registration cannot bloat the store.
const MAX_CAPABILITY_LEN: usize = 512;

/// Relay push type. The relay checks it against the capability kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RelayPushType {
    Alert,
    LiveActivity,
}

impl RelayPushType {
    fn wire_name(self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::LiveActivity => "liveactivity",
        }
    }

    /// Same priorities as the direct path: 10 for alerts, 5 for Live Activity updates.
    fn priority(self) -> u8 {
        match self {
            Self::Alert => 10,
            Self::LiveActivity => 5,
        }
    }
}

/// Outcome of one relay send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RelayOutcome {
    Delivered,
    /// The relay reported the token as gone (410). Prune it, as for direct APNs.
    PruneToken,
    /// Rate limited (429) or relay/APNs failure (5xx). Keep the token.
    Transient,
    /// Any other rejection (e.g. 400 `invalid_capability`). Keep the token.
    Rejected,
}

/// A sealed capability is `hpr1.` followed by base64url (no padding), at most
/// 512 bytes in total. Anything else is refused at registration.
pub(crate) fn is_valid_capability(capability: &str) -> bool {
    capability.len() <= MAX_CAPABILITY_LEN
        && capability
            .strip_prefix(CAPABILITY_PREFIX)
            .is_some_and(|sealed| {
                !sealed.is_empty()
                    && sealed
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            })
}

pub(super) fn send_url(relay_url: &str) -> String {
    format!("{}/v1/send", relay_url.trim().trim_end_matches('/'))
}

/// The `/v1/send` request body. `payload` is the exact APNs JSON the direct path
/// sends (from [`apns::payload_body`] / [`apns::live_activity_payload`]); it is
/// embedded verbatim so direct and relay deliveries carry identical payloads.
pub(super) fn send_body(capability: &str, push_type: RelayPushType, payload: &str) -> String {
    format!(
        "{{\"capability\":{},\"push_type\":\"{}\",\"priority\":{},\"payload\":{payload}}}",
        serde_json::Value::String(capability.to_string()),
        push_type.wire_name(),
        push_type.priority(),
    )
}

/// The curl config fed on stdin: url, method, content type and the JSON body.
pub(super) fn build_curl_config(url: &str, body: &str) -> String {
    let mut config = String::new();
    config.push_str(&format!("url = {}\n", apns::quote_config_value(url)));
    config.push_str("request = \"POST\"\n");
    config.push_str(&format!(
        "header = {}\n",
        apns::quote_config_value("content-type: application/json")
    ));
    config.push_str(&format!("data = {}\n", apns::quote_config_value(body)));
    config
}

pub(super) fn classify_status(status: &str) -> RelayOutcome {
    match status {
        "200" => RelayOutcome::Delivered,
        "410" => RelayOutcome::PruneToken,
        "429" => RelayOutcome::Transient,
        status if status.len() == 3 && status.starts_with('5') => RelayOutcome::Transient,
        _ => RelayOutcome::Rejected,
    }
}

/// Diagnostic codes that may be logged: APNs reasons the relay forwards and the
/// relay's own error codes. The response body is remote input, so any other
/// text is reported as `other` and never reaches the log.
const LOGGABLE_REASONS: &[&str] = &[
    "BadDeviceToken",
    "Unregistered",
    "DeviceTokenNotForTopic",
    "TopicDisallowed",
    "TooManyRequests",
    "PayloadTooLarge",
    "ExpiredProviderToken",
    "InvalidProviderToken",
    "InternalServerError",
    "ServiceUnavailable",
    "invalid_capability",
    "invalid_request",
    "payload_too_large",
    "rate_limited",
    "not_configured",
];

/// The allowlisted `reason` (APNs) or `error` (relay) code of a relay response,
/// `other` for any unknown text, and `none` when the body carries neither.
fn reason_code(body: &str) -> &'static str {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return "none";
    };
    let Some(reason) = ["reason", "error"]
        .iter()
        .find_map(|key| value.get(*key).and_then(serde_json::Value::as_str))
    else {
        return "none";
    };
    LOGGABLE_REASONS
        .iter()
        .find(|known| **known == reason)
        .copied()
        .unwrap_or("other")
}

/// Send one payload to one capability through the relay. Best-effort: failures
/// are logged by status and reason only, never with the capability or payload.
pub(super) fn send(
    relay_url: &str,
    capability: &str,
    push_type: RelayPushType,
    payload: &str,
) -> RelayOutcome {
    let config = build_curl_config(
        &send_url(relay_url),
        &send_body(capability, push_type, payload),
    );
    let Some(stdout) = apns::run_curl_with_stdin_config(&config) else {
        return RelayOutcome::Transient;
    };
    let (body, status) = apns::split_body_status(&stdout);
    let outcome = classify_status(status);
    let reason = reason_code(body);
    // curl's `%{http_code}`; parsed so only a number is ever logged.
    let http_status = status.parse::<u16>().unwrap_or(0);
    match outcome {
        RelayOutcome::Delivered | RelayOutcome::PruneToken => {}
        RelayOutcome::Transient => tracing::warn!(
            status = http_status,
            reason = reason,
            push_type = push_type.wire_name(),
            "push relay delivery failed transiently"
        ),
        RelayOutcome::Rejected => tracing::warn!(
            status = http_status,
            reason = reason,
            push_type = push_type.wire_name(),
            "push relay rejected delivery"
        ),
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_validation_accepts_only_sealed_base64url() {
        assert!(is_valid_capability("hpr1.AbC-_09"));
        assert!(is_valid_capability(&format!("hpr1.{}", "a".repeat(507))));

        assert!(!is_valid_capability(""));
        assert!(!is_valid_capability("hpr1."));
        assert!(!is_valid_capability("hpr2.AbC"));
        assert!(!is_valid_capability("HPR1.AbC"));
        assert!(!is_valid_capability("AbC"));
        // Standard base64 and padding are not base64url-without-padding.
        assert!(!is_valid_capability("hpr1.ab+c"));
        assert!(!is_valid_capability("hpr1.ab/c"));
        assert!(!is_valid_capability("hpr1.abc="));
        assert!(!is_valid_capability("hpr1.ab c"));
        assert!(!is_valid_capability("hpr1.ab\"c"));
        assert!(!is_valid_capability("hpr1.abé"));
        // 513 bytes in total is one over the limit.
        assert!(!is_valid_capability(&format!("hpr1.{}", "a".repeat(508))));
    }

    #[test]
    fn relay_status_mapping() {
        assert_eq!(classify_status("200"), RelayOutcome::Delivered);
        assert_eq!(classify_status("410"), RelayOutcome::PruneToken);
        assert_eq!(classify_status("429"), RelayOutcome::Transient);
        assert_eq!(classify_status("500"), RelayOutcome::Transient);
        assert_eq!(classify_status("502"), RelayOutcome::Transient);
        assert_eq!(classify_status("503"), RelayOutcome::Transient);
        assert_eq!(classify_status("400"), RelayOutcome::Rejected);
        assert_eq!(classify_status("404"), RelayOutcome::Rejected);
        // curl prints 000 when it never got a response.
        assert_eq!(classify_status("000"), RelayOutcome::Rejected);
        assert_eq!(classify_status(""), RelayOutcome::Rejected);
    }

    #[test]
    fn relay_response_body_and_status_split_to_outcome() {
        let (body, status) =
            apns::split_body_status("{\"status\":410,\"reason\":\"Unregistered\"}\n410");
        assert_eq!(classify_status(status), RelayOutcome::PruneToken);
        assert_eq!(reason_code(body), "Unregistered");

        let (body, status) = apns::split_body_status("{\"error\":\"rate_limited\"}\n429");
        assert_eq!(classify_status(status), RelayOutcome::Transient);
        assert_eq!(reason_code(body), "rate_limited");

        let (_, status) = apns::split_body_status("{\"status\":200,\"apns_id\":\"x\"}\n200");
        assert_eq!(classify_status(status), RelayOutcome::Delivered);
    }

    #[test]
    fn reason_code_never_returns_remote_text() {
        assert_eq!(
            reason_code("{\"status\":400,\"reason\":\"BadDeviceToken\"}"),
            "BadDeviceToken"
        );
        assert_eq!(
            reason_code("{\"error\":\"invalid_capability\"}"),
            "invalid_capability"
        );
        // Unknown or hostile text (here echoing a capability) is reduced to `other`.
        assert_eq!(reason_code("{\"reason\":\"hpr1.SeCrEt\"}"), "other");
        assert_eq!(
            reason_code("{\"error\":\"rate_limited\\nforged log line\"}"),
            "other"
        );
        assert_eq!(reason_code("{\"reason\":\"unregistered\"}"), "other");
        assert_eq!(reason_code("{\"reason\":\"a\"}"), "other");
        assert_eq!(reason_code("{\"reason\":null}"), "none");
        assert_eq!(reason_code("<html>bad gateway hpr1.SeCrEt</html>"), "none");
        assert_eq!(reason_code(""), "none");
    }

    #[test]
    fn send_body_embeds_the_direct_payload_verbatim() {
        let payload =
            "{\"aps\":{\"alert\":{\"title\":\"a \\\"b\\\"\",\"body\":\"x\"}},\"pane_id\":\"w1-1\"}";
        let body = send_body("hpr1.AbC", RelayPushType::Alert, payload);
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["capability"], "hpr1.AbC");
        assert_eq!(value["push_type"], "alert");
        assert_eq!(value["priority"], 10);
        assert_eq!(
            value["payload"],
            serde_json::from_str::<serde_json::Value>(payload).unwrap()
        );

        let value: serde_json::Value = serde_json::from_str(&send_body(
            "hpr1.AbC",
            RelayPushType::LiveActivity,
            "{\"aps\":{}}",
        ))
        .unwrap();
        assert_eq!(value["push_type"], "liveactivity");
        assert_eq!(value["priority"], 5);
    }

    #[test]
    fn send_url_joins_base_without_double_slash() {
        assert_eq!(send_url("https://relay.test"), "https://relay.test/v1/send");
        assert_eq!(
            send_url("https://relay.test/"),
            "https://relay.test/v1/send"
        );
    }

    #[test]
    fn capability_and_body_travel_on_stdin_config_not_argv() {
        let capability = "hpr1.SeCrEtCaPaBiLiTy";
        let body = send_body(
            capability,
            RelayPushType::Alert,
            "{\"aps\":{\"alert\":{\"body\":\"hi\"}}}",
        );
        let config = build_curl_config("https://relay.test/v1/send", &body);

        let argv = apns::build_curl_argv();
        assert!(argv.iter().all(|arg| !arg.contains(capability)));
        assert!(argv.iter().all(|arg| !arg.contains("relay.test")));
        assert!(argv
            .iter()
            .all(|arg| !arg.starts_with("-d") && arg != "--data"));
        // curl reads its directives (and so the body) from stdin.
        assert_eq!(
            argv[argv.len() - 2..],
            ["--config".to_string(), "-".to_string()]
        );

        assert!(config.contains("url = \"https://relay.test/v1/send\"\n"));
        assert!(config.contains("request = \"POST\"\n"));
        assert!(config.contains("header = \"content-type: application/json\"\n"));
        // The body is quoted for the curl config and survives un-escaping intact.
        let data_line = config
            .lines()
            .find_map(|line| line.strip_prefix("data = "))
            .unwrap();
        let unquoted = data_line[1..data_line.len() - 1]
            .replace("\\\"", "\"")
            .replace("\\\\", "\\");
        assert_eq!(unquoted, body);
    }
}
