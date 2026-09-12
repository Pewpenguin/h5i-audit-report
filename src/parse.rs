//! Parse and validate `h5i browser audit --json` session audits.

use serde_json::Value;

use crate::model::Audit;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    message: String,
}

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

/// Parse a session audit from JSON text.
///
/// Rejects the root array produced by `h5i browser audit --json --no-session`.
/// Does not reorder `events`.
pub fn parse_audit(input: &str) -> Result<Audit, Error> {
    let value: Value =
        serde_json::from_str(input).map_err(|e| Error::new(format!("invalid JSON: {e}")))?;
    parse_audit_value(value)
}

pub fn parse_audit_value(value: Value) -> Result<Audit, Error> {
    if value.is_array() {
        return Err(Error::new(
            "unsupported input: root JSON array looks like \
             `h5i browser audit --json --no-session` (sessionless helper log). \
             h5i-audit-report expects a session audit object from \
             `h5i browser audit --json`",
        ));
    }

    serde_json::from_value(value).map_err(|e| Error::new(format!("invalid session audit: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Availability, Confinement, Engine, EventKind, EventLane, Grade, Placement, SessionLane,
        State,
    };
    use serde_json::json;

    fn fixture(events: Value, dropped: u64) -> Value {
        json!({
            "session": {
                "id": "br_test",
                "url": "https://example.com/",
                "placement": {"kind": "host"},
                "engine": "h5i-light",
                "lane": "engine-claimed",
                "started_at": "2026-01-01T00:00:00.000000Z",
                "state": "closed",
                "policy_digest": "sha256:abc",
                "ended_at": "2026-01-01T00:01:00.000000Z",
                "end_reason": "closed by the user"
            },
            "sources": {
                "actions": "empty",
                "requests": "empty",
                "control": "empty"
            },
            "events": events,
            "dropped": dropped
        })
    }

    fn envelope(id: u64, lane: &str, grade: &str, kind_fields: Value) -> Value {
        let mut event = json!({
            "id": id,
            "observed_at": "2026-01-01T00:00:01.000000Z",
            "lane": lane,
            "grade": grade,
        });
        let obj = event.as_object_mut().unwrap();
        for (k, v) in kind_fields.as_object().unwrap() {
            obj.insert(k.clone(), v.clone());
        }
        event
    }

    #[test]
    fn valid_minimal_session_audit() {
        let audit = parse_audit_value(fixture(json!([]), 0)).unwrap();
        assert_eq!(audit.session.id, "br_test");
        assert_eq!(audit.session.url, "https://example.com/");
        assert_eq!(audit.session.placement, Placement::Host);
        assert_eq!(audit.session.engine, Engine::H5iLight);
        assert_eq!(audit.session.lane, SessionLane::EngineClaimed);
        assert_eq!(audit.session.state, State::Closed);
        assert_eq!(audit.session.policy_digest, "sha256:abc");
        assert!(audit.events.is_empty());
        assert_eq!(audit.dropped, 0);
        assert_eq!(audit.sources.actions, Availability::Empty);
        assert_eq!(audit.sources.helpers, Availability::Empty);
    }

    #[test]
    fn valid_request_event() {
        let event = envelope(
            1,
            "box-claimed",
            "fail-closed",
            json!({
                "claimed_at": "2026-01-01T00:00:00.500000Z",
                "kind": "request",
                "seq": 7,
                "method": "GET",
                "url": "https://example.com/",
                "initiator": "navigation",
                "allowed": true
            }),
        );
        let mut audit = fixture(json!([event]), 0);
        audit["sources"]["requests"] = json!("read");
        audit["session"]["state"] = json!("live");
        let audit = parse_audit_value(audit).unwrap();

        assert_eq!(audit.events.len(), 1);
        let event = &audit.events[0];
        assert_eq!(event.id, 1);
        assert_eq!(event.lane, EventLane::BoxClaimed);
        assert_eq!(event.grade, Grade::FailClosed);
        assert_eq!(
            event.claimed_at.as_deref(),
            Some("2026-01-01T00:00:00.500000Z")
        );
        match &event.kind {
            EventKind::Request {
                seq,
                method,
                url,
                initiator,
                allowed,
                denied_reason,
            } => {
                assert_eq!(*seq, 7);
                assert_eq!(method, "GET");
                assert_eq!(url, "https://example.com/");
                assert_eq!(initiator, "navigation");
                assert!(*allowed);
                assert!(denied_reason.is_none());
            }
            other => panic!("expected request, got {other:?}"),
        }
    }

    #[test]
    fn denied_request_with_reason() {
        let event = envelope(
            2,
            "box-claimed",
            "fail-closed",
            json!({
                "kind": "request",
                "seq": 1,
                "method": "GET",
                "url": "https://tracker.example/px",
                "initiator": "subresource",
                "allowed": false,
                "denied_reason": "origin is not in the allowlist"
            }),
        );
        let mut audit = fixture(json!([event]), 0);
        audit["sources"]["requests"] = json!("read");
        let audit = parse_audit_value(audit).unwrap();

        match &audit.events[0].kind {
            EventKind::Request {
                allowed,
                denied_reason,
                ..
            } => {
                assert!(!*allowed);
                assert_eq!(
                    denied_reason.as_deref(),
                    Some("origin is not in the allowlist")
                );
            }
            other => panic!("expected request, got {other:?}"),
        }
    }

    #[test]
    fn unknown_event_kind_is_preserved() {
        let event = envelope(
            9,
            "host-observed",
            "best-effort",
            json!({
                "kind": "navigated",
                "url": "https://example.com/next"
            }),
        );
        let audit = parse_audit_value(fixture(json!([event]), 0)).unwrap();
        match &audit.events[0].kind {
            EventKind::Unknown { kind, fields } => {
                assert_eq!(kind, "navigated");
                assert_eq!(
                    fields.get("url").and_then(Value::as_str),
                    Some("https://example.com/next")
                );
            }
            other => panic!("expected unknown, got {other:?}"),
        }
    }

    #[test]
    fn event_order_is_preserved() {
        let events = json!([
            {
                "id": 3,
                "observed_at": "2026-01-01T00:00:03.000000Z",
                "lane": "box-claimed",
                "grade": "best-effort",
                "kind": "agent-action",
                "action": "click @e1",
                "forwarded": true
            },
            {
                "id": 1,
                "observed_at": "2026-01-01T00:00:01.000000Z",
                "lane": "host-observed",
                "grade": "fail-closed",
                "kind": "lifecycle",
                "state": "opened",
                "reason": "https://example.com/"
            },
            {
                "id": 2,
                "observed_at": "2026-01-01T00:00:02.000000Z",
                "lane": "host-observed",
                "grade": "fail-closed",
                "kind": "control",
                "holder": "human",
                "note": "taken"
            }
        ]);
        let mut audit = fixture(events, 0);
        audit["sources"]["actions"] = json!("read");
        let audit = parse_audit_value(audit).unwrap();
        let ids: Vec<u64> = audit.events.iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![3, 1, 2], "parser must not reorder events");
    }

    #[test]
    fn malformed_root_is_rejected() {
        let err = parse_audit("null").unwrap_err();
        assert!(
            err.message().contains("invalid session audit"),
            "{}",
            err.message()
        );
    }

    #[test]
    fn no_session_array_is_rejected() {
        let err = parse_audit_value(json!([{
            "at": "2026-01-01T00:00:00Z",
            "name": "yt-dlp",
            "argv": ["--version"]
        }]))
        .unwrap_err();
        assert!(err.message().contains("--no-session"), "{}", err.message());
        assert!(err.message().contains("sessionless"), "{}", err.message());
    }

    #[test]
    fn missing_session_is_rejected() {
        let mut audit = fixture(json!([]), 0);
        audit.as_object_mut().unwrap().remove("session");
        let err = parse_audit_value(audit).unwrap_err();
        assert!(err.message().contains("session"), "{}", err.message());
    }

    #[test]
    fn missing_session_id_is_rejected() {
        let mut audit = fixture(json!([]), 0);
        audit["session"].as_object_mut().unwrap().remove("id");
        let err = parse_audit_value(audit).unwrap_err();
        assert!(err.message().contains("id"), "{}", err.message());
    }

    #[test]
    fn missing_events_is_rejected() {
        let mut audit = fixture(json!([]), 0);
        audit.as_object_mut().unwrap().remove("events");
        let err = parse_audit_value(audit).unwrap_err();
        assert!(err.message().contains("events"), "{}", err.message());
    }

    #[test]
    fn unavailable_source_is_preserved() {
        let mut audit = fixture(json!([]), 0);
        audit["sources"]["actions"] = json!("unavailable");
        audit["sources"]["requests"] = json!("unavailable");
        let audit = parse_audit_value(audit).unwrap();
        assert_eq!(audit.sources.actions, Availability::Unavailable);
        assert_eq!(audit.sources.requests, Availability::Unavailable);
        assert_ne!(audit.sources.actions, Availability::Empty);
    }

    #[test]
    fn dropped_count_is_parsed() {
        let audit = parse_audit_value(fixture(json!([]), 42)).unwrap();
        assert_eq!(audit.dropped, 42);
    }

    #[test]
    fn unknown_string_enums_are_preserved() {
        let mut audit = fixture(json!([]), 0);
        audit["session"]["engine"] = json!("future-engine");
        audit["session"]["lane"] = json!("future-lane");
        audit["session"]["state"] = json!("hibernating");
        audit["sources"]["actions"] = json!("archived");

        let audit = parse_audit_value(audit).unwrap();
        assert_eq!(
            audit.session.engine,
            Engine::Unknown("future-engine".into())
        );
        assert_eq!(
            audit.session.lane,
            SessionLane::Unknown("future-lane".into())
        );
        assert_eq!(audit.session.state, State::Unknown("hibernating".into()));
        assert_eq!(
            audit.sources.actions,
            Availability::Unknown("archived".into())
        );
    }

    #[test]
    fn unknown_event_lane_and_grade_are_preserved() {
        let event = envelope(
            1,
            "side-channel",
            "optimistic",
            json!({
                "kind": "lifecycle",
                "state": "opened"
            }),
        );
        let audit = parse_audit_value(fixture(json!([event]), 0)).unwrap();
        assert_eq!(
            audit.events[0].lane,
            EventLane::Unknown("side-channel".into())
        );
        assert_eq!(audit.events[0].grade, Grade::Unknown("optimistic".into()));
        assert!(matches!(audit.events[0].kind, EventKind::Lifecycle { .. }));
    }

    #[test]
    fn unknown_placement_kind_is_preserved() {
        let mut audit = fixture(json!([]), 0);
        audit["session"]["placement"] = json!({
            "kind": "vm",
            "image": "alpine"
        });
        let audit = parse_audit_value(audit).unwrap();
        match audit.session.placement {
            Placement::Unknown { kind, fields } => {
                assert_eq!(kind, "vm");
                assert_eq!(fields.get("image").and_then(Value::as_str), Some("alpine"));
            }
            other => panic!("expected unknown placement, got {other:?}"),
        }
    }

    #[test]
    fn unknown_confinement_kind_is_preserved() {
        let mut audit = fixture(json!([]), 0);
        audit["session"]["confinement"] = json!({
            "kind": "bubblewrap",
            "profile": "strict"
        });
        let audit = parse_audit_value(audit).unwrap();
        match audit.session.confinement {
            Some(Confinement::Unknown { kind, fields }) => {
                assert_eq!(kind, "bubblewrap");
                assert_eq!(
                    fields.get("profile").and_then(Value::as_str),
                    Some("strict")
                );
            }
            other => panic!("expected unknown confinement, got {other:?}"),
        }
    }

    #[test]
    fn known_box_placement_still_parses() {
        let mut audit = fixture(json!([]), 0);
        audit["session"]["placement"] = json!({"kind": "box", "name": "web"});
        let audit = parse_audit_value(audit).unwrap();
        assert_eq!(
            audit.session.placement,
            Placement::Box { name: "web".into() }
        );
    }
}
