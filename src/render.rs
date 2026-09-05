//! Self-contained HTML report for a session audit.

use crate::model::{
    Audit, Availability, Engine, Event, EventKind, EventLane, Grade, Placement, SessionLane,
    Sources, State,
};
use serde_json::Value;

/// Render a complete, self-contained HTML report.
pub fn render_report(audit: &Audit) -> String {
    let mut out = String::with_capacity(8 * 1024);
    out.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    out.push_str("<title>h5i audit report — ");
    out.push_str(&esc(&audit.session.id));
    out.push_str("</title>\n<style>\n");
    out.push_str(CSS);
    out.push_str("\n</style>\n</head>\n<body>\n");

    out.push_str("<header>\n<h1>h5i audit report</h1>\n</header>\n");

    render_session(&mut out, audit);
    render_sources(&mut out, &audit.sources, audit.dropped);
    render_counts(&mut out, audit);
    render_filters(&mut out, audit);
    render_timeline(&mut out, audit);

    out.push_str("<script>\n");
    out.push_str(JS);
    out.push_str("\n</script>\n</body>\n</html>\n");
    out
}

fn render_session(out: &mut String, audit: &Audit) {
    let s = &audit.session;
    out.push_str("<section>\n<h2>Session</h2>\n<dl class=\"summary\">\n");
    row(out, "ID", &s.id);
    if let Some(name) = &s.name {
        row(out, "Name", name);
    }
    row(out, "URL", &s.url);
    row(out, "Placement", &placement_label(&s.placement));
    row(out, "Engine", engine_label(s.engine));
    row(out, "Session lane", session_lane_label(s.lane));
    row(out, "State", state_label(s.state));
    row(out, "Started", &s.started_at);
    row(out, "Ended", s.ended_at.as_deref().unwrap_or("—"));
    row(out, "End reason", s.end_reason.as_deref().unwrap_or("—"));
    row(out, "Policy digest", &s.policy_digest);
    if !s.identity.is_empty() {
        row(out, "Identity", &s.identity);
    }
    out.push_str("</dl>\n</section>\n");
}

fn render_sources(out: &mut String, sources: &Sources, dropped: u64) {
    out.push_str("<section>\n<h2>Evidence sources</h2>\n<ul class=\"sources\">\n");
    source_item(out, "actions", sources.actions);
    source_item(out, "requests", sources.requests);
    source_item(out, "control", sources.control);
    source_item(out, "helpers", sources.helpers);
    source_item(out, "messages", sources.messages);
    out.push_str("</ul>\n");
    if dropped > 0 {
        out.push_str("<p class=\"dropped\">");
        out.push_str(&esc(&format!(
            "{dropped} older event(s) were dropped by the audit cap."
        )));
        out.push_str("</p>\n");
    }
    out.push_str("</section>\n");
}

fn source_item(out: &mut String, name: &str, availability: Availability) {
    let label = availability_label(availability);
    out.push_str("<li><span class=\"src-name\">");
    out.push_str(&esc(name));
    out.push_str("</span> <span class=\"avail ");
    out.push_str(availability_class(availability));
    out.push_str("\">");
    out.push_str(&esc(label));
    out.push_str("</span></li>\n");
}

fn render_counts(out: &mut String, audit: &Audit) {
    let mut actions = 0u64;
    let mut allowed = 0u64;
    let mut denied = 0u64;
    for event in &audit.events {
        match &event.kind {
            EventKind::AgentAction { .. } => actions += 1,
            EventKind::Request { allowed: true, .. } => allowed += 1,
            EventKind::Request { allowed: false, .. } => denied += 1,
            _ => {}
        }
    }
    out.push_str("<section>\n<h2>Summary</h2>\n<ul class=\"counts\">\n");
    out.push_str(&format!(
        "<li>Agent actions: <strong>{}</strong></li>\n",
        actions
    ));
    out.push_str(&format!(
        "<li>Allowed requests: <strong>{}</strong></li>\n",
        allowed
    ));
    out.push_str(&format!(
        "<li>Denied requests: <strong>{}</strong></li>\n",
        denied
    ));
    out.push_str("</ul>\n</section>\n");
}

fn render_filters(out: &mut String, audit: &Audit) {
    let mut kinds: Vec<String> = Vec::new();
    for event in &audit.events {
        let k = kind_name(&event.kind).to_string();
        if !kinds.iter().any(|x| x == &k) {
            kinds.push(k);
        }
    }

    out.push_str("<section class=\"filters\">\n<h2>Timeline</h2>\n");
    out.push_str("<div class=\"filter-bar\">\n");
    out.push_str("<label>Event type <select id=\"filter-type\">\n");
    out.push_str("<option value=\"all\">All</option>\n");
    for kind in &kinds {
        out.push_str("<option value=\"");
        out.push_str(&esc(kind));
        out.push_str("\">");
        out.push_str(&esc(kind));
        out.push_str("</option>\n");
    }
    out.push_str("</select></label>\n");
    out.push_str(
        "<label>Request decision <select id=\"filter-decision\">\n\
         <option value=\"all\">All</option>\n\
         <option value=\"allowed\">Allowed</option>\n\
         <option value=\"denied\">Denied</option>\n\
         </select></label>\n",
    );
    out.push_str("</div>\n");
}

fn render_timeline(out: &mut String, audit: &Audit) {
    out.push_str("<ol class=\"timeline\" id=\"timeline\">\n");
    for event in &audit.events {
        render_event(out, event);
    }
    out.push_str("</ol>\n</section>\n");
}

fn render_event(out: &mut String, event: &Event) {
    let kind = kind_name(&event.kind);
    let decision = match &event.kind {
        EventKind::Request { allowed: true, .. } => "allowed",
        EventKind::Request { allowed: false, .. } => "denied",
        _ => "",
    };
    let decision_class = match decision {
        "allowed" => " decision-allowed",
        "denied" => " decision-denied",
        _ => "",
    };

    out.push_str("<li class=\"event");
    out.push_str(decision_class);
    out.push_str("\" data-event data-kind=\"");
    out.push_str(&esc(kind));
    out.push_str("\" data-decision=\"");
    out.push_str(decision);
    out.push_str("\">\n");

    out.push_str("<div class=\"meta\">");
    out.push_str("<span class=\"eid\">#");
    out.push_str(&esc(&event.id.to_string()));
    out.push_str("</span> ");
    out.push_str("<time>");
    out.push_str(&esc(&event.observed_at));
    out.push_str("</time> ");
    out.push_str("<span class=\"lane ");
    out.push_str(event_lane_class(event.lane));
    out.push_str("\">");
    out.push_str(&esc(event_lane_label(event.lane)));
    out.push_str("</span> ");
    out.push_str("<span class=\"grade\">");
    out.push_str(&esc(grade_label(event.grade)));
    out.push_str("</span> ");
    out.push_str("<span class=\"kind\">");
    out.push_str(&esc(kind));
    out.push_str("</span>");
    if let Some(caused_by) = event.caused_by {
        out.push_str(" <span class=\"caused\">caused by #");
        out.push_str(&esc(&caused_by.to_string()));
        out.push_str("</span>");
    }
    if let Some(claimed_at) = &event.claimed_at {
        out.push_str(" <span class=\"claimed\">claimed ");
        out.push_str(&esc(claimed_at));
        out.push_str("</span>");
    }
    out.push_str("</div>\n");

    out.push_str("<div class=\"detail\">");
    render_kind_detail(out, &event.kind);
    out.push_str("</div>\n</li>\n");
}

fn render_kind_detail(out: &mut String, kind: &EventKind) {
    match kind {
        EventKind::Lifecycle { state, reason } => {
            out.push_str("state ");
            out.push_str(&esc(state));
            if let Some(reason) = reason {
                out.push_str(" — ");
                out.push_str(&esc(reason));
            }
        }
        EventKind::AgentAction { action, forwarded } => {
            out.push_str(if *forwarded { "verb " } else { "verb ! " });
            out.push_str(&esc(action));
        }
        EventKind::Request {
            seq,
            method,
            url,
            initiator,
            allowed,
            denied_reason,
        } => {
            out.push_str(&esc(&format!("#{seq} ")));
            out.push_str(&esc(method));
            out.push(' ');
            out.push_str(&esc(url));
            out.push_str(" <span class=\"initiator\">");
            out.push_str(&esc(initiator));
            out.push_str("</span> ");
            if *allowed {
                out.push_str("<span class=\"badge allowed\">Allowed</span>");
            } else {
                out.push_str("<span class=\"badge denied\">Denied</span>");
                if let Some(reason) = denied_reason {
                    out.push_str(" — ");
                    out.push_str(&esc(reason));
                }
            }
        }
        EventKind::Response {
            seq,
            status,
            bytes,
            duration_ms,
            error,
        } => {
            out.push_str(&esc(&format!("#{seq}")));
            if let Some(status) = status {
                out.push_str(&esc(&format!(" status {status}")));
            }
            if let Some(bytes) = bytes {
                out.push_str(&esc(&format!(" · {bytes} bytes")));
            }
            if let Some(ms) = duration_ms {
                out.push_str(&esc(&format!(" · {ms} ms")));
            }
            if let Some(error) = error {
                out.push_str(" · error ");
                out.push_str(&esc(error));
            }
            if status.is_none() && error.is_none() {
                out.push_str(" · no response");
            }
        }
        EventKind::PolicyVerdict { subject, reason } => {
            out.push_str("refused ");
            out.push_str(&esc(subject));
            out.push_str(" — ");
            out.push_str(&esc(reason));
        }
        EventKind::Control { holder, note } => {
            out.push_str("control → ");
            out.push_str(&esc(holder));
            if let Some(note) = note {
                out.push_str(" — ");
                out.push_str(&esc(note));
            }
        }
        EventKind::Helper {
            name,
            argv,
            status,
            note,
        } => {
            out.push_str("helper ");
            out.push_str(&esc(name));
            out.push(' ');
            out.push_str(&esc(&argv.join(" ")));
            if let Some(status) = status {
                out.push_str(&esc(&format!(" (exit {status})")));
            }
            if let Some(note) = note {
                out.push_str(" — ");
                out.push_str(&esc(note));
            }
        }
        EventKind::Unknown { kind, fields } => {
            out.push_str("unsupported kind ");
            out.push_str(&esc(kind));
            if !fields.is_empty() {
                out.push_str("<ul class=\"unknown-fields\">");
                for (key, value) in fields {
                    out.push_str("<li><code>");
                    out.push_str(&esc(key));
                    out.push_str("</code>: ");
                    out.push_str(&esc(&value_preview(value)));
                    out.push_str("</li>");
                }
                out.push_str("</ul>");
            }
        }
    }
}

fn value_preview(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn row(out: &mut String, label: &str, value: &str) {
    out.push_str("<dt>");
    out.push_str(&esc(label));
    out.push_str("</dt><dd>");
    out.push_str(&esc(value));
    out.push_str("</dd>\n");
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn kind_name(kind: &EventKind) -> &str {
    match kind {
        EventKind::Lifecycle { .. } => "lifecycle",
        EventKind::AgentAction { .. } => "agent-action",
        EventKind::Request { .. } => "request",
        EventKind::Response { .. } => "response",
        EventKind::PolicyVerdict { .. } => "policy-verdict",
        EventKind::Control { .. } => "control",
        EventKind::Helper { .. } => "helper",
        EventKind::Unknown { kind, .. } => kind.as_str(),
    }
}

fn placement_label(placement: &Placement) -> String {
    match placement {
        Placement::Host => "host".into(),
        Placement::Box { name } => format!("box ({name})"),
    }
}

fn engine_label(engine: Engine) -> &'static str {
    match engine {
        Engine::H5iLight => "h5i-light",
        Engine::Chromium => "chromium",
    }
}

fn session_lane_label(lane: SessionLane) -> &'static str {
    match lane {
        SessionLane::EngineClaimed => "engine-claimed",
        SessionLane::HostObserved => "host-observed",
    }
}

fn state_label(state: State) -> &'static str {
    match state {
        State::Live => "live",
        State::Closed => "closed",
        State::Died => "died",
        State::Expired => "expired",
        State::Evicted => "evicted",
    }
}

fn availability_label(a: Availability) -> &'static str {
    match a {
        Availability::Read => "read",
        Availability::Empty => "empty",
        Availability::Unavailable => "unavailable",
        Availability::Partial => "partial",
    }
}

fn availability_class(a: Availability) -> &'static str {
    match a {
        Availability::Read => "avail-read",
        Availability::Empty => "avail-empty",
        Availability::Unavailable => "avail-unavailable",
        Availability::Partial => "avail-partial",
    }
}

fn event_lane_label(lane: EventLane) -> &'static str {
    match lane {
        EventLane::HostObserved => "host-observed",
        EventLane::BoxClaimed => "box-claimed",
    }
}

fn event_lane_class(lane: EventLane) -> &'static str {
    match lane {
        EventLane::HostObserved => "lane-host",
        EventLane::BoxClaimed => "lane-box",
    }
}

fn grade_label(grade: Grade) -> &'static str {
    match grade {
        Grade::FailClosed => "fail-closed",
        Grade::BestEffort => "best-effort",
    }
}

const CSS: &str = r#"
:root {
  --bg: #f7f5f1;
  --ink: #1c1b19;
  --muted: #5c5852;
  --line: #d9d3c8;
  --host: #1f6b4a;
  --box: #8a5a12;
  --deny: #8b1e1e;
  --allow: #1f6b4a;
  --partial: #8a5a12;
  --unavailable: #8b1e1e;
}
* { box-sizing: border-box; }
body {
  margin: 0 auto;
  max-width: 52rem;
  padding: 1.5rem 1.25rem 3rem;
  font: 15px/1.45 "Segoe UI", system-ui, sans-serif;
  color: var(--ink);
  background: var(--bg);
}
h1 { font-size: 1.5rem; margin: 0 0 1rem; }
h2 { font-size: 1.1rem; margin: 1.75rem 0 0.75rem; }
.summary { display: grid; grid-template-columns: 9rem 1fr; gap: 0.35rem 1rem; margin: 0; }
.summary dt { color: var(--muted); }
.summary dd { margin: 0; word-break: break-word; }
.sources, .counts { list-style: none; padding: 0; margin: 0; }
.sources li, .counts li { padding: 0.25rem 0; }
.src-name { font-weight: 600; min-width: 6rem; display: inline-block; }
.avail { font-family: ui-monospace, monospace; font-size: 0.9em; }
.avail-read { color: var(--allow); }
.avail-empty { color: var(--muted); }
.avail-unavailable { color: var(--unavailable); font-weight: 600; }
.avail-partial { color: var(--partial); font-weight: 600; }
.dropped { color: var(--partial); }
.filter-bar { display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 0.75rem; }
.timeline { list-style: none; padding: 0; margin: 0; border-top: 1px solid var(--line); }
.event { padding: 0.75rem 0; border-bottom: 1px solid var(--line); }
.meta { color: var(--muted); font-size: 0.85rem; display: flex; flex-wrap: wrap; gap: 0.4rem 0.65rem; }
.eid, .kind { font-family: ui-monospace, monospace; color: var(--ink); }
.lane-host { color: var(--host); font-weight: 600; }
.lane-box { color: var(--box); font-weight: 600; }
.detail { margin-top: 0.35rem; word-break: break-word; }
.badge { font-size: 0.8rem; font-weight: 700; text-transform: uppercase; }
.badge.allowed { color: var(--allow); }
.badge.denied { color: var(--deny); }
.decision-denied .detail { color: var(--deny); }
.initiator { color: var(--muted); font-size: 0.9em; }
.unknown-fields { margin: 0.35rem 0 0; padding-left: 1.2rem; }
"#;

const JS: &str = r#"
(function () {
  var typeSel = document.getElementById("filter-type");
  var decSel = document.getElementById("filter-decision");
  if (!typeSel || !decSel) return;
  function apply() {
    var type = typeSel.value;
    var decision = decSel.value;
    var nodes = document.querySelectorAll("[data-event]");
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      var kind = el.getAttribute("data-kind") || "";
      var dec = el.getAttribute("data-decision") || "";
      var show = true;
      if (type !== "all" && kind !== type) show = false;
      if (decision !== "all" && dec !== decision) show = false;
      el.hidden = !show;
    }
  }
  typeSel.addEventListener("change", apply);
  decSel.addEventListener("change", apply);
})();
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Event, EventLane, Grade, Session, Sources};
    use serde_json::json;

    fn sample_audit(events: Vec<Event>) -> Audit {
        Audit {
            session: Session {
                id: "br_test".into(),
                name: None,
                url: "https://example.com/".into(),
                placement: Placement::Host,
                engine: Engine::H5iLight,
                lane: SessionLane::EngineClaimed,
                started_at: "2026-01-01T00:00:00.000000Z".into(),
                ended_at: Some("2026-01-01T00:01:00.000000Z".into()),
                end_reason: Some("closed by the user".into()),
                state: State::Closed,
                policy_digest: "sha256:abc".into(),
                identity: String::new(),
                identity_digest: String::new(),
                confinement: None,
                restored_from: None,
            },
            sources: Sources {
                actions: Availability::Read,
                requests: Availability::Unavailable,
                control: Availability::Empty,
                helpers: Availability::Empty,
                messages: Availability::Partial,
            },
            events,
            dropped: 0,
        }
    }

    fn envelope(id: u64, kind: EventKind) -> Event {
        Event {
            id,
            observed_at: format!("2026-01-01T00:00:0{id}.000000Z"),
            lane: EventLane::BoxClaimed,
            grade: Grade::FailClosed,
            caused_by: None,
            claimed_at: None,
            kind,
        }
    }

    #[test]
    fn basic_report_generation() {
        let html = render_report(&sample_audit(vec![]));
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("</html>"));
        assert!(html.contains("<style>"));
        assert!(html.contains("<script>"));
    }

    #[test]
    fn session_fields_appear() {
        let html = render_report(&sample_audit(vec![]));
        assert!(html.contains("br_test"));
        assert!(html.contains("https://example.com/"));
        assert!(html.contains("h5i-light"));
        assert!(html.contains("closed"));
        assert!(html.contains("sha256:abc"));
        assert!(html.contains("closed by the user"));
        assert!(html.contains("2026-01-01T00:00:00.000000Z"));
        assert!(html.contains("2026-01-01T00:01:00.000000Z"));
    }

    #[test]
    fn sources_distinguish_unavailable() {
        let html = render_report(&sample_audit(vec![]));
        assert!(html.contains("avail-unavailable"));
        assert!(html.contains(">unavailable<"));
        assert!(html.contains("avail-partial"));
        assert!(html.contains("avail-empty"));
        assert!(html.contains("avail-read"));
    }

    #[test]
    fn request_allowed_and_denied() {
        let audit = sample_audit(vec![
            envelope(
                1,
                EventKind::Request {
                    seq: 1,
                    method: "GET".into(),
                    url: "https://example.com/".into(),
                    initiator: "navigation".into(),
                    allowed: true,
                    denied_reason: None,
                },
            ),
            envelope(
                2,
                EventKind::Request {
                    seq: 2,
                    method: "GET".into(),
                    url: "https://tracker.example/".into(),
                    initiator: "subresource".into(),
                    allowed: false,
                    denied_reason: Some("not allowlisted".into()),
                },
            ),
        ]);
        let html = render_report(&audit);
        assert!(html.contains("Allowed"));
        assert!(html.contains("Denied"));
        assert!(html.contains("not allowlisted"));
        assert!(html.contains("Allowed requests: <strong>1</strong>"));
        assert!(html.contains("Denied requests: <strong>1</strong>"));
    }

    #[test]
    fn event_order_is_preserved() {
        let audit = sample_audit(vec![
            envelope(
                3,
                EventKind::AgentAction {
                    action: "click".into(),
                    forwarded: true,
                },
            ),
            envelope(
                1,
                EventKind::Lifecycle {
                    state: "opened".into(),
                    reason: None,
                },
            ),
            envelope(
                2,
                EventKind::Control {
                    holder: "human".into(),
                    note: None,
                },
            ),
        ]);
        let html = render_report(&audit);
        let i3 = html.find("<span class=\"eid\">#3</span>").unwrap();
        let i1 = html.find("<span class=\"eid\">#1</span>").unwrap();
        let i2 = html.find("<span class=\"eid\">#2</span>").unwrap();
        assert!(i3 < i1 && i1 < i2, "order broken: {i3} {i1} {i2}");
    }

    #[test]
    fn unknown_event_kind_is_rendered() {
        let mut fields = serde_json::Map::new();
        fields.insert("url".into(), json!("https://example.com/next"));
        let audit = sample_audit(vec![envelope(
            9,
            EventKind::Unknown {
                kind: "navigated".into(),
                fields,
            },
        )]);
        let html = render_report(&audit);
        assert!(html.contains("navigated"));
        assert!(html.contains("https://example.com/next"));
        assert!(html.contains("data-kind=\"navigated\""));
    }

    #[test]
    fn malicious_html_is_escaped() {
        let evil = "<script>alert(1)</script>";
        let audit = Audit {
            session: Session {
                id: evil.into(),
                name: None,
                url: evil.into(),
                placement: Placement::Host,
                engine: Engine::H5iLight,
                lane: SessionLane::EngineClaimed,
                started_at: evil.into(),
                ended_at: Some(evil.into()),
                end_reason: Some(evil.into()),
                state: State::Closed,
                policy_digest: evil.into(),
                identity: String::new(),
                identity_digest: String::new(),
                confinement: None,
                restored_from: None,
            },
            sources: Sources {
                actions: Availability::Empty,
                requests: Availability::Empty,
                control: Availability::Empty,
                helpers: Availability::Empty,
                messages: Availability::Empty,
            },
            events: vec![envelope(
                1,
                EventKind::Request {
                    seq: 1,
                    method: "GET".into(),
                    url: evil.into(),
                    initiator: evil.into(),
                    allowed: false,
                    denied_reason: Some(evil.into()),
                },
            )],
            dropped: 0,
        };
        let html = render_report(&audit);
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[test]
    fn no_external_resource_references() {
        let html = render_report(&sample_audit(vec![]));
        let lower = html.to_ascii_lowercase();
        assert!(!lower.contains("cdn."));
        assert!(!lower.contains("@import"));
        assert!(!lower.contains("<link "));
        assert!(!lower.contains("src=\"http"));
        assert!(!lower.contains("src='http"));
        assert!(!lower.contains("href=\"http"));
        assert!(!lower.contains("href='http"));
    }
}
