//! Types for `h5i browser audit --json` session audits.

use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Audit {
    pub session: Session,
    pub sources: Sources,
    pub events: Vec<Event>,
    pub dropped: u64,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Session {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub url: String,
    pub placement: Placement,
    pub engine: Engine,
    pub lane: SessionLane,
    pub started_at: String,
    #[serde(default)]
    pub ended_at: Option<String>,
    #[serde(default)]
    pub end_reason: Option<String>,
    pub state: State,
    pub policy_digest: String,
    #[serde(default)]
    pub identity: String,
    #[serde(default)]
    pub identity_digest: String,
    #[serde(default)]
    pub confinement: Option<Confinement>,
    #[serde(default)]
    pub restored_from: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    Host,
    Box {
        name: String,
    },
    Unknown {
        kind: String,
        fields: Map<String, Value>,
    },
}

impl<'de> Deserialize<'de> for Placement {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut map = Map::<String, Value>::deserialize(deserializer)?;
        let kind = take_kind(&mut map)?;
        match kind.as_str() {
            "host" => Ok(Placement::Host),
            "box" => {
                let name = match map.remove("name") {
                    Some(Value::String(s)) => s,
                    Some(other) => {
                        return Err(serde::de::Error::custom(format!(
                            "`placement.name` must be a string, got {other}"
                        )));
                    }
                    None => {
                        return Err(serde::de::Error::custom(
                            "missing field `name` for placement kind `box`",
                        ));
                    }
                };
                Ok(Placement::Box { name })
            }
            _ => Ok(Placement::Unknown { kind, fields: map }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Engine {
    H5iLight,
    Chromium,
    Unknown(String),
}

impl<'de> Deserialize<'de> for Engine {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "h5i-light" => Engine::H5iLight,
            "chromium" => Engine::Chromium,
            _ => Engine::Unknown(s),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionLane {
    EngineClaimed,
    HostObserved,
    Unknown(String),
}

impl<'de> Deserialize<'de> for SessionLane {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "engine-claimed" => SessionLane::EngineClaimed,
            "host-observed" => SessionLane::HostObserved,
            _ => SessionLane::Unknown(s),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Live,
    Closed,
    Died,
    Expired,
    Evicted,
    Unknown(String),
}

impl<'de> Deserialize<'de> for State {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "live" => State::Live,
            "closed" => State::Closed,
            "died" => State::Died,
            "expired" => State::Expired,
            "evicted" => State::Evicted,
            _ => State::Unknown(s),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confinement {
    Process,
    None {
        why: String,
    },
    /// A confinement kind this build does not model.
    Unknown {
        kind: String,
        fields: Map<String, Value>,
    },
}

impl<'de> Deserialize<'de> for Confinement {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut map = Map::<String, Value>::deserialize(deserializer)?;
        let kind = take_kind(&mut map)?;
        match kind.as_str() {
            "process" => Ok(Confinement::Process),
            "none" => {
                let why = match map.remove("why") {
                    Some(Value::String(s)) => s,
                    Some(other) => {
                        return Err(serde::de::Error::custom(format!(
                            "`confinement.why` must be a string, got {other}"
                        )));
                    }
                    None => {
                        return Err(serde::de::Error::custom(
                            "missing field `why` for confinement kind `none`",
                        ));
                    }
                };
                Ok(Confinement::None { why })
            }
            _ => Ok(Confinement::Unknown { kind, fields: map }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Sources {
    pub actions: Availability,
    pub requests: Availability,
    pub control: Availability,
    #[serde(default)]
    pub helpers: Availability,
    #[serde(default)]
    pub messages: Availability,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Availability {
    Read,
    /// Matches h5i's serde default for helpers/messages.
    #[default]
    Empty,
    Unavailable,
    Partial,
    Unknown(String),
}

impl<'de> Deserialize<'de> for Availability {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "read" => Availability::Read,
            "empty" => Availability::Empty,
            "unavailable" => Availability::Unavailable,
            "partial" => Availability::Partial,
            _ => Availability::Unknown(s),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub id: u64,
    pub observed_at: String,
    pub lane: EventLane,
    pub grade: Grade,
    pub caused_by: Option<u64>,
    pub claimed_at: Option<String>,
    pub kind: EventKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventLane {
    HostObserved,
    BoxClaimed,
    Unknown(String),
}

impl<'de> Deserialize<'de> for EventLane {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "host-observed" => EventLane::HostObserved,
            "box-claimed" => EventLane::BoxClaimed,
            _ => EventLane::Unknown(s),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Grade {
    FailClosed,
    BestEffort,
    Unknown(String),
}

impl<'de> Deserialize<'de> for Grade {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "fail-closed" => Grade::FailClosed,
            "best-effort" => Grade::BestEffort,
            _ => Grade::Unknown(s),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum EventKind {
    Lifecycle {
        state: String,
        reason: Option<String>,
    },
    AgentAction {
        action: String,
        forwarded: bool,
    },
    Request {
        seq: u64,
        method: String,
        url: String,
        initiator: String,
        allowed: bool,
        denied_reason: Option<String>,
    },
    Response {
        seq: u64,
        status: Option<u16>,
        bytes: Option<u64>,
        duration_ms: Option<u64>,
        error: Option<String>,
    },
    PolicyVerdict {
        subject: String,
        reason: String,
    },
    Control {
        holder: String,
        note: Option<String>,
    },
    Helper {
        name: String,
        argv: Vec<String>,
        status: Option<i32>,
        note: Option<String>,
    },
    /// Kind this build does not model. Remaining object fields after the envelope.
    Unknown {
        kind: String,
        fields: Map<String, Value>,
    },
}

impl<'de> Deserialize<'de> for Event {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            id: u64,
            observed_at: String,
            lane: EventLane,
            grade: Grade,
            #[serde(default)]
            caused_by: Option<u64>,
            #[serde(default)]
            claimed_at: Option<String>,
            kind: String,
            #[serde(flatten)]
            rest: Map<String, Value>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let kind = match wire.kind.as_str() {
            "lifecycle" => {
                let b: Lifecycle = serde_json::from_value(Value::Object(wire.rest))
                    .map_err(serde::de::Error::custom)?;
                EventKind::Lifecycle {
                    state: b.state,
                    reason: b.reason,
                }
            }
            "agent-action" => {
                let b: AgentAction = serde_json::from_value(Value::Object(wire.rest))
                    .map_err(serde::de::Error::custom)?;
                EventKind::AgentAction {
                    action: b.action,
                    forwarded: b.forwarded,
                }
            }
            "request" => {
                let b: Request = serde_json::from_value(Value::Object(wire.rest))
                    .map_err(serde::de::Error::custom)?;
                EventKind::Request {
                    seq: b.seq,
                    method: b.method,
                    url: b.url,
                    initiator: b.initiator,
                    allowed: b.allowed,
                    denied_reason: b.denied_reason,
                }
            }
            "response" => {
                let b: Response = serde_json::from_value(Value::Object(wire.rest))
                    .map_err(serde::de::Error::custom)?;
                EventKind::Response {
                    seq: b.seq,
                    status: b.status,
                    bytes: b.bytes,
                    duration_ms: b.duration_ms,
                    error: b.error,
                }
            }
            "policy-verdict" => {
                let b: PolicyVerdict = serde_json::from_value(Value::Object(wire.rest))
                    .map_err(serde::de::Error::custom)?;
                EventKind::PolicyVerdict {
                    subject: b.subject,
                    reason: b.reason,
                }
            }
            "control" => {
                let b: Control = serde_json::from_value(Value::Object(wire.rest))
                    .map_err(serde::de::Error::custom)?;
                EventKind::Control {
                    holder: b.holder,
                    note: b.note,
                }
            }
            "helper" => {
                let b: Helper = serde_json::from_value(Value::Object(wire.rest))
                    .map_err(serde::de::Error::custom)?;
                EventKind::Helper {
                    name: b.name,
                    argv: b.argv,
                    status: b.status,
                    note: b.note,
                }
            }
            _ => EventKind::Unknown {
                kind: wire.kind,
                fields: wire.rest,
            },
        };

        Ok(Event {
            id: wire.id,
            observed_at: wire.observed_at,
            lane: wire.lane,
            grade: wire.grade,
            caused_by: wire.caused_by,
            claimed_at: wire.claimed_at,
            kind,
        })
    }
}

fn take_kind<E: serde::de::Error>(map: &mut Map<String, Value>) -> Result<String, E> {
    match map.remove("kind") {
        Some(Value::String(s)) => Ok(s),
        Some(other) => Err(E::custom(format!("`kind` must be a string, got {other}"))),
        None => Err(E::custom("missing field `kind`")),
    }
}

#[derive(Deserialize)]
struct Lifecycle {
    state: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
struct AgentAction {
    action: String,
    forwarded: bool,
}

#[derive(Deserialize)]
struct Request {
    seq: u64,
    method: String,
    url: String,
    initiator: String,
    allowed: bool,
    #[serde(default)]
    denied_reason: Option<String>,
}

#[derive(Deserialize)]
struct Response {
    seq: u64,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    bytes: Option<u64>,
    #[serde(default)]
    duration_ms: Option<u64>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct PolicyVerdict {
    subject: String,
    reason: String,
}

#[derive(Deserialize)]
struct Control {
    holder: String,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Deserialize)]
struct Helper {
    name: String,
    argv: Vec<String>,
    #[serde(default)]
    status: Option<i32>,
    #[serde(default)]
    note: Option<String>,
}
