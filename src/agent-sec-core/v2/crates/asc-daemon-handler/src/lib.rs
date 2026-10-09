//! Inbound daemon protocol adapters for application use cases.
//!
//! This crate translates bounded transport requests into versioned daemon
//! protocol calls, applies server-owned authorization, routes accepted calls to
//! application ports, and projects application or transport failures back into
//! protocol responses. Process bootstrap and transport execution remain in
//! `asc-daemon` and `asc-daemon-service`, respectively.

#![forbid(unsafe_code)]

mod action;
mod correlation;
mod dispatcher;
mod observability_query;
mod pap;
mod pii;
mod prompt_scan;
mod query;
mod rejection;
mod skill_sec;

pub use correlation::{
    CorrelatedSecurityEvent, CorrelationCandidates, FALLBACK_TIME_WINDOW_SECONDS, MatchReason,
    ObservabilityRecordFields, SecurityCorrelationService, ZERO_RUN_ID,
};
pub use dispatcher::DaemonDispatcher;
pub use observability_query::{
    ObservabilityQueries, ObservabilityQueryHandler, SqliteObservabilityQuerySource,
};
pub use query::{SecurityEventQueries, SecurityQueryHandler, SqliteEventQuerySource};
pub use rejection::JsonRejectionEncoder;
