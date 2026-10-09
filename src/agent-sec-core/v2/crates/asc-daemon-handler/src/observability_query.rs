//! Owner-scoped observability query projection over the daemon's read stores.
//!
//! This is the v2 restoration of v1's `obs.*` dashboard query family
//! (`agent_sec_cli/daemon/handlers/security_query.py`). The security posture
//! matches the `sec.*` restoration: v1 isolated owners by running one daemon
//! per user over a per-user database, while v2 serves many local UIDs from
//! one system store, so every read here — observability rows, the per-session
//! and per-run security counts, and the timeline's correlated security
//! events — carries a [`QueryScope`] derived from the kernel-authenticated
//! peer. The methods became servable only after the system observability
//! store gained its owner column (#6605); serving them earlier would have
//! turned the daemon into a cross-UID reader (issue #6608).

use std::path::Path;

use asc_daemon_core::Principal;
use asc_daemon_protocol::{DaemonResponse, ObsQueryParams, RequestId, error_code, method};
use asc_observability::{RunSummary, SessionSummary};
use asc_persistence_sqlite::QueryScope;
use asc_persistence_sqlite::observability::{
    EpochWindow, ObservabilityEventRow, Page, SystemObservabilityReader,
};
use asc_persistence_sqlite::security_events::{
    CorrelationRequest, EventFilters, GroupCounts, SqliteEventReader,
};
use asc_security_events::CorrelationCandidate;
use asc_sqlite_kernel::KernelError;
use serde_json::{Map, Value, json};

use crate::correlation::{
    CorrelationCandidates, ObservabilityRecordFields, SecurityCorrelationService,
};
use crate::query::{bounded, bounded_message, event_payload, invalid_parameters, iso_to_epoch};

/// v1's default page size for the two list methods.
const DEFAULT_LIMIT: u64 = 100;
/// v1's hard cap on one page of any `obs.*` method, and the timeline's default.
const MAX_LIMIT: u64 = 1000;
/// v1's hard cap on `offset` (`(1 << 63) - 1`).
const MAX_OFFSET: u64 = 9_223_372_036_854_775_807;

/// Read-only observability queries one daemon can serve, scoped per owner.
///
/// The port keeps the handler free of storage decisions; the daemon
/// composition root binds it to the same databases the writers and the state
/// migrator use.
pub trait ObservabilityQueries: CorrelationCandidates {
    /// Returns one owner scope's sessions, most recent activity first.
    fn list_sessions(
        &self,
        window: EpochWindow,
        page: Page,
        scope: &QueryScope,
    ) -> Vec<SessionSummary>;
    /// Returns the number of distinct sessions of one owner scope.
    fn count_sessions(&self, window: EpochWindow, scope: &QueryScope) -> u64;
    /// Returns one owner scope's runs of `session_id`, chronological.
    fn list_runs(
        &self,
        session_id: &str,
        window: EpochWindow,
        page: Page,
        scope: &QueryScope,
    ) -> Vec<RunSummary>;
    /// Returns the number of distinct runs of `session_id` in one owner scope.
    fn count_runs(&self, session_id: &str, window: EpochWindow, scope: &QueryScope) -> u64;
    /// Returns one owner scope's rows of one run, oldest first.
    fn list_events(
        &self,
        session_id: &str,
        run_id: &str,
        window: EpochWindow,
        page: Page,
        scope: &QueryScope,
    ) -> Vec<ObservabilityEventRow>;
    /// Returns one owner scope's security-event counts grouped by session.
    fn security_counts_by_session(&self, filters: &EventFilters, scope: &QueryScope)
    -> GroupCounts;
    /// Returns one owner scope's security-event counts grouped by run.
    fn security_counts_by_run(
        &self,
        session_id: &str,
        filters: &EventFilters,
        scope: &QueryScope,
    ) -> GroupCounts;
}

/// [`ObservabilityQueries`] over the daemon's system observability database
/// and security-event database.
///
/// The observability reader opens its own read-only connection over the
/// system store (the one the state migrator fills) and never creates or
/// converges anything; the security reader is the same read-only source the
/// `sec.*` family uses, so both streams answer from the databases their
/// writers own.
pub struct SqliteObservabilityQuerySource {
    observability: SystemObservabilityReader,
    security: SqliteEventReader,
}

impl SqliteObservabilityQuerySource {
    /// Opens the source over the two databases.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError`] when either path cannot be normalized.
    pub fn new(observability_path: &Path, security_path: &Path) -> Result<Self, KernelError> {
        Ok(Self {
            observability: SystemObservabilityReader::new(observability_path)?,
            security: SqliteEventReader::new(security_path)?,
        })
    }
}

impl CorrelationCandidates for SqliteObservabilityQuerySource {
    fn correlation_candidates(
        &self,
        request: &CorrelationRequest<'_>,
        scope: &QueryScope,
    ) -> Vec<CorrelationCandidate> {
        self.security.query_correlation_candidates(request, scope)
    }
}

impl ObservabilityQueries for SqliteObservabilityQuerySource {
    fn list_sessions(
        &self,
        window: EpochWindow,
        page: Page,
        scope: &QueryScope,
    ) -> Vec<SessionSummary> {
        self.observability.list_sessions(window, page, *scope)
    }

    fn count_sessions(&self, window: EpochWindow, scope: &QueryScope) -> u64 {
        self.observability.count_sessions(window, *scope)
    }

    fn list_runs(
        &self,
        session_id: &str,
        window: EpochWindow,
        page: Page,
        scope: &QueryScope,
    ) -> Vec<RunSummary> {
        self.observability
            .list_runs(session_id, window, page, *scope)
    }

    fn count_runs(&self, session_id: &str, window: EpochWindow, scope: &QueryScope) -> u64 {
        self.observability.count_runs(session_id, window, *scope)
    }

    fn list_events(
        &self,
        session_id: &str,
        run_id: &str,
        window: EpochWindow,
        page: Page,
        scope: &QueryScope,
    ) -> Vec<ObservabilityEventRow> {
        self.observability
            .list_events(session_id, run_id, window, page, *scope)
    }

    fn security_counts_by_session(
        &self,
        filters: &EventFilters,
        scope: &QueryScope,
    ) -> GroupCounts {
        self.security
            .count_by("session_id", filters, scope, 0)
            .unwrap_or_default()
    }

    fn security_counts_by_run(
        &self,
        session_id: &str,
        filters: &EventFilters,
        scope: &QueryScope,
    ) -> GroupCounts {
        let run_filters = EventFilters {
            session_id: Some(session_id.to_owned()),
            ..filters.clone()
        };
        self.security
            .count_by("run_id", &run_filters, scope, 0)
            .unwrap_or_default()
    }
}

/// Protocol adapter for the `obs.*` query family.
pub struct ObservabilityQueryHandler {
    source: Option<Box<dyn ObservabilityQueries>>,
}

impl ObservabilityQueryHandler {
    /// Binds the handler to no store.
    ///
    /// Every `obs.*` method is then rejected with `unavailable`, so an
    /// assembly that never binds a store fails closed instead of serving
    /// queries from an arbitrary database.
    pub fn unconfigured() -> Self {
        Self { source: None }
    }

    /// Binds the handler to one query source.
    pub fn new(source: impl ObservabilityQueries + 'static) -> Self {
        Self {
            source: Some(Box::new(source)),
        }
    }

    /// Serves one query method for one authenticated principal.
    pub fn handle(
        &self,
        request_id: RequestId,
        principal: &Principal,
        query: method::ObsQueryMethod,
        params: Value,
    ) -> DaemonResponse {
        let Some(source) = self.source.as_deref() else {
            return DaemonResponse::error(
                request_id,
                error_code::UNAVAILABLE,
                "observability queries are not configured",
            );
        };
        let params: ObsQueryParams = match serde_json::from_value(params) {
            Ok(params) => params,
            Err(error) => {
                return DaemonResponse::error(
                    request_id,
                    error_code::INVALID_REQUEST,
                    &bounded_message(&error.to_string()),
                );
            }
        };
        // The owner scope is derived once, from transport-authenticated
        // evidence only. Nothing decoded from the request participates.
        let scope = QueryScope::Owner(principal.peer().uid());
        match query {
            method::ObsQueryMethod::SessionsList => {
                Self::sessions_list(source, request_id, &params, scope)
            }
            method::ObsQueryMethod::RunsList => Self::runs_list(source, request_id, &params, scope),
            method::ObsQueryMethod::TimelineGet => {
                Self::timeline_get(source, request_id, &params, scope)
            }
        }
    }

    /// Serves `obs.sessions.list`.
    fn sessions_list(
        source: &dyn ObservabilityQueries,
        request_id: RequestId,
        params: &ObsQueryParams,
        scope: QueryScope,
    ) -> DaemonResponse {
        let Ok((window, filters)) = obs_window(params) else {
            return invalid_parameters(request_id);
        };
        let Ok((limit, offset)) = pagination(params, DEFAULT_LIMIT) else {
            return invalid_parameters(request_id);
        };

        let sessions = source.list_sessions(window, page(limit, offset), &scope);
        let total = source.count_sessions(window, &scope);
        let security_counts = count_lookup(&source.security_counts_by_session(&filters, &scope));

        let items: Vec<Value> = sessions
            .iter()
            .map(|session| {
                json!({
                    "session_id": session.session_id,
                    "first_seen_epoch": session.first_seen_epoch,
                    "last_seen_epoch": session.last_seen_epoch,
                    "turn_count": session.turn_count,
                    "observability_event_count": session.event_count,
                    "security_event_count": security_counts
                        .get(session.session_id.as_str())
                        .copied()
                        .unwrap_or(0),
                })
            })
            .collect();
        DaemonResponse::success(
            request_id,
            json!({
                "items": items,
                "total": total,
                "limit": limit,
                "offset": offset,
                "next_offset": crate::query::next_offset(
                    u32::try_from(offset).expect("bounded to i64::MAX fits u32"),
                    limit,
                    u64::from(u32::try_from(items.len()).expect("page size is u32")),
                    total,
                ),
            }),
        )
    }

    /// Serves `obs.runs.list`.
    fn runs_list(
        source: &dyn ObservabilityQueries,
        request_id: RequestId,
        params: &ObsQueryParams,
        scope: QueryScope,
    ) -> DaemonResponse {
        let Some(session_id) = crate::query::non_empty(params.session_id.as_deref()) else {
            return invalid_parameters(request_id);
        };
        let Ok((window, filters)) = obs_window(params) else {
            return invalid_parameters(request_id);
        };
        let Ok((limit, offset)) = pagination(params, DEFAULT_LIMIT) else {
            return invalid_parameters(request_id);
        };

        let runs = source.list_runs(session_id, window, page(limit, offset), &scope);
        let total = source.count_runs(session_id, window, &scope);
        let security_counts =
            count_lookup(&source.security_counts_by_run(session_id, &filters, &scope));

        let items: Vec<Value> = runs
            .iter()
            .map(|run| {
                json!({
                    "run_id": run.run_id,
                    "started_at_epoch": run.started_at_epoch,
                    "ended_at_epoch": run.ended_at_epoch,
                    "user_input_preview": run.user_input_preview,
                    "observability_event_count": run.event_count,
                    "security_event_count": security_counts
                        .get(run.run_id.as_str())
                        .copied()
                        .unwrap_or(0),
                })
            })
            .collect();
        DaemonResponse::success(
            request_id,
            json!({
                "session_id": session_id,
                "items": items,
                "total": total,
                "limit": limit,
                "offset": offset,
                "next_offset": crate::query::next_offset(
                    u32::try_from(offset).expect("bounded to i64::MAX fits u32"),
                    limit,
                    u64::from(u32::try_from(items.len()).expect("page size is u32")),
                    total,
                ),
            }),
        )
    }

    /// Serves `obs.timeline.get`.
    fn timeline_get(
        source: &dyn ObservabilityQueries,
        request_id: RequestId,
        params: &ObsQueryParams,
        scope: QueryScope,
    ) -> DaemonResponse {
        let (Some(session_id), Some(run_id)) = (
            crate::query::non_empty(params.session_id.as_deref()),
            crate::query::non_empty(params.run_id.as_deref()),
        ) else {
            return invalid_parameters(request_id);
        };
        let Ok((window, _filters)) = obs_window(params) else {
            return invalid_parameters(request_id);
        };
        let Ok((limit, offset)) = pagination(params, MAX_LIMIT) else {
            return invalid_parameters(request_id);
        };
        let include_security = params.include_security.unwrap_or(true);

        let rows = source.list_events(session_id, run_id, window, page(limit, offset), &scope);
        let mut items: Vec<Value> = rows.iter().map(observability_item).collect();
        if include_security && !rows.is_empty() {
            let metrics: Vec<Map<String, Value>> = rows
                .iter()
                .map(|row| json_object(&row.metrics_json))
                .collect();
            let records: Vec<ObservabilityRecordFields<'_>> = rows
                .iter()
                .zip(metrics.iter())
                .map(|(row, metrics)| ObservabilityRecordFields {
                    hook: row.hook.as_str(),
                    session_id: Some(row.session_id.as_str()),
                    run_id: Some(row.run_id.as_str()),
                    tool_call_id: row.tool_call_id.as_deref(),
                    observed_at_epoch: row.observed_at_epoch,
                    metrics,
                })
                .collect();
            let correlator =
                SecurityCorrelationService::new(source as &dyn CorrelationCandidates, scope);
            for (row, correlated) in rows.iter().zip(correlator.find_correlated_many(&records)) {
                for match_info in correlated {
                    items.push(security_item(row, &match_info));
                }
            }
        }

        // v1 sorts by (timestamp_epoch, kind); "observability" precedes
        // "security" at equal timestamps, so the record of the action comes
        // before the events it produced.
        items.sort_by(|left, right| {
            let epoch = left["timestamp_epoch"]
                .as_f64()
                .partial_cmp(&right["timestamp_epoch"].as_f64())
                .unwrap_or(std::cmp::Ordering::Equal);
            epoch.then_with(|| {
                left["kind"]
                    .as_str()
                    .unwrap_or_default()
                    .cmp(right["kind"].as_str().unwrap_or_default())
            })
        });

        DaemonResponse::success(
            request_id,
            json!({
                "session_id": session_id,
                "run_id": run_id,
                "limit": limit,
                "offset": offset,
                "items": items,
            }),
        )
    }
}

/// The parsed time range of one `obs.*` request.
///
/// The same epochs bound both reads: the observability window and the
/// security-event filters, matching v1's dual derivation of one range.
type ParsedWindow = (EpochWindow, EventFilters);

/// Resolves the v1 time-range parameters of one `obs.*` request.
///
/// `since`/`until` accept v1's ISO-8601 spellings, including naive local
/// timestamps, normalized to UTC at this boundary; `start_ns`/`end_ns` are
/// absolute epoch nanoseconds and are mutually exclusive with their ISO
/// counterparts, and a reversed range is the caller's fault.
fn obs_window(params: &ObsQueryParams) -> Result<ParsedWindow, ()> {
    if params.since.is_some() && params.start_ns.is_some() {
        return Err(());
    }
    if params.until.is_some() && params.end_ns.is_some() {
        return Err(());
    }
    let since = match (&params.since, params.start_ns) {
        (Some(raw), _) => Some(iso_to_epoch(raw, "since")?),
        (None, Some(nanos)) => Some(crate::query::epoch_of_nanos(nanos)),
        (None, None) => None,
    };
    let until = match (&params.until, params.end_ns) {
        (Some(raw), _) => Some(iso_to_epoch(raw, "until")?),
        (None, Some(nanos)) => Some(crate::query::epoch_of_nanos(nanos)),
        (None, None) => None,
    };
    if let (Some(since), Some(until)) = (since, until)
        && since > until
    {
        return Err(());
    }
    Ok((
        EpochWindow {
            start_epoch: since,
            end_epoch: until,
        },
        EventFilters {
            since_epoch: since,
            until_epoch: until,
            ..EventFilters::default()
        },
    ))
}

/// Validates v1's `limit`/`offset` pair.
fn pagination(params: &ObsQueryParams, default_limit: u64) -> Result<(u64, u64), ()> {
    let limit = bounded(params.limit, default_limit, 1, MAX_LIMIT)?;
    let offset = bounded(params.offset, 0, 0, MAX_OFFSET)?;
    Ok((limit, offset))
}

fn page(limit: u64, offset: u64) -> Page {
    Page {
        limit: Some(u32::try_from(limit).expect("bounded to 1000")),
        offset: u32::try_from(offset).expect("bounded to u32::MAX"),
    }
}

/// Builds the per-session / per-run security count lookup.
fn count_lookup(groups: &GroupCounts) -> std::collections::HashMap<String, u64> {
    groups
        .iter()
        .filter_map(|(key, count)| {
            key.as_deref()
                .filter(|key| !key.is_empty())
                .map(|key| (key.to_owned(), *count))
        })
        .collect()
}

/// Renders one observability row as the v1 timeline item.
fn observability_item(row: &ObservabilityEventRow) -> Value {
    json!({
        "kind": "observability",
        "id": row.id,
        "hook": row.hook,
        "timestamp": row.observed_at,
        "timestamp_epoch": row.observed_at_epoch,
        "session_id": row.session_id,
        "run_id": row.run_id,
        "call_id": row.call_id,
        "tool_call_id": row.tool_call_id,
        "metadata": json_object(&row.metadata_json),
        "metrics": json_object(&row.metrics_json),
    })
}

/// Renders one correlated security event as the v1 timeline item.
fn security_item(
    row: &ObservabilityEventRow,
    correlated: &crate::correlation::CorrelatedSecurityEvent,
) -> Value {
    json!({
        "kind": "security",
        "observability_event_id": row.id,
        "observability": observability_item(row),
        "hook": row.hook,
        "session_id": row.session_id,
        "run_id": row.run_id,
        "call_id": row.call_id,
        "tool_call_id": row.tool_call_id,
        "timestamp": correlated.event.timestamp,
        "timestamp_epoch": correlated.security_timestamp_epoch,
        "event": event_payload(&correlated.event, true),
        "match": {
            "reason": correlated.match_reason.as_str(),
            "rank": correlated.match_rank,
            "time_delta_seconds": correlated.time_delta_seconds,
        },
    })
}

/// Parses one stored JSON blob as an object, `{}` otherwise — v1's
/// `_json_object`: malformed rows render as empty objects rather than
/// failing the whole timeline.
fn json_object(raw: &str) -> Map<String, Value> {
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(map)) => map,
        _ => Map::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asc_daemon_core::PeerCredentials;
    use asc_persistence_sqlite::observability::SYSTEM_OBSERVABILITY_TABLES;
    use asc_persistence_sqlite::observability::table::SYSTEM_OBSERVABILITY_SQLITE_SCHEMA_VERSION;
    use asc_persistence_sqlite::security_events::SqliteEventWriter;
    use asc_security_events::SecurityEvent;
    use asc_sqlite_kernel::SqliteStore;
    use serde_json::json;
    use tempfile::TempDir;

    const INSERT_SQL: &str = "INSERT INTO observability_events (hook, observed_at, \
         observed_at_epoch, session_id, run_id, metrics_json, metadata_json, call_id, \
         tool_call_id, owner) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";

    /// A foreign owner that certainly shares neither store with the caller.
    const FOREIGN_UID: u32 = 42_424_242;

    fn request_id() -> RequestId {
        RequestId::new("test".to_owned()).expect("non-empty")
    }

    fn principal(uid: u32) -> Principal {
        Principal::from_authenticated_peer(
            PeerCredentials::new(uid, 456, 123),
            asc_daemon_core::PrincipalRole::LocalUser,
        )
    }

    fn handle(
        handler: &ObservabilityQueryHandler,
        uid: u32,
        method_name: &str,
        params: Value,
    ) -> DaemonResponse {
        let resolved = method::resolve(method_name).expect("registered method");
        let method::MethodId::ObsQuery(query) = resolved else {
            panic!("not an observability method");
        };
        handler.handle(request_id(), &principal(uid), query, params)
    }

    fn success_data(response: DaemonResponse) -> Value {
        match response {
            DaemonResponse::Success(success) => success.result,
            DaemonResponse::Error(error) => panic!("expected success, got {error:?}"),
        }
    }

    fn error_code_of(response: DaemonResponse) -> String {
        match response {
            DaemonResponse::Success(_) => panic!("expected error"),
            DaemonResponse::Error(error) => error.error.code.as_str().to_owned(),
        }
    }

    /// Renders one seeded epoch as the matching v1 wire timestamp.
    fn epoch_iso(epoch: f64) -> String {
        let seconds = epoch.floor() as i64 % 86_400;
        let (hour, minute, second) = (seconds / 3_600, (seconds % 3_600) / 60, seconds % 60);
        format!("2026-01-01T{hour:02}:{minute:02}:{second:02}Z")
    }

    /// The epoch of 2026-01-01T00:00:00Z, the base of every seeded instant.
    const BASE_EPOCH: f64 = 1_767_225_600.0;

    /// Seeds the system observability store with two owners' sessions.
    ///
    /// Owner 1000: session "s-own" with runs "r-1" (two rows) and "r-2" (one
    /// row); the `before_tool_call` row carries the tool call id its security
    /// event shares. Owner 2000: session "s-foreign" with run "r-1" — the
    /// same run id under a different owner, which a scoped reader must keep
    /// apart.
    fn seed_observability(path: &Path) {
        let store = SqliteStore::new(
            path,
            false,
            SYSTEM_OBSERVABILITY_SQLITE_SCHEMA_VERSION,
            SYSTEM_OBSERVABILITY_TABLES,
            None,
            "[observability]",
        )
        .expect("system store");
        store
            .with_connection(true, |conn| {
                for (hook, epoch, session, run, owner, metrics, tool_call_id) in [
                    (
                        "before_agent_run",
                        BASE_EPOCH + 100.0,
                        "s-own",
                        "r-1",
                        1000u32,
                        r#"{"user_input":"list files"}"#,
                        None,
                    ),
                    (
                        "before_tool_call",
                        BASE_EPOCH + 105.0,
                        "s-own",
                        "r-1",
                        1000,
                        r#"{"parameters":{"command":"ls -la /tmp"}}"#,
                        Some("tc-1"),
                    ),
                    (
                        "before_agent_run",
                        BASE_EPOCH + 200.0,
                        "s-own",
                        "r-2",
                        1000,
                        r#"{"user_input":"second"}"#,
                        None,
                    ),
                    (
                        "before_agent_run",
                        BASE_EPOCH + 150.0,
                        "s-foreign",
                        "r-1",
                        2000,
                        r#"{"user_input":"foreign"}"#,
                        None,
                    ),
                ] {
                    conn.execute(
                        INSERT_SQL,
                        rusqlite::params![
                            hook,
                            epoch_iso(epoch),
                            epoch,
                            session,
                            run,
                            metrics,
                            "{}",
                            Option::<String>::None,
                            tool_call_id,
                            owner,
                        ],
                    )?;
                }
                Ok(())
            })
            .expect("seed");
    }

    /// Seeds the security-event store: one code_scan for owner 1000's
    /// `s-own`/`r-1` tool call, one prompt_scan for owner 1000's `s-own`/`r-2`,
    /// and one code_scan for the foreign owner under the same session id.
    fn seed_security(path: &Path) {
        let writer = SqliteEventWriter::new(path).expect("writer");
        let mut tool_event =
            SecurityEvent::new("sandbox_prehook", "code_scan", serde_json::Map::new());
        tool_event.uid = 1000;
        tool_event.session_id = Some("s-own".to_owned());
        tool_event.run_id = Some("r-1".to_owned());
        tool_event.tool_call_id = Some("tc-1".to_owned());
        tool_event.timestamp = "2026-01-01T00:01:44+00:00".to_owned();
        tool_event
            .details
            .insert("request".to_owned(), json!({"code": "ls -la /tmp"}));
        writer.write(&tool_event);

        let mut prompt_event =
            SecurityEvent::new("sandbox_prehook", "prompt_scan", serde_json::Map::new());
        prompt_event.uid = 1000;
        prompt_event.session_id = Some("s-own".to_owned());
        prompt_event.run_id = Some("r-2".to_owned());
        prompt_event.timestamp = "2026-01-01T00:03:16+00:00".to_owned();
        prompt_event
            .details
            .insert("request".to_owned(), json!({"text": "second"}));
        writer.write(&prompt_event);

        let mut foreign_event =
            SecurityEvent::new("sandbox_prehook", "code_scan", serde_json::Map::new());
        foreign_event.uid = FOREIGN_UID;
        foreign_event.session_id = Some("s-own".to_owned());
        foreign_event.run_id = Some("r-1".to_owned());
        foreign_event.tool_call_id = Some("tc-1".to_owned());
        foreign_event.timestamp = "2026-01-01T00:00:44+00:00".to_owned();
        foreign_event
            .details
            .insert("request".to_owned(), json!({"code": "ls -la /tmp"}));
        writer.write(&foreign_event);
        writer.close_at(1000.0);
    }

    fn seeded_source() -> (TempDir, SqliteObservabilityQuerySource) {
        let dir = TempDir::new().expect("temp dir");
        let observability = dir.path().join("observability.db");
        let security = dir.path().join("security-events.db");
        seed_observability(&observability);
        seed_security(&security);
        let source =
            SqliteObservabilityQuerySource::new(&observability, &security).expect("source");
        (dir, source)
    }

    #[test]
    fn sessions_list_reports_only_the_callers_sessions() {
        let (_dir, source) = seeded_source();
        let handler = ObservabilityQueryHandler::new(source);

        let data = success_data(handle(&handler, 1000, method::OBS_SESSIONS_LIST, json!({})));
        let items = data["items"].as_array().expect("items");
        assert_eq!(items.len(), 1, "only the caller's session: {data}");
        assert_eq!(items[0]["session_id"], json!("s-own"));
        assert_eq!(items[0]["observability_event_count"], json!(3));
        assert_eq!(items[0]["turn_count"], json!(2));
        assert_eq!(
            items[0]["security_event_count"],
            json!(2),
            "the two own security events fall in this session"
        );
        assert_eq!(data["total"], json!(1));
        assert_eq!(data["limit"], json!(100));
        assert_eq!(data["offset"], json!(0));
        assert_eq!(data["next_offset"], json!(null));
    }

    #[test]
    fn runs_list_requires_a_session_and_stays_inside_the_owner() {
        let (_dir, source) = seeded_source();
        let handler = ObservabilityQueryHandler::new(source);

        let missing = handle(&handler, 1000, method::OBS_RUNS_LIST, json!({}));
        assert_eq!(error_code_of(missing), "invalid_argument");

        let data = success_data(handle(
            &handler,
            1000,
            method::OBS_RUNS_LIST,
            json!({"session_id": "s-own"}),
        ));
        let items = data["items"].as_array().expect("items");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["run_id"], json!("r-1"));
        assert_eq!(items[0]["started_at_epoch"], json!(BASE_EPOCH + 100.0));
        assert_eq!(
            items[0]["user_input_preview"],
            json!("list files"),
            "the preview comes from the first before_agent_run metrics blob"
        );
        assert_eq!(items[0]["security_event_count"], json!(1));
        assert_eq!(items[1]["run_id"], json!("r-2"));
        assert_eq!(items[1]["security_event_count"], json!(1));

        // The foreign owner's run lives under the same session id spelling;
        // the owner predicate must keep it apart.
        let foreign = success_data(handle(
            &handler,
            2000,
            method::OBS_RUNS_LIST,
            json!({"session_id": "s-own"}),
        ));
        assert_eq!(
            foreign["items"].as_array().expect("items").len(),
            0,
            "owner 2000's rows sit under s-foreign, not s-own"
        );
        let foreign_own = success_data(handle(
            &handler,
            2000,
            method::OBS_RUNS_LIST,
            json!({"session_id": "s-foreign"}),
        ));
        assert_eq!(foreign_own["items"].as_array().expect("items").len(), 1);
    }

    #[test]
    fn timeline_get_correlates_security_events_inside_the_owner_scope() {
        let (_dir, source) = seeded_source();
        let handler = ObservabilityQueryHandler::new(source);

        let data = success_data(handle(
            &handler,
            1000,
            method::OBS_TIMELINE_GET,
            json!({"session_id": "s-own", "run_id": "r-1"}),
        ));
        let items = data["items"].as_array().expect("items");
        // The foreign owner seeded an identical-looking code_scan under the
        // same session/run/tool ids; only the caller's own may appear.
        let security: Vec<&Value> = items
            .iter()
            .filter(|item| item["kind"] == json!("security"))
            .collect();
        assert_eq!(
            security.len(),
            1,
            "exactly one own correlated event: {data}"
        );
        assert_eq!(security[0]["event"]["category"], json!("code_scan"));
        assert_eq!(security[0]["match"]["reason"], json!("tool_call_id"));
        assert_eq!(security[0]["observability_event_id"], json!(2));
        assert_eq!(
            items[0]["kind"],
            json!("observability"),
            "the record precedes the event it produced at the same instant"
        );

        // include_security=false drops them without touching the records.
        let without = success_data(handle(
            &handler,
            1000,
            method::OBS_TIMELINE_GET,
            json!({"session_id": "s-own", "run_id": "r-1", "include_security": false}),
        ));
        assert!(
            without["items"]
                .as_array()
                .expect("items")
                .iter()
                .all(|item| item["kind"] == json!("observability"))
        );
    }

    #[test]
    fn a_foreign_run_id_answers_an_empty_timeline() {
        let (_dir, source) = seeded_source();
        let handler = ObservabilityQueryHandler::new(source);

        let data = success_data(handle(
            &handler,
            1000,
            method::OBS_TIMELINE_GET,
            json!({"session_id": "s-foreign", "run_id": "r-1"}),
        ));
        assert_eq!(
            data["items"].as_array().expect("items").len(),
            0,
            "another owner's session is indistinguishable from an empty one"
        );
    }

    #[test]
    fn the_time_range_parameters_follow_v1_rules() {
        let (_dir, source) = seeded_source();
        let handler = ObservabilityQueryHandler::new(source);

        for params in [
            json!({"since": "2026-01-01T00:00:00Z", "start_ns": 1}),
            json!({"until": "2026-01-01T00:00:00Z", "end_ns": 1}),
            json!({"since": "2026-01-02T00:00:00Z", "until": "2026-01-01T00:00:00Z"}),
            json!({"since": "not-a-timestamp"}),
            json!({"limit": 0}),
            json!({"limit": 1001}),
        ] {
            let response = handle(&handler, 1000, method::OBS_SESSIONS_LIST, params.clone());
            assert_eq!(
                error_code_of(response),
                "invalid_argument",
                "params {params} must be rejected"
            );
        }
        // A negative offset is rejected one step earlier, at decode, exactly
        // as v1's integer type check did.
        let response = handle(
            &handler,
            1000,
            method::OBS_SESSIONS_LIST,
            json!({"offset": -1}),
        );
        assert_eq!(error_code_of(response), "invalid_request");

        // A window that keeps only r-2's row narrows the session list.
        let data = success_data(handle(
            &handler,
            1000,
            method::OBS_SESSIONS_LIST,
            json!({"since": "2026-01-01T00:03:00Z"}),
        ));
        let items = data["items"].as_array().expect("items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["observability_event_count"], json!(1));
        assert_eq!(items[0]["turn_count"], json!(1));

        // Nanosecond bounds are accepted as absolute epochs: 2026-01-01T00:02:30Z
        // keeps only r-2's row.
        let ns = success_data(handle(
            &handler,
            1000,
            method::OBS_SESSIONS_LIST,
            json!({"start_ns": 1_767_225_750_000_000_000_u64}),
        ));
        assert_eq!(ns["items"].as_array().expect("items").len(), 1);
    }

    #[test]
    fn an_unbound_handler_fails_closed() {
        let handler = ObservabilityQueryHandler::unconfigured();
        let response = handle(&handler, 1000, method::OBS_SESSIONS_LIST, json!({}));
        assert_eq!(error_code_of(response), "unavailable");
    }

    #[test]
    fn a_missing_store_pair_answers_empty_results() {
        let dir = TempDir::new().expect("temp dir");
        let source = SqliteObservabilityQuerySource::new(
            &dir.path().join("absent-observability.db"),
            &dir.path().join("absent-security.db"),
        )
        .expect("source opens over missing databases");
        let handler = ObservabilityQueryHandler::new(source);
        let data = success_data(handle(&handler, 1000, method::OBS_SESSIONS_LIST, json!({})));
        assert_eq!(data["items"].as_array().expect("items").len(), 0);
        assert_eq!(data["total"], json!(0));
    }
}
