//! Compatibility commands for the caller's own observability sessions.
//!
//! This is the v2 restoration of v1's `agent-sec-cli observability report` and
//! `observability review` entry points (`agent_sec_cli/observability/cli.py`).
//! The v1 CLI read its per-user database directly; the v2 CLI only goes through
//! the system daemon, which derives the owner scope from the connection's
//! kernel peer credentials — every request below can only match the caller's
//! own rows (issue #6608).
//!
//! `review` replaces v1's interactive Textual TUI with a non-interactive
//! drill-down over the same data: the session list, one session's runs, and
//! one run's timeline with the correlated security results. A daemon-only
//! security CLI does not grow a TUI runtime, and the batch shape stays
//! scriptable through `--format json`. Timestamps render in UTC (like the
//! report) rather than v1's local-time TUI cells, so output is deterministic
//! on hosts with any timezone.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io;
use std::path::Path;
use std::time::Duration;

use asc_daemon_client::ClientError;
use asc_daemon_protocol::{DaemonRequest, DaemonResponse, ObsQueryParams, SecQueryParams, method};
use clap::{Args, Subcommand};
use serde_json::{Map, Value, json};

/// v1's `--format` values for both commands.
const FORMATS: [&str; 2] = ["text", "json"];
/// The largest page the daemon serves for one `obs.*` request; every list is
/// paged internally so a dump or debrief always covers the whole scope.
const PAGE: u64 = 1000;
/// v1's category allowlist for the report's security verdict section.
const REPORT_CATEGORIES: [&str; 6] = [
    "code_scan",
    "prompt_scan",
    "pii_scan",
    "skill_ledger",
    "sandbox",
    "hardening",
];

/// The `observability` command family: v1's `report` debrief and the batch
/// `review` drill-down.
#[derive(Debug, Subcommand)]
pub enum ObservabilityCommand {
    /// Print a per-session debrief (LLM calls, tools, security).
    Report(ReportCommand),
    /// Browse the caller's recorded sessions, runs and event timelines.
    Review(ReviewCommand),
}

impl ObservabilityCommand {
    /// Runs the whole command against the daemon endpoint.
    ///
    /// Both subcommands page through several query methods whose offsets
    /// depend on earlier responses, so they own their transport loop instead
    /// of sharing the single-request path.
    ///
    /// # Errors
    ///
    /// Returns the command's input, daemon, transport, or output failure.
    pub fn run(
        &self,
        socket: &Path,
        timeout: Duration,
        stdout: &mut dyn io::Write,
    ) -> Result<u8, ObservabilityError> {
        let mut transport = SocketTransport { socket, timeout };
        match self {
            Self::Report(report) => report.run(&mut transport, stdout),
            Self::Review(review) => review.run(&mut transport, stdout),
        }
    }
}

/// `observability report`: v1's per-session debrief over `obs.*` and
/// `sec.events.list`.
#[derive(Debug, Args)]
pub struct ReportCommand {
    /// Session ID to report on.
    #[arg(long)]
    session_id: Option<String>,
    /// Report on the most recent session (by last activity).
    #[arg(long)]
    last: bool,
    /// Output format: text or json.
    #[arg(long, default_value = "text")]
    format: String,
}

/// `observability review`: v1's drill-down, rendered without a terminal UI.
///
/// With no flags the command lists the caller's sessions; `--session-id`
/// narrows to that session's runs; adding `--run-id` renders the run's full
/// event timeline with correlated security results, and `--details` appends
/// each event's metadata, metrics and security matches.
#[derive(Debug, Args)]
pub struct ReviewCommand {
    /// Session ID to browse.
    #[arg(long)]
    session_id: Option<String>,
    /// Run ID whose timeline is rendered; requires --session-id.
    #[arg(long)]
    run_id: Option<String>,
    /// Append the full record (metadata, metrics, security matches) of every
    /// timeline event; requires --run-id.
    #[arg(long)]
    details: bool,
    /// Output format: text or json.
    #[arg(long, default_value = "text")]
    format: String,
}

impl ReportCommand {
    /// Resolves the target session, aggregates its rows, and renders.
    ///
    /// # Errors
    ///
    /// Returns local input failures, daemon query failures, transport
    /// failures, or output write failures.
    fn run<T: QueryTransport>(
        &self,
        transport: &mut T,
        stdout: &mut dyn io::Write,
    ) -> Result<u8, ObservabilityError> {
        if !FORMATS.contains(&self.format.as_str()) {
            return Err(ObservabilityError::Input(format!(
                "Error: --format must be 'text' or 'json', got '{}'.",
                self.format
            )));
        }
        let session = match (&self.session_id, self.last) {
            (Some(_), true) => {
                return Err(ObservabilityError::Input(
                    "Error: --session-id and --last are mutually exclusive.".to_owned(),
                ));
            }
            (Some(session_id), false) => find_session(transport, session_id)?.ok_or_else(|| {
                ObservabilityError::Input(format!("Error: session '{session_id}' not found."))
            })?,
            (None, true) => {
                // The daemon orders sessions by most recent activity, exactly
                // v1's `list_sessions` contract, so the first row is --last.
                let result = query(
                    transport,
                    method::OBS_SESSIONS_LIST,
                    obs_params(None, None, Some(1), 0, None),
                )?;
                result["items"]
                    .as_array()
                    .and_then(|items| items.first())
                    .map(session_summary)
                    .ok_or_else(|| ObservabilityError::Input("No sessions recorded.".to_owned()))?
            }
            (None, false) => {
                return Err(ObservabilityError::Input(
                    "Error: specify --session-id or --last.".to_owned(),
                ));
            }
        };
        let debrief = build_debrief(transport, session)?;
        if self.format == "json" {
            let json = serde_json::to_string(&debrief_json(&debrief)).expect("serializes");
            writeln!(stdout, "{json}")?;
        } else {
            render_debrief_text(&debrief, stdout)?;
        }
        Ok(0)
    }
}

impl ReviewCommand {
    /// Selects the drill-down level and renders it.
    ///
    /// # Errors
    ///
    /// Returns local input failures, daemon query failures, transport
    /// failures, or output write failures.
    fn run<T: QueryTransport>(
        &self,
        transport: &mut T,
        stdout: &mut dyn io::Write,
    ) -> Result<u8, ObservabilityError> {
        if !FORMATS.contains(&self.format.as_str()) {
            return Err(ObservabilityError::Input(format!(
                "Error: --format must be 'text' or 'json', got '{}'.",
                self.format
            )));
        }
        if self.run_id.is_some() && self.session_id.is_none() {
            return Err(ObservabilityError::Input(
                "Error: --run-id requires --session-id.".to_owned(),
            ));
        }
        if self.details && self.run_id.is_none() {
            return Err(ObservabilityError::Input(
                "Error: --details requires --run-id.".to_owned(),
            ));
        }
        match (&self.session_id, &self.run_id) {
            (Some(session_id), Some(run_id)) => {
                self.render_timeline(transport, session_id, run_id, stdout)
            }
            (Some(session_id), None) => self.render_runs(transport, session_id, stdout),
            (None, None) => self.render_sessions(transport, stdout),
            // The validation above rejected this combination already.
            (None, Some(_)) => unreachable!("--run-id without --session-id is rejected"),
        }
    }

    /// Renders the session list (v1's `SessionListScreen` columns).
    fn render_sessions<T: QueryTransport>(
        &self,
        transport: &mut T,
        stdout: &mut dyn io::Write,
    ) -> Result<u8, ObservabilityError> {
        let (sessions, _) = page_list(transport, method::OBS_SESSIONS_LIST, &|offset| {
            obs_params(None, None, Some(PAGE), offset, None)
        })?;
        if self.format == "json" {
            return write_items_json(&sessions, stdout);
        }
        if sessions.is_empty() {
            writeln!(stdout, "No observability records found.")?;
            return Ok(0);
        }
        let rows: Vec<Vec<String>> = sessions
            .iter()
            .map(|session| {
                vec![
                    epoch_to_utc(session["last_seen_epoch"].as_f64().unwrap_or_default()),
                    truncate(session["session_id"].as_str().unwrap_or_default(), 40),
                    session["turn_count"]
                        .as_u64()
                        .unwrap_or_default()
                        .to_string(),
                    session["observability_event_count"]
                        .as_u64()
                        .unwrap_or_default()
                        .to_string(),
                ]
            })
            .collect();
        render_table(&["LAST_SEEN", "SESSION", "TURNS", "EVENTS"], &rows, stdout)?;
        Ok(0)
    }

    /// Renders one session's runs (v1's `TurnListScreen` columns).
    fn render_runs<T: QueryTransport>(
        &self,
        transport: &mut T,
        session_id: &str,
        stdout: &mut dyn io::Write,
    ) -> Result<u8, ObservabilityError> {
        let (runs, _) = page_list(transport, method::OBS_RUNS_LIST, &|offset| {
            obs_params(Some(session_id), None, Some(PAGE), offset, None)
        })?;
        if self.format == "json" {
            return write_items_json(&runs, stdout);
        }
        if runs.is_empty() {
            writeln!(stdout, "No runs recorded for this session.")?;
            return Ok(0);
        }
        let rows: Vec<Vec<String>> = runs
            .iter()
            .map(|run| {
                let preview = run["user_input_preview"]
                    .as_str()
                    .filter(|preview| !preview.is_empty())
                    .unwrap_or("(no user_input)");
                vec![
                    epoch_to_utc(run["started_at_epoch"].as_f64().unwrap_or_default()),
                    truncate(run["run_id"].as_str().unwrap_or_default(), 36),
                    truncate(preview, 60),
                    run["observability_event_count"]
                        .as_u64()
                        .unwrap_or_default()
                        .to_string(),
                ]
            })
            .collect();
        render_table(&["STARTED", "RUN", "PREVIEW", "EVENTS"], &rows, stdout)?;
        Ok(0)
    }

    /// Renders one run's timeline with the per-row security results (v1's
    /// `EventListScreen` columns), plus the full records with `--details`.
    fn render_timeline<T: QueryTransport>(
        &self,
        transport: &mut T,
        session_id: &str,
        run_id: &str,
        stdout: &mut dyn io::Write,
    ) -> Result<u8, ObservabilityError> {
        let items = timeline_all(transport, session_id, run_id, true)?;
        if self.format == "json" {
            return write_items_json(&items, stdout);
        }
        if items.is_empty() {
            writeln!(stdout, "No events for this run.")?;
            return Ok(0);
        }
        // The timeline interleaves the security events the daemon correlated
        // with each observability row; the table joins them back onto their
        // row, exactly v1's per-row Security Result column.
        let mut security_by_row: HashMap<String, Vec<&Value>> = HashMap::new();
        for item in &items {
            if item["kind"].as_str() == Some("security") {
                security_by_row
                    .entry(item["observability_event_id"].to_string())
                    .or_default()
                    .push(item);
            }
        }
        let mut rows = Vec::new();
        for item in &items {
            if item["kind"].as_str() != Some("observability") {
                continue;
            }
            let ident = item["tool_call_id"]
                .as_str()
                .or_else(|| item["call_id"].as_str())
                .unwrap_or_default();
            let security = security_by_row.get(&item["id"].to_string()).map_or_else(
                || "-".to_owned(),
                |events| {
                    let labels: Vec<String> = events
                        .iter()
                        .map(|event_item| {
                            let event = &event_item["event"];
                            let category = event["category"].as_str().unwrap_or_default();
                            let verdict = event["verdict"]
                                .as_str()
                                .or_else(|| event["result"].as_str())
                                .unwrap_or_default();
                            format!("{category}:{verdict}")
                        })
                        .collect();
                    labels.join(", ")
                },
            );
            rows.push(vec![
                epoch_to_utc(item["timestamp_epoch"].as_f64().unwrap_or_default()),
                item["hook"].as_str().unwrap_or_default().to_owned(),
                truncate(ident, 18),
                truncate(&security, 50),
            ]);
        }
        render_table(&["TIME", "HOOK", "CALL/TOOL", "SECURITY"], &rows, stdout)?;
        if self.details {
            render_event_details(&items, &security_by_row, stdout)?;
        }
        Ok(0)
    }
}

/// Local failures and daemon failures of the observability commands.
///
/// Owned here instead of the shared [`crate::InputError`] because the wording
/// of the input variants is v1's; the shared enum wraps this one so the binary
/// keeps a single error exit path.
#[derive(Debug, thiserror::Error)]
pub enum ObservabilityError {
    /// Invalid command input; the message is v1's user-facing wording.
    #[error("{0}")]
    Input(String),
    /// A daemon query failed.
    #[error("observability query failed: {message} ({code})")]
    Daemon {
        /// Machine-readable daemon error category.
        code: String,
        /// Sanitized operator-facing explanation.
        message: String,
    },
    /// The daemon transport failed before a response arrived.
    #[error(transparent)]
    Transport(#[from] ClientError),
    /// Writing the rendered output failed.
    #[error(transparent)]
    Output(#[from] io::Error),
}

impl ObservabilityError {
    /// Whether the message already reads as a terminal usage error, so the
    /// binary prints it verbatim instead of behind the `agent-sec-cli:`
    /// prefix, mirroring V1's report/review messages.
    #[must_use]
    pub const fn is_usage_hint(&self) -> bool {
        matches!(self, Self::Input(_))
    }
}

/// One daemon round trip, abstracted so the command flows are testable
/// against scripted responses.
trait QueryTransport {
    /// Sends one request and returns the daemon's response.
    ///
    /// # Errors
    ///
    /// Returns the transport failure when no response arrived.
    fn call(&mut self, request: DaemonRequest) -> Result<DaemonResponse, ClientError>;
}

/// The production transport: one Unix-socket call per request.
struct SocketTransport<'a> {
    /// Daemon endpoint resolved by the CLI parse.
    socket: &'a Path,
    /// Per-request deadline.
    timeout: Duration,
}

impl QueryTransport for SocketTransport<'_> {
    fn call(&mut self, request: DaemonRequest) -> Result<DaemonResponse, ClientError> {
        asc_daemon_client::call(self.socket, &request, self.timeout)
    }
}

/// Sends one query and returns its result payload.
///
/// # Errors
///
/// Returns the daemon's error response or the transport failure.
fn query<T: QueryTransport>(
    transport: &mut T,
    method_name: &str,
    params: Value,
) -> Result<Value, ObservabilityError> {
    let request = DaemonRequest {
        trace_context: None,
        compatibility: None,
        method: method_name.to_owned(),
        params,
    };
    match transport.call(request) {
        Ok(DaemonResponse::Success(success)) => Ok(success.result),
        Ok(DaemonResponse::Error(error)) => Err(ObservabilityError::Daemon {
            code: error.error.code.to_string(),
            message: error.error.message().to_owned(),
        }),
        Err(error) => Err(ObservabilityError::Transport(error)),
    }
}

/// Builds one `obs.*` request's parameter dictionary.
fn obs_params(
    session_id: Option<&str>,
    run_id: Option<&str>,
    limit: Option<u64>,
    offset: u64,
    include_security: Option<bool>,
) -> Value {
    let params = ObsQueryParams {
        session_id: session_id.map(str::to_owned),
        run_id: run_id.map(str::to_owned),
        limit,
        offset: Some(offset),
        include_security,
        ..ObsQueryParams::default()
    };
    // Every field is a string, integer, or optional flag, so encoding cannot
    // fail; this mirrors the protocol-side handlers' expectation.
    serde_json::to_value(params).expect("plain query fields serialize")
}

/// Builds one `sec.events.list` page request for the report's security
/// section, with v1's category allowlist applied client-side.
fn security_params(session_id: &str, offset: u64) -> Value {
    let params = SecQueryParams {
        session_id: Some(session_id.to_owned()),
        limit: Some(PAGE),
        offset: Some(offset),
        include_details: Some(false),
        ..SecQueryParams::default()
    };
    serde_json::to_value(params).expect("plain query fields serialize")
}

/// Pages one `next_offset`-style list to exhaustion.
///
/// # Errors
///
/// Returns any page's daemon or transport failure.
fn page_list<T: QueryTransport>(
    transport: &mut T,
    method_name: &str,
    params_of: &dyn Fn(u64) -> Value,
) -> Result<(Vec<Value>, u64), ObservabilityError> {
    let mut offset = 0;
    let mut items = Vec::new();
    let mut total;
    loop {
        let result = query(transport, method_name, params_of(offset))?;
        if let Some(page) = result["items"].as_array() {
            items.extend(page.iter().cloned());
        }
        total = result["total"].as_u64().unwrap_or_default();
        match result["next_offset"].as_u64() {
            Some(next) if next > offset => offset = next,
            _ => break,
        }
    }
    Ok((items, total))
}

/// Pages one run's timeline to exhaustion.
///
/// The daemon pages over observability rows and appends each page's
/// correlated security events, so the walk advances the offset by the
/// observability rows alone.
///
/// # Errors
///
/// Returns any page's daemon or transport failure.
fn timeline_all<T: QueryTransport>(
    transport: &mut T,
    session_id: &str,
    run_id: &str,
    include_security: bool,
) -> Result<Vec<Value>, ObservabilityError> {
    let mut offset = 0;
    let mut items = Vec::new();
    loop {
        let result = query(
            transport,
            method::OBS_TIMELINE_GET,
            obs_params(
                Some(session_id),
                Some(run_id),
                Some(PAGE),
                offset,
                Some(include_security),
            ),
        )?;
        let rows = result["items"].as_array().map_or(0, |page| {
            page.iter()
                .filter(|item| item["kind"].as_str() != Some("security"))
                .count()
        });
        if let Some(page) = result["items"].as_array() {
            items.extend(page.iter().cloned());
        }
        let page_rows =
            u64::try_from(rows).expect("a page row count fits the protocol's u64 offset");
        if page_rows < PAGE {
            break;
        }
        offset += page_rows;
    }
    Ok(items)
}

/// Finds the caller's session by ID across every `obs.sessions.list` page.
///
/// # Errors
///
/// Returns any page's daemon or transport failure.
fn find_session<T: QueryTransport>(
    transport: &mut T,
    session_id: &str,
) -> Result<Option<SessionSummary>, ObservabilityError> {
    let mut offset = 0;
    loop {
        let result = query(
            transport,
            method::OBS_SESSIONS_LIST,
            obs_params(None, None, Some(PAGE), offset, None),
        )?;
        let found = result["items"].as_array().and_then(|items| {
            items
                .iter()
                .find(|item| item["session_id"].as_str() == Some(session_id))
                .cloned()
        });
        if let Some(found) = found {
            return Ok(Some(session_summary(&found)));
        }
        match result["next_offset"].as_u64() {
            Some(next) if next > offset => offset = next,
            _ => return Ok(None),
        }
    }
}

/// One session summary as `obs.sessions.list` returns it.
struct SessionSummary {
    session_id: String,
    first_seen_epoch: f64,
    last_seen_epoch: f64,
    turn_count: u64,
}

/// Reads one `obs.sessions.list` item.
fn session_summary(item: &Value) -> SessionSummary {
    SessionSummary {
        session_id: item["session_id"].as_str().unwrap_or_default().to_owned(),
        first_seen_epoch: item["first_seen_epoch"].as_f64().unwrap_or_default(),
        last_seen_epoch: item["last_seen_epoch"].as_f64().unwrap_or_default(),
        turn_count: item["turn_count"].as_u64().unwrap_or_default(),
    }
}

/// Everything the report renders for one session.
struct Debrief {
    session: SessionSummary,
    llm_calls: u64,
    request_bytes: u64,
    response_bytes: u64,
    tools: Vec<(String, u64)>,
    security: Map<String, Value>,
    security_hint: String,
}

/// Aggregates one session's runs, timelines, and security verdicts.
///
/// # Errors
///
/// Returns any query's daemon or transport failure, except the security
/// query, whose failure keeps the debrief with v1's hint (the observability
/// half is independent of the security store).
fn build_debrief<T: QueryTransport>(
    transport: &mut T,
    session: SessionSummary,
) -> Result<Debrief, ObservabilityError> {
    let (runs, _) = page_list(transport, method::OBS_RUNS_LIST, &|offset| {
        obs_params(Some(&session.session_id), None, Some(PAGE), offset, None)
    })?;
    let mut llm_calls = 0;
    let mut request_bytes = 0;
    let mut response_bytes = 0;
    // Insertion-ordered so the count-descending sort below breaks ties by
    // first appearance, exactly like v1's insertion-ordered dict.
    let mut tools: Vec<(String, u64)> = Vec::new();
    for run in &runs {
        let run_id = run["run_id"].as_str().unwrap_or_default();
        for item in timeline_all(transport, &session.session_id, run_id, false)? {
            if item["kind"].as_str() != Some("observability") {
                continue;
            }
            let hook = item["hook"].as_str().unwrap_or_default();
            let metrics = &item["metrics"];
            match hook {
                "after_llm_call" => {
                    llm_calls += 1;
                    request_bytes += metrics["request_payload_bytes"]
                        .as_u64()
                        .unwrap_or_default();
                    response_bytes += metrics["response_stream_bytes"]
                        .as_u64()
                        .unwrap_or_default();
                }
                "before_tool_call" => {
                    let name = metrics["tool_name"].as_str().unwrap_or("unknown");
                    match tools.iter_mut().find(|(tool, _)| tool == name) {
                        Some((_, count)) => *count += 1,
                        None => tools.push((name.to_owned(), 1)),
                    }
                }
                _ => {}
            }
        }
    }
    // v1 sorts by descending count; `sort_by` is stable, so first-seen order
    // breaks ties exactly like v1's insertion-ordered dict.
    tools.sort_by(|(_, left), (_, right)| right.cmp(left));

    let (security, security_hint) = match page_list(transport, method::SEC_EVENTS_LIST, &|offset| {
        security_params(&session.session_id, offset)
    }) {
        Ok((events, _)) => {
            let mut security = Map::new();
            for event in &events {
                let category = event["category"].as_str().unwrap_or("unknown");
                let result = event["result"].as_str().unwrap_or("succeeded");
                if !REPORT_CATEGORIES.contains(&category) {
                    continue;
                }
                let verdicts = security
                    .entry(category.to_owned())
                    .or_insert_with(|| Value::Object(Map::new()));
                if let Some(counts) = verdicts.as_object_mut() {
                    let count = counts.get(result).and_then(Value::as_u64).unwrap_or(0) + 1;
                    counts.insert(result.to_owned(), json!(count));
                }
            }
            let hint = if security.is_empty() {
                "security hooks may not pass session_id yet"
            } else {
                ""
            };
            (security, hint)
        }
        Err(ObservabilityError::Daemon { .. }) => {
            // v1 kept rendering the debrief when the security database was
            // unreadable, so a daemon-side failure here degrades the security
            // section instead of failing the whole report.
            (Map::new(), "failed to query security events")
        }
        Err(error) => return Err(error),
    };
    Ok(Debrief {
        session,
        llm_calls,
        request_bytes,
        response_bytes,
        tools,
        security,
        security_hint: security_hint.to_owned(),
    })
}

/// Builds v1's `SessionReport.to_dict` shape.
fn debrief_json(debrief: &Debrief) -> Value {
    let mut tools = Map::new();
    for (name, count) in &debrief.tools {
        tools.insert(name.clone(), json!(count));
    }
    json!({
        "session_id": debrief.session.session_id,
        "first_seen": epoch_to_utc(debrief.session.first_seen_epoch),
        "last_seen": epoch_to_utc(debrief.session.last_seen_epoch),
        "duration_seconds": round_tenths(
            debrief.session.last_seen_epoch - debrief.session.first_seen_epoch,
        ),
        "turn_count": debrief.session.turn_count,
        "llm_calls": debrief.llm_calls,
        "request_bytes": debrief.request_bytes,
        "response_bytes": debrief.response_bytes,
        "tool_breakdown": Value::Object(tools),
        "security_verdicts": Value::Object(debrief.security.clone()),
        "security_hint": if debrief.security_hint.is_empty() {
            Value::Null
        } else {
            Value::String(debrief.security_hint.clone())
        },
    })
}

/// Renders v1's `format_text` debrief layout.
fn render_debrief_text(debrief: &Debrief, stdout: &mut dyn io::Write) -> io::Result<()> {
    let duration = debrief.session.last_seen_epoch - debrief.session.first_seen_epoch;
    let short_id: String = debrief.session.session_id.chars().take(12).collect();
    writeln!(
        stdout,
        "Session {short_id}  ({} — {}, {}, {} turns)",
        epoch_to_utc(debrief.session.first_seen_epoch),
        epoch_to_utc(debrief.session.last_seen_epoch),
        duration_text(duration),
        debrief.session.turn_count
    )?;
    writeln!(stdout)?;
    writeln!(stdout, "  LLM calls:       {}", debrief.llm_calls)?;
    if debrief.request_bytes != 0 || debrief.response_bytes != 0 {
        writeln!(
            stdout,
            "  Payload:         {} bytes sent, {} bytes received",
            with_commas(debrief.request_bytes),
            with_commas(debrief.response_bytes)
        )?;
    }
    writeln!(stdout)?;
    if debrief.tools.is_empty() {
        writeln!(stdout, "  Tools used:      (none)")?;
    } else {
        let parts: Vec<String> = debrief
            .tools
            .iter()
            .map(|(name, count)| format!("{name}({count})"))
            .collect();
        writeln!(stdout, "  Tools used:      {}", parts.join(", "))?;
    }
    writeln!(stdout)?;
    if debrief.security.is_empty() {
        let mut message = "(no security events)".to_owned();
        if !debrief.security_hint.is_empty() {
            write!(message, " — {}", debrief.security_hint).expect("a String write cannot fail");
        }
        writeln!(stdout, "  Security:        {message}")?;
    } else {
        writeln!(stdout, "  Security:")?;
        let mut categories: Vec<(&String, &Value)> = debrief.security.iter().collect();
        categories.sort_by(|(left, _), (right, _)| left.cmp(right));
        for (category, verdicts) in categories {
            let mut counts: Vec<(&String, &Value)> = verdicts
                .as_object()
                .map_or_else(Vec::new, |verdicts| verdicts.iter().collect());
            counts.sort_by(|(left, _), (right, _)| left.cmp(right));
            let parts: Vec<String> = counts
                .iter()
                .map(|(result, count)| format!("{result}: {count}"))
                .collect();
            writeln!(stdout, "    {category:<20} {}", parts.join(", "))?;
        }
    }
    Ok(())
}

/// Appends v1's `EventDetailScreen` content for every timeline event.
fn render_event_details(
    items: &[Value],
    security_by_row: &HashMap<String, Vec<&Value>>,
    stdout: &mut dyn io::Write,
) -> io::Result<()> {
    let mut event_number = 0;
    for item in items {
        if item["kind"].as_str() != Some("observability") {
            continue;
        }
        event_number += 1;
        let hook = item["hook"].as_str().unwrap_or_default();
        let epoch = item["timestamp_epoch"].as_f64().unwrap_or_default();
        writeln!(stdout)?;
        writeln!(stdout, "Event {event_number}:")?;
        writeln!(stdout, "  Hook:        {hook}")?;
        writeln!(stdout, "  Observed at: {}", epoch_to_utc(epoch))?;
        writeln!(
            stdout,
            "  Session:     {}",
            item["session_id"].as_str().unwrap_or_default()
        )?;
        writeln!(
            stdout,
            "  Run:         {}",
            item["run_id"].as_str().unwrap_or_default()
        )?;
        if let Some(call_id) = item["call_id"].as_str() {
            writeln!(stdout, "  Call ID:     {call_id}")?;
        }
        if let Some(tool_call_id) = item["tool_call_id"].as_str() {
            writeln!(stdout, "  Tool call:   {tool_call_id}")?;
        }
        writeln!(stdout)?;
        writeln!(stdout, "  Metadata:")?;
        write_indented_json(stdout, &item["metadata"], "  ")?;
        writeln!(stdout)?;
        writeln!(stdout, "  Metrics:")?;
        write_indented_json(stdout, &item["metrics"], "  ")?;
        let correlated = security_by_row.get(&item["id"].to_string());
        if let Some(matches) = correlated
            && !matches.is_empty()
        {
            writeln!(stdout)?;
            writeln!(stdout, "  Security Events:")?;
            for (index, event_item) in matches.iter().enumerate() {
                let event = &event_item["event"];
                let match_info = &event_item["match"];
                writeln!(
                    stdout,
                    "  {}. {} / {} result={}",
                    index + 1,
                    event["category"].as_str().unwrap_or_default(),
                    event["event_type"].as_str().unwrap_or_default(),
                    event["result"].as_str().unwrap_or_default()
                )?;
                writeln!(
                    stdout,
                    "     match={} delta={:+.3}s security_at={}",
                    match_info["reason"].as_str().unwrap_or_default(),
                    match_info["time_delta_seconds"]
                        .as_f64()
                        .unwrap_or_default(),
                    epoch_to_utc(event_item["timestamp_epoch"].as_f64().unwrap_or_default())
                )?;
                writeln!(stdout, "     details:")?;
                write_indented_json(stdout, &event["details"], "     ")?;
            }
        }
    }
    Ok(())
}

/// Writes one JSON blob pretty-printed with every line indented.
fn write_indented_json(stdout: &mut dyn io::Write, value: &Value, indent: &str) -> io::Result<()> {
    let pretty = serde_json::to_string_pretty(value).expect("serializes");
    for line in pretty.lines() {
        if line.is_empty() {
            writeln!(stdout)?;
        } else {
            writeln!(stdout, "{indent}{line}")?;
        }
    }
    Ok(())
}

/// Writes merged items as one compact JSON object, mirroring the text views'
/// completeness: every page's rows appear in one `items` array.
fn write_items_json(items: &[Value], stdout: &mut dyn io::Write) -> Result<u8, ObservabilityError> {
    let json = serde_json::to_string(&json!({ "items": items })).expect("serializes");
    writeln!(stdout, "{json}")?;
    Ok(0)
}

/// Renders v1's kubectl-style columnar table.
fn render_table(
    headers: &[&str],
    rows: &[Vec<String>],
    stdout: &mut dyn io::Write,
) -> io::Result<()> {
    let mut widths: Vec<usize> = headers.iter().map(|header| header.len() + 2).collect();
    for row in rows {
        for (column, cell) in row.iter().enumerate() {
            widths[column] = widths[column].max(cell.len() + 2);
        }
    }
    let mut line = String::new();
    for (header, width) in headers.iter().zip(&widths) {
        write!(line, "{header:<width$}").expect("a String write cannot fail");
    }
    writeln!(stdout, "{}", line.trim_end())?;
    for row in rows {
        let mut line = String::new();
        for (cell, width) in row.iter().zip(&widths) {
            write!(line, "{cell:<width$}").expect("a String write cannot fail");
        }
        writeln!(stdout, "{}", line.trim_end())?;
    }
    Ok(())
}

/// Truncates to `width` characters with v1's ellipsis, which never splits a
/// multi-byte character.
fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_owned();
    }
    let cut = value
        .char_indices()
        .nth(width.saturating_sub(1))
        .map_or(0, |(index, _)| index);
    format!("{}…", &value[..cut])
}

/// Groups an integer with v1's thousands separators.
fn with_commas(value: u64) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

/// Rounds to one decimal place, v1's `round(duration, 1)`.
fn round_tenths(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

/// Formats a duration the way v1's report header does.
fn duration_text(duration: f64) -> String {
    if duration >= 60.0 {
        let minutes = (duration / 60.0).floor();
        let seconds = (duration - minutes * 60.0).floor();
        // Both components truncate toward zero, matching v1's `int()`.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        {
            format!("{}m {}s", minutes as i64, seconds as i64)
        }
    } else {
        format!("{duration:.0}s")
    }
}

/// Formats a UTC epoch second as v1's `"%Y-%m-%d %H:%M:%S"`.
fn epoch_to_utc(epoch: f64) -> String {
    // Epoch seconds are far inside f64's exact-integer range, so the floor
    // and the truncating cast lose nothing for any real timestamp.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let total_seconds = epoch.floor() as i64;
    let days = total_seconds.div_euclid(86_400);
    let day_seconds = total_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
}

/// Converts days since 1970-01-01 to a proleptic Gregorian date.
///
/// Howard Hinnant's `civil_from_days`: the arithmetic keeps every quotient
/// exact in `i64`, so no cast or overflow check is needed.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = u32::try_from(day_of_year - (153 * mp + 2) / 5 + 1).expect("1..=31");
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let month = u32::try_from(month).expect("1..=12");
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asc_daemon_protocol::RequestId;
    use clap::Parser;
    use std::collections::VecDeque;

    #[derive(Debug, Parser)]
    struct ReportCli {
        #[command(flatten)]
        report: ReportCommand,
    }

    #[derive(Debug, Parser)]
    struct ReviewCli {
        #[command(flatten)]
        review: ReviewCommand,
    }

    fn report(args: &[&str]) -> ReportCommand {
        ReportCli::parse_from(std::iter::once("cli").chain(args.iter().copied())).report
    }

    fn review(args: &[&str]) -> ReviewCommand {
        ReviewCli::parse_from(std::iter::once("cli").chain(args.iter().copied())).review
    }

    /// Serves queued responses in order and records every request.
    struct Scripted {
        responses: VecDeque<DaemonResponse>,
        requests: Vec<(String, Value)>,
    }

    impl QueryTransport for Scripted {
        fn call(&mut self, request: DaemonRequest) -> Result<DaemonResponse, ClientError> {
            self.requests
                .push((request.method.clone(), request.params.clone()));
            self.responses
                .pop_front()
                .ok_or(ClientError::InvalidTimeout)
        }
    }

    fn scripted(responses: Vec<DaemonResponse>) -> Scripted {
        Scripted {
            responses: VecDeque::from(responses),
            requests: Vec::new(),
        }
    }

    fn request_id() -> RequestId {
        RequestId::new("test".to_owned()).expect("non-empty")
    }

    fn success(result: Value) -> DaemonResponse {
        DaemonResponse::success(request_id(), result)
    }

    fn failure() -> DaemonResponse {
        DaemonResponse::error(request_id(), "unavailable", "not configured")
    }

    fn session_item(session_id: &str, first: f64, last: f64, turns: u64, events: u64) -> Value {
        json!({
            "session_id": session_id,
            "first_seen_epoch": first,
            "last_seen_epoch": last,
            "turn_count": turns,
            "observability_event_count": events,
            "security_event_count": 0,
        })
    }

    fn run_item(run_id: &str, started: f64, preview: Value, events: u64) -> Value {
        json!({
            "run_id": run_id,
            "started_at_epoch": started,
            "ended_at_epoch": started + 10.0,
            "user_input_preview": preview,
            "observability_event_count": events,
            "security_event_count": 0,
        })
    }

    fn obs_item(id: i64, hook: &str, epoch: f64, metrics: Value) -> Value {
        json!({
            "kind": "observability",
            "id": id,
            "hook": hook,
            "timestamp": "2026-01-01T00:00:00Z",
            "timestamp_epoch": epoch,
            "session_id": "s-1",
            "run_id": "r-1",
            "call_id": null,
            "tool_call_id": null,
            "metadata": {},
            "metrics": metrics,
        })
    }

    fn sec_item(observed_id: i64, epoch: f64, category: &str, result: &str) -> Value {
        json!({
            "kind": "security",
            "observability_event_id": observed_id,
            "observability": {},
            "hook": "before_tool_call",
            "session_id": "s-1",
            "run_id": "r-1",
            "call_id": null,
            "tool_call_id": "tc-1",
            "timestamp": "2026-01-01T00:00:00Z",
            "timestamp_epoch": epoch,
            "event": { "category": category, "result": result },
            "match": { "reason": "exact", "rank": 0, "time_delta_seconds": 0.25 },
        })
    }

    fn list_response(items: &[Value], total: u64, next: Option<u64>) -> Value {
        json!({
            "items": items,
            "total": total,
            "limit": 1000,
            "offset": 0,
            "next_offset": next,
        })
    }

    fn timeline_response(items: &[Value]) -> Value {
        json!({
            "session_id": "s-1",
            "run_id": "r-1",
            "limit": 1000,
            "offset": 0,
            "items": items,
        })
    }

    /// One debrief script: session s-1, runs r-1 and r-2, two LLM calls,
    /// three tool calls, and three security events.
    fn debrief_script() -> Vec<DaemonResponse> {
        vec![
            success(list_response(
                &[session_item("s-1", 0.0, 100.0, 2, 5)],
                1,
                None,
            )),
            success(list_response(
                &[
                    run_item("r-1", 10.0, json!("list files"), 3),
                    run_item("r-2", 60.0, json!("second"), 2),
                ],
                2,
                None,
            )),
            success(timeline_response(&[
                obs_item(
                    1,
                    "before_agent_run",
                    10.0,
                    json!({"user_input": "list files"}),
                ),
                obs_item(2, "before_tool_call", 15.0, json!({"tool_name": "bash"})),
                obs_item(
                    3,
                    "after_llm_call",
                    20.0,
                    json!({"request_payload_bytes": 120, "response_stream_bytes": 3400}),
                ),
            ])),
            success(timeline_response(&[
                obs_item(4, "before_agent_run", 60.0, json!({"user_input": "second"})),
                obs_item(5, "before_tool_call", 65.0, json!({"tool_name": "read"})),
                obs_item(
                    6,
                    "after_llm_call",
                    70.0,
                    json!({"request_payload_bytes": 120, "response_stream_bytes": 3400}),
                ),
            ])),
            success(list_response(
                &[
                    json!({"category": "code_scan", "result": "succeeded"}),
                    json!({"category": "code_scan", "result": "succeeded"}),
                    json!({"category": "prompt_scan", "result": "failed"}),
                ],
                3,
                None,
            )),
        ]
    }

    fn text_of(output: &Vec<u8>) -> String {
        String::from_utf8_lossy(output).into_owned()
    }

    #[test]
    fn the_v1_report_flags_parse() {
        let command = report(&["--session-id", "s-1", "--format", "json"]);
        assert_eq!(command.session_id.as_deref(), Some("s-1"));
        assert!(!command.last);
        assert_eq!(command.format, "json");
        let command = report(&["--last"]);
        assert!(command.last);
        assert_eq!(command.format, "text");
    }

    #[test]
    fn invalid_report_input_is_rejected_before_transport() {
        let cases: Vec<Vec<&str>> = vec![
            vec!["--format", "csv"],
            vec![],
            vec!["--session-id", "s-1", "--last"],
        ];
        for args in cases {
            let mut transport = scripted(Vec::new());
            let error = report(&args)
                .run(&mut transport, &mut Vec::new())
                .expect_err("rejected locally");
            assert!(
                matches!(error, ObservabilityError::Input(_)),
                "{args:?} must be a usage error"
            );
            assert!(transport.requests.is_empty(), "no request may be sent");
        }
    }

    #[test]
    fn last_reports_the_most_recent_session() {
        let mut transport = scripted(debrief_script());
        let mut output = Vec::new();
        let code = report(&["--last"])
            .run(&mut transport, &mut output)
            .expect("report");
        assert_eq!(code, 0);
        assert_eq!(transport.requests[0].0, "obs.sessions.list");
        assert_eq!(transport.requests[0].1["limit"], json!(1));
        let text = text_of(&output);
        assert!(text.contains("Session s-1  ("), "header: {text}");
    }

    #[test]
    fn a_session_beyond_the_first_page_is_found() {
        let mut responses = vec![
            success(list_response(
                &[session_item("s-other", 0.0, 50.0, 1, 1)],
                2,
                Some(1),
            )),
            success(list_response(
                &[session_item("s-1", 0.0, 100.0, 2, 5)],
                2,
                None,
            )),
        ];
        responses.extend(debrief_script().into_iter().skip(1));
        let mut transport = scripted(responses);
        let mut output = Vec::new();
        let code = report(&["--session-id", "s-1"])
            .run(&mut transport, &mut output)
            .expect("report");
        assert_eq!(code, 0);
        let session_requests = transport
            .requests
            .iter()
            .filter(|(method_name, _)| method_name == "obs.sessions.list")
            .count();
        assert_eq!(session_requests, 2, "the walk must follow next_offset");
        assert!(text_of(&output).contains("Session s-1"));
    }

    #[test]
    fn a_missing_session_is_a_usage_error() {
        let mut transport = scripted(vec![success(list_response(&[], 0, None))]);
        let error = report(&["--session-id", "nope"])
            .run(&mut transport, &mut Vec::new())
            .expect_err("not found");
        assert_eq!(
            error.to_string(),
            "Error: session 'nope' not found.",
            "v1 wording"
        );
    }

    #[test]
    fn no_sessions_is_reported_as_v1_worded_it() {
        let mut transport = scripted(vec![success(list_response(&[], 0, None))]);
        let error = report(&["--last"])
            .run(&mut transport, &mut Vec::new())
            .expect_err("no sessions");
        assert_eq!(error.to_string(), "No sessions recorded.", "v1 wording");
    }

    #[test]
    fn the_debrief_json_matches_the_v1_shape() {
        let mut transport = scripted(debrief_script());
        let mut output = Vec::new();
        let code = report(&["--last", "--format", "json"])
            .run(&mut transport, &mut output)
            .expect("report");
        assert_eq!(code, 0);
        let parsed: Value = serde_json::from_str(&text_of(&output)).expect("json");
        assert_eq!(parsed["session_id"], json!("s-1"));
        assert_eq!(parsed["first_seen"], json!("1970-01-01 00:00:00"));
        assert_eq!(parsed["last_seen"], json!("1970-01-01 00:01:40"));
        assert_eq!(parsed["duration_seconds"], json!(100.0));
        assert_eq!(parsed["turn_count"], json!(2));
        assert_eq!(parsed["llm_calls"], json!(2));
        assert_eq!(parsed["request_bytes"], json!(240));
        assert_eq!(parsed["response_bytes"], json!(6800));
        assert_eq!(
            parsed["tool_breakdown"],
            json!({"bash": 1, "read": 1}),
            "count-desc with first-seen tie order"
        );
        assert_eq!(
            parsed["security_verdicts"],
            json!({"code_scan": {"succeeded": 2}, "prompt_scan": {"failed": 1}})
        );
        assert_eq!(parsed["security_hint"], Value::Null);
        let raw = text_of(&output);
        assert!(
            raw.contains("\"bash\":1,\"read\":1") || raw.contains("\"bash\": 1,\"read\": 1"),
            "tool order is count-desc: {raw}"
        );
    }

    #[test]
    fn the_debrief_text_matches_the_v1_layout() {
        let mut transport = scripted(debrief_script());
        let mut output = Vec::new();
        report(&["--last"])
            .run(&mut transport, &mut output)
            .expect("report");
        let text = text_of(&output);
        let expected = [
            "Session s-1  (1970-01-01 00:00:00 — 1970-01-01 00:01:40, 1m 40s, 2 turns)",
            "",
            "  LLM calls:       2",
            "  Payload:         240 bytes sent, 6,800 bytes received",
            "",
            "  Tools used:      bash(1), read(1)",
            "",
            "  Security:",
            "    code_scan            succeeded: 2",
            "    prompt_scan          failed: 1",
        ];
        assert_eq!(text, expected.join("\n") + "\n", "v1 format_text layout");
    }

    #[test]
    fn a_security_query_failure_keeps_the_debrief() {
        let mut responses = debrief_script();
        responses.pop();
        responses.push(failure());
        let mut transport = scripted(responses);
        let mut output = Vec::new();
        let code = report(&["--last"])
            .run(&mut transport, &mut output)
            .expect("report still renders");
        assert_eq!(code, 0);
        let text = text_of(&output);
        assert!(
            text.contains(
                "  Security:        (no security events) — failed to query security events"
            ),
            "v1 hint: {text}"
        );
    }

    #[test]
    fn a_daemon_error_fails_the_report() {
        let mut transport = scripted(vec![failure()]);
        let error = report(&["--last"])
            .run(&mut transport, &mut Vec::new())
            .expect_err("daemon failure");
        assert!(matches!(error, ObservabilityError::Daemon { .. }));
        assert_eq!(
            error.to_string(),
            "observability query failed: not configured (unavailable)"
        );
    }

    #[test]
    fn review_sessions_table_matches_the_v1_columns() {
        let mut transport = scripted(vec![success(list_response(
            &[
                session_item("s-1", 0.0, 100.0, 2, 5),
                session_item("s-2", 0.0, 40.0, 1, 1),
            ],
            2,
            None,
        ))]);
        let mut output = Vec::new();
        let code = review(&[])
            .run(&mut transport, &mut output)
            .expect("review");
        assert_eq!(code, 0);
        let text = text_of(&output);
        assert!(text.contains("LAST_SEEN"), "headers: {text}");
        assert!(text.contains("SESSION"));
        assert!(text.contains("TURNS"));
        assert!(text.contains("EVENTS"));
        assert!(text.contains("s-1"));
        assert!(
            text.contains("1970-01-01 00:01:40"),
            "last-seen render: {text}"
        );
    }

    #[test]
    fn review_runs_table_renders_previews() {
        let mut transport = scripted(vec![success(list_response(
            &[
                run_item("r-1", 1_767_225_610.0, json!("list files"), 3),
                run_item("r-2", 1_767_225_670.0, Value::Null, 2),
            ],
            2,
            None,
        ))]);
        let mut output = Vec::new();
        let code = review(&["--session-id", "s-1"])
            .run(&mut transport, &mut output)
            .expect("review");
        assert_eq!(code, 0);
        let text = text_of(&output);
        assert!(text.contains("STARTED"), "headers: {text}");
        assert!(text.contains("list files"));
        assert!(text.contains("(no user_input)"), "v1 preview default");
        assert!(text.contains("2026-01-01 00:00:10"), "UTC render: {text}");
        assert_eq!(transport.requests[0].0, "obs.runs.list");
        assert_eq!(transport.requests[0].1["session_id"], json!("s-1"));
    }

    #[test]
    fn review_timeline_joins_security_results_per_row() {
        let mut transport = scripted(vec![success(timeline_response(&[
            obs_item(1, "before_tool_call", 15.0, json!({"tool_name": "bash"})),
            sec_item(1, 15.25, "code_scan", "succeeded"),
            obs_item(2, "after_llm_call", 20.0, json!({})),
        ]))]);
        let mut output = Vec::new();
        let code = review(&["--session-id", "s-1", "--run-id", "r-1"])
            .run(&mut transport, &mut output)
            .expect("review");
        assert_eq!(code, 0);
        let text = text_of(&output);
        assert!(text.contains("TIME"), "headers: {text}");
        assert!(text.contains("before_tool_call"));
        assert!(
            text.contains("code_scan:succeeded"),
            "joined column: {text}"
        );
        let security_column = text
            .lines()
            .find(|line| line.contains("after_llm_call"))
            .expect("second row");
        assert!(
            security_column.trim_end().ends_with('-'),
            "no match: {text}"
        );
    }

    #[test]
    fn review_details_print_the_full_records() {
        let mut transport = scripted(vec![success(timeline_response(&[
            obs_item(1, "before_tool_call", 15.0, json!({"tool_name": "bash"})),
            sec_item(1, 15.25, "code_scan", "succeeded"),
        ]))]);
        let mut output = Vec::new();
        let code = review(&["--session-id", "s-1", "--run-id", "r-1", "--details"])
            .run(&mut transport, &mut output)
            .expect("review");
        assert_eq!(code, 0);
        let text = text_of(&output);
        assert!(text.contains("Event 1:"), "block header: {text}");
        assert!(text.contains("  Hook:        before_tool_call"));
        assert!(text.contains("  Metadata:"));
        assert!(text.contains("  Metrics:"));
        assert!(text.contains("  Security Events:"));
        assert!(text.contains("match=exact delta=+0.250s"), "v1 match line");
    }

    #[test]
    fn review_json_dumps_every_page_of_the_items() {
        let mut transport = scripted(vec![
            success(list_response(
                &[session_item("s-1", 0.0, 100.0, 2, 5)],
                2,
                Some(1),
            )),
            success(list_response(
                &[session_item("s-2", 0.0, 40.0, 1, 1)],
                2,
                None,
            )),
        ]);
        let mut output = Vec::new();
        let code = review(&["--format", "json"])
            .run(&mut transport, &mut output)
            .expect("review");
        assert_eq!(code, 0);
        let parsed: Value = serde_json::from_str(&text_of(&output)).expect("json");
        assert_eq!(parsed["items"].as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn review_empty_states_match_the_v1_wording() {
        let cases: Vec<(&[&str], Vec<DaemonResponse>, &str)> = vec![
            (
                &[],
                vec![success(list_response(&[], 0, None))],
                "No observability records found.",
            ),
            (
                &["--session-id", "s-1"],
                vec![success(list_response(&[], 0, None))],
                "No runs recorded for this session.",
            ),
            (
                &["--session-id", "s-1", "--run-id", "r-1"],
                vec![success(timeline_response(&[]))],
                "No events for this run.",
            ),
        ];
        for (args, responses, expected) in cases {
            let mut transport = scripted(responses);
            let mut output = Vec::new();
            let code = review(args)
                .run(&mut transport, &mut output)
                .expect("empty is not an error");
            assert_eq!(code, 0);
            assert_eq!(text_of(&output), format!("{expected}\n"));
        }
    }

    #[test]
    fn review_requires_a_session_for_a_run_and_details() {
        for args in [&["--run-id", "r-1"][..], &["--details"][..]] {
            let mut transport = scripted(Vec::new());
            let error = review(args)
                .run(&mut transport, &mut Vec::new())
                .expect_err("rejected locally");
            assert!(matches!(error, ObservabilityError::Input(_)));
            assert!(transport.requests.is_empty());
        }
    }

    #[test]
    fn the_timeline_walk_follows_observability_rows() {
        let mut epoch = 15.0;
        let mut first_page = Vec::new();
        for index in 0..1000 {
            first_page.push(obs_item(index, "after_llm_call", epoch, json!({})));
            epoch += 1.0;
        }
        let second_page = vec![
            obs_item(
                1000,
                "before_tool_call",
                2_000.0,
                json!({"tool_name": "bash"}),
            ),
            sec_item(1000, 2_000.25, "code_scan", "succeeded"),
        ];
        let mut transport = scripted(vec![
            success(timeline_response(&first_page)),
            success(timeline_response(&second_page)),
        ]);
        let mut output = Vec::new();
        let code = review(&["--session-id", "s-1", "--run-id", "r-1"])
            .run(&mut transport, &mut output)
            .expect("review");
        assert_eq!(code, 0);
        assert_eq!(transport.requests.len(), 2, "two pages");
        assert_eq!(transport.requests[1].1["offset"], json!(1000));
        let text = text_of(&output);
        assert!(text.contains("code_scan:succeeded"), "second page: {text}");
    }

    #[test]
    fn epoch_formatting_is_pinned() {
        let cases: [(f64, &str); 6] = [
            (0.0, "1970-01-01 00:00:00"),
            (-1.0, "1969-12-31 23:59:59"),
            (1_767_225_600.0, "2026-01-01 00:00:00"),
            (1_709_251_200.0, "2024-03-01 00:00:00"),
            (951_782_400.0, "2000-02-29 00:00:00"),
            (1_767_225_600.9, "2026-01-01 00:00:00"),
        ];
        for (epoch, expected) in cases {
            assert_eq!(epoch_to_utc(epoch), expected, "epoch {epoch}");
        }
    }

    #[test]
    fn thousands_separation_matches_python_formatting() {
        let cases: [(u64, &str); 5] = [
            (0, "0"),
            (999, "999"),
            (1_000, "1,000"),
            (6_800, "6,800"),
            (1_234_567, "1,234,567"),
        ];
        for (value, expected) in cases {
            assert_eq!(with_commas(value), expected);
        }
    }
}
