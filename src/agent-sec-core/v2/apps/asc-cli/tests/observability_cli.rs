//! End-to-end `observability report` / `review` through the real CLI binary.
//!
//! Proves what the unit tests cannot: the v2 CLI restores v1's user entry
//! points on top of the daemon's owner-scoped `obs.*` and `sec.*` query
//! methods, and the rows another owner wrote into the shared system stores
//! never reach the debrief aggregates, the session lists, or the run timeline
//! (issue #6608).

use std::ffi::OsString;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use asc_daemon::{BootstrapConfig, scan_application, serve};
use asc_daemon_core::{PeerCredentials, PrincipalPolicy, PrincipalRole};
use asc_daemon_handler::{
    DaemonDispatcher, JsonRejectionEncoder, SqliteEventQuerySource, SqliteObservabilityQuerySource,
};
use asc_pap::PapService;
use asc_pap_repository_memory::ProcessLocalPapRepository;
use asc_persistence_sqlite::observability::SYSTEM_OBSERVABILITY_TABLES;
use asc_persistence_sqlite::observability::table::SYSTEM_OBSERVABILITY_SQLITE_SCHEMA_VERSION;
use asc_persistence_sqlite::security_events::SqliteEventWriter;
use asc_policy_engine::PolicyTemplateCompiler;
use asc_security_events::SecurityEvent;
use asc_sqlite_kernel::SqliteStore;
use serde_json::{Map, Value, json};
use tokio::net::UnixStream;

mod common;

/// A foreign owner that certainly did not open this socket.
const FOREIGN_UID: u32 = 42_424_242;

/// The epoch of 2026-01-01T00:00:00Z, the base of every seeded instant.
const BASE_EPOCH: f64 = 1_767_225_600.0;

const INSERT_SQL: &str = "INSERT INTO observability_events (hook, observed_at, \
     observed_at_epoch, session_id, run_id, metrics_json, metadata_json, call_id, \
     tool_call_id, owner) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";

#[derive(Clone, Copy)]
struct FixedRolePolicy(PrincipalRole);

impl PrincipalPolicy for FixedRolePolicy {
    fn role_for(&self, _peer: PeerCredentials) -> PrincipalRole {
        self.0
    }
}

struct RunningDaemon {
    shutdown: asc_daemon_service::ShutdownToken,
    task: tokio::task::JoinHandle<()>,
}

impl RunningDaemon {
    async fn start(socket: &Path, observability: &Path, security: &Path) -> Self {
        let application = PapService::new(
            Arc::new(ProcessLocalPapRepository::default()),
            Arc::new(PolicyTemplateCompiler),
        );
        // The action runtime is not under test; the testing finalizer keeps
        // the scan methods wired without writing into the query stores.
        let dispatcher = Arc::new(
            DaemonDispatcher::new(
                application,
                Arc::new(FixedRolePolicy(PrincipalRole::LocalUser)),
                scan_application(
                    asc_action_runtime::testing::discarding_finalizer(),
                    Arc::new(asc_capability_pii_scan::PiiRuleSet::builtin().unwrap()),
                ),
            )
            .with_security_queries(
                SqliteEventQuerySource::new(security).expect("security query source opens"),
            )
            .with_observability_queries(
                SqliteObservabilityQuerySource::new(observability, security)
                    .expect("query source opens"),
            ),
        );
        let shutdown = asc_daemon_service::ShutdownToken::new();
        let service_shutdown = shutdown.clone();
        let mut config = BootstrapConfig::new(socket);
        config.service.request_read_timeout = Duration::from_millis(50);
        let task = tokio::spawn(async move {
            serve(
                config,
                dispatcher,
                Arc::new(JsonRejectionEncoder),
                service_shutdown,
            )
            .await
            .unwrap();
        });
        wait_for_socket(socket).await;
        Self { shutdown, task }
    }

    async fn stop(self) {
        self.shutdown.request();
        self.task.await.unwrap();
    }
}

async fn wait_for_socket(path: &Path) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(probe) = UnixStream::connect(path).await {
                drop(probe);
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("daemon should accept connections on its socket");
}

/// Seeds the system observability store with two owners' rows.
///
/// The caller's own session "s-own" carries a full turn: a user input, a bash
/// tool call, an LLM call with payload sizes, and a second run. The foreign
/// owner seeds the same session, run and tool-call spellings (so any leak of
/// the owner predicate inflates the debrief) plus its own session "s-foreign"
/// (so any row-level leak shows up in the session list).
fn seed_observability(path: &Path, own_uid: u32) {
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
            for (hook, epoch, session, run, owner, metrics, call_id, tool_call_id) in [
                (
                    "before_agent_run",
                    BASE_EPOCH + 100.0,
                    "s-own",
                    "r-1",
                    own_uid,
                    r#"{"user_input":"list files"}"#,
                    None,
                    None,
                ),
                (
                    "before_tool_call",
                    BASE_EPOCH + 105.0,
                    "s-own",
                    "r-1",
                    own_uid,
                    r#"{"tool_name":"bash"}"#,
                    None,
                    Some("tc-1"),
                ),
                (
                    "after_llm_call",
                    BASE_EPOCH + 110.0,
                    "s-own",
                    "r-1",
                    own_uid,
                    r#"{"request_payload_bytes":120,"response_stream_bytes":3400}"#,
                    Some("c-1"),
                    None,
                ),
                (
                    "before_agent_run",
                    BASE_EPOCH + 200.0,
                    "s-own",
                    "r-2",
                    own_uid,
                    r#"{"user_input":"second"}"#,
                    None,
                    None,
                ),
                (
                    "before_tool_call",
                    BASE_EPOCH + 150.0,
                    "s-own",
                    "r-1",
                    FOREIGN_UID,
                    r#"{"tool_name":"curl"}"#,
                    None,
                    Some("tc-1"),
                ),
                (
                    "before_agent_run",
                    BASE_EPOCH + 300.0,
                    "s-foreign",
                    "r-f",
                    FOREIGN_UID,
                    r#"{"user_input":"foreign session"}"#,
                    None,
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
                        call_id,
                        tool_call_id,
                        owner,
                    ],
                )?;
            }
            Ok(())
        })
        .expect("seed");
}

/// Renders one seeded epoch as the matching v1 wire timestamp.
fn epoch_iso(epoch: f64) -> String {
    let seconds = epoch.floor() as i64 % 86_400;
    let (hour, minute, second) = (seconds / 3_600, (seconds % 3_600) / 60, seconds % 60);
    format!("2026-01-01T{hour:02}:{minute:02}:{second:02}Z")
}

/// Seeds the security-event store: the caller's own code_scan on the r-1 tool
/// call plus a prompt_scan failure, and a foreign code_scan under the same
/// session, run and tool-call spellings.
fn seed_security(path: &Path, own_uid: u32) {
    let writer = SqliteEventWriter::new(path).expect("writer");
    let mut event = SecurityEvent::new("sandbox_prehook", "code_scan", Map::new());
    event.uid = own_uid;
    event.session_id = Some("s-own".to_owned());
    event.run_id = Some("r-1".to_owned());
    event.tool_call_id = Some("tc-1".to_owned());
    event.timestamp = "2026-01-01T00:01:44+00:00".to_owned();
    event
        .details
        .insert("request".to_owned(), json!({"code": "ls -la /tmp"}));
    writer.write(&event);
    let mut event = SecurityEvent::new("prompt_scan_result", "prompt_scan", Map::new());
    event.uid = own_uid;
    event.session_id = Some("s-own".to_owned());
    event.run_id = Some("r-1".to_owned());
    event.result = asc_security_events::EventResult::Failed;
    event.timestamp = "2026-01-01T00:01:45+00:00".to_owned();
    writer.write(&event);
    let mut event = SecurityEvent::new("sandbox_prehook", "code_scan", Map::new());
    event.uid = FOREIGN_UID;
    event.session_id = Some("s-own".to_owned());
    event.run_id = Some("r-1".to_owned());
    event.tool_call_id = Some("tc-1".to_owned());
    event.timestamp = "2026-01-01T00:01:46+00:00".to_owned();
    writer.write(&event);
    writer.close_at(1000.0);
}

/// One CLI invocation against the running daemon.
fn cli(socket: &Path, args: &[&str]) -> std::process::Output {
    let mut argv: Vec<OsString> = vec!["--socket".into(), socket.to_str().unwrap().into()];
    argv.extend(args.iter().map(OsString::from));
    common::run(&argv)
}

fn stdout_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn report_debriefs_the_callers_latest_session_in_json() {
    let directory = common::Directory::new();
    let socket = directory.0.join("daemon.sock");
    let observability = directory.0.join("observability.db");
    let security = directory.0.join("security-events.db");
    let own_uid = rustix::process::getuid().as_raw();
    seed_observability(&observability, own_uid);
    seed_security(&security, own_uid);
    let daemon = RunningDaemon::start(&socket, &observability, &security).await;

    // Issue #6608's reproduction step 3, verbatim.
    let output = cli(
        &socket,
        &["observability", "report", "--last", "--format", "json"],
    );
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    let report: Value = serde_json::from_slice(&output.stdout).expect("json report");
    assert_eq!(report["session_id"], json!("s-own"));
    assert_eq!(report["turn_count"], json!(2), "own runs r-1 and r-2");
    assert_eq!(report["llm_calls"], json!(1));
    assert_eq!(report["request_bytes"], json!(120));
    assert_eq!(report["response_bytes"], json!(3400));
    assert_eq!(
        report["tool_breakdown"],
        json!({"bash": 1}),
        "the foreign curl row must not leak into the aggregate"
    );
    assert_eq!(
        report["security_verdicts"],
        json!({"code_scan": {"succeeded": 1}, "prompt_scan": {"failed": 1}}),
        "the foreign security event must not leak into the verdicts"
    );
    assert_eq!(report["first_seen"], json!("2026-01-01 00:01:40"));
    assert_eq!(report["last_seen"], json!("2026-01-01 00:03:20"));
    assert_eq!(report["duration_seconds"], json!(100.0));
    assert_eq!(report["security_hint"], Value::Null);
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn report_text_matches_the_v1_debrief_layout() {
    let directory = common::Directory::new();
    let socket = directory.0.join("daemon.sock");
    let observability = directory.0.join("observability.db");
    let security = directory.0.join("security-events.db");
    let own_uid = rustix::process::getuid().as_raw();
    seed_observability(&observability, own_uid);
    seed_security(&security, own_uid);
    let daemon = RunningDaemon::start(&socket, &observability, &security).await;

    let output = cli(
        &socket,
        &["observability", "report", "--session-id", "s-own"],
    );
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    let text = stdout_of(&output);
    let expected = [
        "Session s-own  (2026-01-01 00:01:40 — 2026-01-01 00:03:20, 1m 40s, 2 turns)",
        "",
        "  LLM calls:       1",
        "  Payload:         120 bytes sent, 3,400 bytes received",
        "",
        "  Tools used:      bash(1)",
        "",
        "  Security:",
        "    code_scan            succeeded: 1",
        "    prompt_scan          failed: 1",
    ];
    assert_eq!(text, expected.join("\n") + "\n", "v1 format_text layout");
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn report_rejects_a_session_the_caller_does_not_own() {
    let directory = common::Directory::new();
    let socket = directory.0.join("daemon.sock");
    let observability = directory.0.join("observability.db");
    let security = directory.0.join("security-events.db");
    let own_uid = rustix::process::getuid().as_raw();
    seed_observability(&observability, own_uid);
    seed_security(&security, own_uid);
    let daemon = RunningDaemon::start(&socket, &observability, &security).await;

    // The foreign session exists in the shared store, but the caller's scope
    // makes it indistinguishable from a missing one.
    let output = cli(
        &socket,
        &["observability", "report", "--session-id", "s-foreign"],
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stderr_of(&output),
        "Error: session 's-foreign' not found.\n"
    );
    let output = cli(&socket, &["observability", "report"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stderr_of(&output),
        "Error: specify --session-id or --last.\n"
    );
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_lists_only_the_callers_sessions() {
    let directory = common::Directory::new();
    let socket = directory.0.join("daemon.sock");
    let observability = directory.0.join("observability.db");
    let security = directory.0.join("security-events.db");
    let own_uid = rustix::process::getuid().as_raw();
    seed_observability(&observability, own_uid);
    seed_security(&security, own_uid);
    let daemon = RunningDaemon::start(&socket, &observability, &security).await;

    let output = cli(&socket, &["observability", "review"]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    let text = stdout_of(&output);
    assert!(text.contains("LAST_SEEN"), "headers: {text}");
    assert!(text.contains("s-own"), "own session: {text}");
    assert!(
        !text.contains("s-foreign"),
        "the foreign session must not appear: {text}"
    );
    assert!(text.contains("2026-01-01 00:03:20"), "last seen: {text}");

    let output = cli(&socket, &["observability", "review", "--format", "json"]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    let parsed: Value = serde_json::from_slice(&output.stdout).expect("json");
    let items = parsed["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "one own session: {parsed}");
    assert_eq!(items[0]["session_id"], json!("s-own"));
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_renders_the_run_timeline_with_security_results() {
    let directory = common::Directory::new();
    let socket = directory.0.join("daemon.sock");
    let observability = directory.0.join("observability.db");
    let security = directory.0.join("security-events.db");
    let own_uid = rustix::process::getuid().as_raw();
    seed_observability(&observability, own_uid);
    seed_security(&security, own_uid);
    let daemon = RunningDaemon::start(&socket, &observability, &security).await;

    let output = cli(
        &socket,
        &[
            "observability",
            "review",
            "--session-id",
            "s-own",
            "--run-id",
            "r-1",
        ],
    );
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    let text = stdout_of(&output);
    assert!(text.contains("TIME"), "headers: {text}");
    assert!(text.contains("before_agent_run"), "{text}");
    assert!(text.contains("before_tool_call"), "{text}");
    assert!(text.contains("after_llm_call"), "{text}");
    assert!(
        text.contains("code_scan:succeeded") || text.contains("code_scan:allowed"),
        "correlated security column: {text}"
    );
    assert!(
        !text.contains("curl"),
        "the foreign tool row must not appear: {text}"
    );

    let output = cli(
        &socket,
        &[
            "observability",
            "review",
            "--session-id",
            "s-own",
            "--run-id",
            "r-1",
            "--details",
        ],
    );
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    let text = stdout_of(&output);
    assert!(text.contains("Event 1:"), "{text}");
    assert!(text.contains("  Metadata:"), "{text}");
    assert!(text.contains("  Metrics:"), "{text}");
    assert!(text.contains("  Security Events:"), "{text}");
    assert!(text.contains("match="), "{text}");
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_requires_a_session_for_a_run() {
    let directory = common::Directory::new();
    let socket = directory.0.join("daemon.sock");
    let observability = directory.0.join("observability.db");
    let security = directory.0.join("security-events.db");
    let own_uid = rustix::process::getuid().as_raw();
    seed_observability(&observability, own_uid);
    seed_security(&security, own_uid);
    let daemon = RunningDaemon::start(&socket, &observability, &security).await;

    let output = cli(&socket, &["observability", "review", "--run-id", "r-1"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stderr_of(&output),
        "Error: --run-id requires --session-id.\n"
    );
    daemon.stop().await;
}
