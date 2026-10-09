//! End-to-end `obs.*` owner-scoped queries over a real Unix socket.
//!
//! Proves the wiring the unit tests cannot: that the v1 observability query
//! methods are registered, that a local peer is authorized to call them, and
//! that the rows another owner wrote into the shared system store are
//! invisible — in session lists, in run lists, in the per-session security
//! counts, and in the timeline's correlated security events (issue #6608).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use asc_action_runtime::Finalizer;
use asc_daemon::{BootstrapConfig, scan_application, serve};
use asc_daemon_core::{PeerCredentials, PrincipalPolicy, PrincipalRole};
use asc_daemon_handler::{DaemonDispatcher, JsonRejectionEncoder, SqliteObservabilityQuerySource};
use asc_pap::PapService;
use asc_pap_repository_memory::ProcessLocalPapRepository;
use asc_persistence_sqlite::observability::table::SYSTEM_OBSERVABILITY_SQLITE_SCHEMA_VERSION;
use asc_persistence_sqlite::observability::{
    SYSTEM_OBSERVABILITY_TABLES, SystemObservabilityReader,
};
use asc_persistence_sqlite::security_events::SqliteEventWriter;
use asc_policy_engine::PolicyTemplateCompiler;
use asc_security_events::SecurityEvent;
use asc_sqlite_kernel::SqliteStore;
use serde_json::{Map, json};
use tokio::net::UnixStream;

mod support;

use support::request_json;

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
    directory: PathBuf,
    socket_path: PathBuf,
    shutdown: asc_daemon_service::ShutdownToken,
    task: tokio::task::JoinHandle<()>,
}

impl RunningDaemon {
    async fn start(role: PrincipalRole, observability: &Path, security: &Path) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "asc-daemon-obs-query-{}-{}",
            std::process::id(),
            support_directory_id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let socket_path = directory.join("daemon.sock");
        let application = PapService::new(
            Arc::new(ProcessLocalPapRepository::default()),
            Arc::new(PolicyTemplateCompiler),
        );
        // The action runtime is not under test; a discarding finalizer keeps
        // the scan methods wired without writing into the query stores.
        let outputs = Arc::new(DiscardingOutputs);
        let dispatcher = Arc::new(
            DaemonDispatcher::new(
                application,
                Arc::new(FixedRolePolicy(role)),
                scan_application(
                    Finalizer::new(outputs.clone(), outputs.clone(), outputs.clone()),
                    Arc::new(asc_capability_pii_scan::PiiRuleSet::builtin().unwrap()),
                ),
            )
            .with_observability_queries(
                SqliteObservabilityQuerySource::new(observability, security)
                    .expect("query source opens"),
            ),
        );
        let shutdown = asc_daemon_service::ShutdownToken::new();
        let service_shutdown = shutdown.clone();
        let mut config = BootstrapConfig::new(&socket_path);
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
        wait_for_socket(&socket_path).await;
        Self {
            directory,
            socket_path,
            shutdown,
            task,
        }
    }

    async fn stop(self) {
        self.shutdown.request();
        self.task.await.unwrap();
        std::fs::remove_dir(self.directory).unwrap();
    }
}

fn support_directory_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

struct DiscardingOutputs;
impl asc_action_runtime::SecurityEventSink for DiscardingOutputs {
    fn write(&self, _: &SecurityEvent) {}
}
impl asc_action_runtime::TelemetrySink for DiscardingOutputs {
    fn enabled(&self) -> bool {
        false
    }
    fn write(&self, _: &asc_telemetry::TelemetryRecord) -> asc_action_runtime::TelemetryStatus {
        asc_action_runtime::TelemetryStatus::Skipped
    }
}
impl asc_action_runtime::DiagnosticSink for DiscardingOutputs {
    fn record(&self, _: &asc_action_runtime::Diagnostic) {}
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
/// The caller's own rows live under session "s-own" (runs "r-1" with a
/// before_agent_run and a tool-call row, and "r-2"); the foreign owner seeds
/// the same session, run and tool-call spellings so any leak of the owner
/// predicate is visible in every list shape.
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
            for (hook, epoch, session, run, owner, metrics, tool_call_id) in [
                (
                    "before_agent_run",
                    BASE_EPOCH + 100.0,
                    "s-own",
                    "r-1",
                    own_uid,
                    r#"{"user_input":"list files"}"#,
                    None,
                ),
                (
                    "before_tool_call",
                    BASE_EPOCH + 105.0,
                    "s-own",
                    "r-1",
                    own_uid,
                    r#"{"parameters":{"command":"ls -la /tmp"}}"#,
                    Some("tc-1"),
                ),
                (
                    "before_agent_run",
                    BASE_EPOCH + 200.0,
                    "s-own",
                    "r-2",
                    own_uid,
                    r#"{"user_input":"second"}"#,
                    None,
                ),
                (
                    "before_agent_run",
                    BASE_EPOCH + 150.0,
                    "s-own",
                    "r-1",
                    FOREIGN_UID,
                    r#"{"user_input":"foreign"}"#,
                    Some("tc-1"),
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

/// Renders one seeded epoch as the matching v1 wire timestamp.
fn epoch_iso(epoch: f64) -> String {
    let seconds = epoch.floor() as i64 % 86_400;
    let (hour, minute, second) = (seconds / 3_600, (seconds % 3_600) / 60, seconds % 60);
    format!("2026-01-01T{hour:02}:{minute:02}:{second:02}Z")
}

/// Seeds the security-event store: the caller's own code_scan on the r-1 tool
/// call, and a foreign code_scan under the same session, run and tool-call
/// spellings.
fn seed_security(path: &Path, own_uid: u32) {
    let writer = SqliteEventWriter::new(path).expect("writer");
    for uid in [own_uid, FOREIGN_UID] {
        let mut event = SecurityEvent::new("sandbox_prehook", "code_scan", Map::new());
        event.uid = uid;
        event.session_id = Some("s-own".to_owned());
        event.run_id = Some("r-1".to_owned());
        event.tool_call_id = Some("tc-1".to_owned());
        event.timestamp = "2026-01-01T00:01:44+00:00".to_owned();
        event
            .details
            .insert("request".to_owned(), json!({"code": "ls -la /tmp"}));
        writer.write(&event);
    }
    writer.close_at(1000.0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_peer_reads_only_its_own_observability_through_the_socket() {
    let directory = tempfile::tempdir().expect("temp dir");
    let observability = directory.path().join("observability.db");
    let security = directory.path().join("security-events.db");
    let own_uid = rustix::process::getuid().as_raw();
    seed_observability(&observability, own_uid);
    seed_security(&security, own_uid);
    let daemon = RunningDaemon::start(PrincipalRole::LocalUser, &observability, &security).await;

    // Sessions: only the caller's, with only the caller's security counts.
    let listed = request_json(
        &daemon.socket_path,
        &json!({"method": "obs.sessions.list", "params": {}}),
    )
    .await;
    let items = listed["result"]["items"].as_array().expect("items array");
    assert_eq!(items.len(), 1, "only the caller's session: {listed}");
    assert_eq!(items[0]["session_id"], json!("s-own"));
    assert_eq!(items[0]["observability_event_count"], json!(3));
    assert_eq!(items[0]["turn_count"], json!(2));
    assert_eq!(
        items[0]["security_event_count"],
        json!(1),
        "the foreign security event must not leak into the counts"
    );
    assert_eq!(listed["result"]["total"], json!(1));

    // Runs of the shared session spelling: only the caller's.
    let runs = request_json(
        &daemon.socket_path,
        &json!({"method": "obs.runs.list", "params": {"session_id": "s-own"}}),
    )
    .await;
    let run_items = runs["result"]["items"].as_array().expect("items array");
    assert_eq!(
        run_items.len(),
        2,
        "r-1 and r-2, foreign r-1 excluded: {runs}"
    );
    assert_eq!(run_items[0]["run_id"], json!("r-1"));
    assert_eq!(run_items[0]["user_input_preview"], json!("list files"));
    assert_eq!(run_items[0]["security_event_count"], json!(1));

    // The timeline correlates only the caller's security event, even though
    // the foreign owner seeded the same session, run and tool-call ids.
    let timeline = request_json(
        &daemon.socket_path,
        &json!({"method": "obs.timeline.get", "params": {"session_id": "s-own", "run_id": "r-1"}}),
    )
    .await;
    let timeline_items = timeline["result"]["items"].as_array().expect("items");
    let security_items: Vec<&serde_json::Value> = timeline_items
        .iter()
        .filter(|item| item["kind"] == json!("security"))
        .collect();
    assert_eq!(
        security_items.len(),
        1,
        "exactly one own correlated event: {timeline}"
    );
    assert_eq!(security_items[0]["event"]["category"], json!("code_scan"));
    assert_eq!(security_items[0]["match"]["reason"], json!("tool_call_id"));
    assert_eq!(
        timeline_items[0]["kind"],
        json!("observability"),
        "the record precedes the event it produced"
    );

    // include_security=false keeps the records and drops the events.
    let without = request_json(
        &daemon.socket_path,
        &json!({"method": "obs.timeline.get", "params": {
            "session_id": "s-own", "run_id": "r-1", "include_security": false
        }}),
    )
    .await;
    assert!(
        without["result"]["items"]
            .as_array()
            .expect("items")
            .iter()
            .all(|item| item["kind"] == json!("observability"))
    );

    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_administrator_reads_only_its_own_observability_too() {
    let directory = tempfile::tempdir().expect("temp dir");
    let observability = directory.path().join("observability.db");
    let security = directory.path().join("security-events.db");
    let own_uid = rustix::process::getuid().as_raw();
    seed_observability(&observability, own_uid);
    seed_security(&security, own_uid);
    // The administrator role is a policy role, not a cross-owner audit role:
    // the v2 daemon assigns none yet, so even an administrator reads only the
    // rows its own peer credentials own (issue #6608).
    let daemon = RunningDaemon::start(
        PrincipalRole::PolicyAdministrator,
        &observability,
        &security,
    )
    .await;

    let listed = request_json(
        &daemon.socket_path,
        &json!({"method": "obs.sessions.list", "params": {}}),
    )
    .await;
    let items = listed["result"]["items"].as_array().expect("items array");
    assert_eq!(items.len(), 1, "administrator sees only its own rows");
    assert_eq!(items[0]["security_event_count"], json!(1));

    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_observability_store_answers_empty_not_unavailable() {
    // Before the first state migration the system observability database
    // does not exist; the daemon must answer empty timelines rather than
    // erroring, because "no rows yet" is the correct result.
    let directory = tempfile::tempdir().expect("temp dir");
    let observability = directory.path().join("observability.db");
    let security = directory.path().join("security-events.db");
    let daemon = RunningDaemon::start(PrincipalRole::LocalUser, &observability, &security).await;

    let listed = request_json(
        &daemon.socket_path,
        &json!({"method": "obs.sessions.list", "params": {}}),
    )
    .await;
    assert_eq!(
        listed["result"]["items"].as_array().expect("items").len(),
        0
    );
    assert_eq!(listed["result"]["total"], json!(0));

    let timeline = request_json(
        &daemon.socket_path,
        &json!({"method": "obs.timeline.get", "params": {"session_id": "s", "run_id": "r"}}),
    )
    .await;
    assert_eq!(
        timeline["result"]["items"].as_array().expect("items").len(),
        0
    );

    // The reader never created the database on the way.
    let reader = SystemObservabilityReader::new(&observability).expect("reader");
    assert!(!reader.path().exists());

    daemon.stop().await;
}
