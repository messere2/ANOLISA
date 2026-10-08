//! Scheduled `SQLite` retention for the long-running daemon.
//!
//! The gated maintenance pass used to run only from the graceful-exit path
//! (`event_sinks.close()` after the main loop returns), so a daemon that stayed
//! up never pruned and a `SIGKILL` never caught up. This module keeps the same
//! daily gate but drives it from the daemon's own lifecycle: one run-if-due pass
//! at startup, then a periodic tick that re-checks the gate. A failed pass is
//! reported through process diagnostics and leaves the gate open, so the next
//! tick retries instead of waiting out the interval.

use std::sync::Arc;
use std::time::Duration;

use asc_event_sink::ConfiguredSecurityEventSinks;

/// How often the daemon re-checks the daily retention gate.
///
/// The gate itself only opens once per day; the tick bounds how long a missed
/// or failed pass can stay unobserved and doubles as the retry backoff.
const RETENTION_TICK: Duration = Duration::from_secs(60 * 60);

/// Spawns the retention service: an immediate catch-up pass, then a tick.
///
/// The returned handle is aborted when the serve loop returns; the bounded
/// final pass still happens through `event_sinks.close()` in `main`.
pub fn spawn_retention_service(
    sinks: Arc<ConfiguredSecurityEventSinks>,
    report: impl Fn(&str) + Send + Sync + 'static,
) -> tokio::task::JoinHandle<()> {
    spawn_retention_service_with_tick(sinks, report, RETENTION_TICK)
}

/// [`spawn_retention_service`] with an injectable tick, for tests.
fn spawn_retention_service_with_tick(
    sinks: Arc<ConfiguredSecurityEventSinks>,
    report: impl Fn(&str) + Send + Sync + 'static,
    tick: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Startup catch-up: a pass missed by a previous unclean exit runs now.
        run_one_pass(&sinks, &report).await;
        loop {
            tokio::time::sleep(tick).await;
            run_one_pass(&sinks, &report).await;
        }
    })
}

/// Runs one gated pass on the blocking pool.
///
/// Synchronous `SQLite` must not run on the runtime's workers (the deployment
/// contract keeps it off the accept loop), so each pass goes through
/// `spawn_blocking` and only the outcome is handled here.
async fn run_one_pass(sinks: &Arc<ConfiguredSecurityEventSinks>, report: &impl Fn(&str)) {
    let sinks = Arc::clone(sinks);
    let pass = tokio::task::spawn_blocking(move || sinks.maintain()).await;
    match pass {
        // Both a completed pass and a closed gate are silent, as in v1: this is
        // opportunistic housekeeping.
        Ok(Ok(_)) => {}
        Ok(Err(problem)) => report(&format!(
            "asc-daemon: security-event retention failed; the gate stays open and the next tick retries: {problem}"
        )),
        Err(problem) => report(&format!(
            "asc-daemon: security-event retention task failed to finish: {problem}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use asc_event_sink::ConfiguredSecurityEventSinks;
    use asc_security_events::SecurityEvent;
    use serde_json::Map;

    use super::*;

    fn security_sinks(dir: &tempfile::TempDir) -> Arc<ConfiguredSecurityEventSinks> {
        let sinks = ConfiguredSecurityEventSinks::new(
            dir.path().join("events.jsonl"),
            dir.path().join("events.db"),
        );
        sinks.warm_sqlite().expect("warm sqlite");
        Arc::new(sinks)
    }

    fn event() -> SecurityEvent {
        SecurityEvent::new("code_scan", "code_scan", Map::new())
    }

    fn recorder() -> (
        Arc<Mutex<Vec<String>>>,
        impl Fn(&str) + Send + Sync + 'static,
    ) {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&messages);
        (messages, move |message: &str| {
            sink.lock().expect("lock").push(message.to_owned())
        })
    }

    #[tokio::test]
    async fn a_failed_pass_is_reported_and_keeps_the_gate_open() {
        let dir = tempfile::tempdir().expect("temp dir");
        let sinks = security_sinks(&dir);
        sinks.log_event(&event());

        // Removing the table from a second connection is the cheapest way to
        // make the retention pass fail for real.
        let conn = rusqlite::Connection::open(dir.path().join("events.db")).expect("open");
        conn.execute("DROP TABLE security_events", [])
            .expect("drop table");
        drop(conn);

        let (messages, report) = recorder();
        run_one_pass(&sinks, &report).await;

        let messages = messages.lock().expect("lock");
        assert_eq!(messages.len(), 1, "the failure must reach diagnostics");
        assert!(messages[0].contains("retention failed"));
        drop(messages);
        assert!(
            !dir.path().join("events.db.maintenance").exists(),
            "the gate must stay open for the next tick"
        );
    }

    #[tokio::test]
    async fn the_service_catches_up_at_startup_and_keeps_ticking() {
        let dir = tempfile::tempdir().expect("temp dir");
        let sinks = security_sinks(&dir);
        sinks.log_event(&event());
        let marker = dir.path().join("events.db.maintenance");

        let (_messages, report) = recorder();
        let service = spawn_retention_service_with_tick(sinks, report, Duration::from_millis(100));

        // The startup catch-up pass marks the gate promptly...
        let caught_up = tokio::time::timeout(Duration::from_secs(5), async {
            while !marker.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok();
        assert!(caught_up, "the startup pass must run");

        // ...and the tick re-checks the gate: clearing the marker makes the
        // next tick run another pass and restore it.
        std::fs::remove_file(&marker).expect("clear marker");
        let ticked = tokio::time::timeout(Duration::from_secs(5), async {
            while !marker.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok();
        assert!(ticked, "the periodic tick must re-check the gate");

        service.abort();
    }
}
