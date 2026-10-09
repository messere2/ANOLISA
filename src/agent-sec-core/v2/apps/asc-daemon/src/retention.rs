//! Periodic security-event `SQLite` retention for the long-lived daemon.
//!
//! v1 ran retention when short-lived CLI processes exited through `atexit`,
//! and the daemon only ran the gated pass in `event_sinks.close()` after its
//! main loop returned - a daemon that keeps running never pruned, and a hard
//! kill skipped the shutdown pass entirely, so expired events survived until
//! some orderly exit. The retention task gives the daemon its own lifecycle:
//!
//! - the startup catch-up ([`run_startup_catchup`]) runs one gated pass
//!   **before UDS admission begins**, so the potentially large first prune
//!   over a historical backlog never overlaps request audit writes;
//! - after admission, the task re-checks the shared cross-process gate once
//!   per [`RetentionSchedule::check_interval`]; the gate still decides whether
//!   anything actually runs;
//! - failures and contention surface through the daemon's diagnostics and
//!   retry after [`RetentionSchedule::failure_retry`] instead of waiting for
//!   the next daily window;
//! - shutdown is cooperative: [`RetentionTask::shutdown`] stops scheduling,
//!   then joins the task - and through it any in-flight `spawn_blocking`
//!   pass - so the bounded final pass in `event_sinks.close()` runs only
//!   after the task has terminated and can never contend with residual
//!   maintenance on the same `SqliteStore` mutex.
//!
//! The service contract (trigger, readiness, health, logging, retry,
//! cancellation, shutdown, and fixtures) is
//! `src/agent-sec-core/docs/design/DAEMON_JOB_CONTRACT_zh.md` section 11.5.

use std::sync::Arc;
use std::time::Duration;

use asc_event_sink::MaintenanceOutcome;
use tokio::sync::watch;

/// How often a running daemon re-checks the security-event `SQLite`
/// retention gate. The gate itself stays the shared daily window; this is
/// only the cadence at which a long-lived daemon looks at it.
pub const RETENTION_CHECK_INTERVAL_SECONDS: u64 = 3600;

/// How quickly a failed or contended retention pass is retried. The gate does
/// not advance over a failure, so the retry is bounded only by this backoff.
pub const RETENTION_FAILURE_RETRY_SECONDS: u64 = 60;

/// Terminal-join budget for the retention task at shutdown, mirroring the
/// skill-worker drain budget in the composition root.
pub const RETENTION_JOIN_TIMEOUT: Duration = Duration::from_secs(65);

/// One blocking maintenance attempt against the security-events store.
///
/// The production pass is `ConfiguredSecurityEventSinks::run_sqlite_retention`;
/// the seam keeps the lifecycle fixtures in `tests/retention_lifecycle.rs`
/// production-shaped without a live database.
pub type RetentionPass = Arc<dyn Fn(f64) -> MaintenanceOutcome + Send + Sync>;

/// Where lifecycle diagnostics go (the daemon's telemetry reporter).
pub type RetentionReport = Arc<dyn Fn(&str) + Send + Sync>;

/// The retention task's timing knobs.
#[derive(Debug, Clone, Copy)]
pub struct RetentionSchedule {
    /// Cadence between gate checks once the daemon is serving.
    pub check_interval: Duration,
    /// Backoff after a failed or contended pass before the next attempt.
    pub failure_retry: Duration,
}

impl Default for RetentionSchedule {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(RETENTION_CHECK_INTERVAL_SECONDS),
            failure_retry: Duration::from_secs(RETENTION_FAILURE_RETRY_SECONDS),
        }
    }
}

impl RetentionSchedule {
    /// Builds an explicit schedule.
    #[must_use]
    pub const fn new(check_interval: Duration, failure_retry: Duration) -> Self {
        Self {
            check_interval,
            failure_retry,
        }
    }
}

/// The handle owning the retention task's lifecycle.
///
/// Dropping the handle cancels the task; [`RetentionTask::shutdown`] cancels
/// and joins it. The task is never aborted: an in-flight `spawn_blocking`
/// pass cannot be cancelled (see `runtime.rs`), so ownership is expressed
/// through the cooperative cancel signal plus a terminal join.
pub struct RetentionTask {
    join: tokio::task::JoinHandle<()>,
    cancel: watch::Sender<bool>,
}

impl RetentionTask {
    /// Starts the periodic task.
    ///
    /// `first_check` is the delay before the first gate check: the composition
    /// root passes [`RetentionSchedule::failure_retry`] when the startup
    /// catch-up failed or was contended, and
    /// [`RetentionSchedule::check_interval`] otherwise.
    #[must_use]
    pub fn spawn(
        pass: RetentionPass,
        schedule: RetentionSchedule,
        report: RetentionReport,
        first_check: Duration,
    ) -> Self {
        let (cancel, cancelled) = watch::channel(false);
        let join = tokio::spawn(async move {
            run_periodic(pass, schedule, report, first_check, cancelled).await;
        });
        Self { join, cancel }
    }

    /// Requests cancellation without waiting.
    ///
    /// The task stops scheduling new passes; an in-flight `spawn_blocking`
    /// pass still runs to completion, because a blocking closure cannot be
    /// cancelled.
    pub fn cancel(&self) {
        let _ = self.cancel.send(true);
    }

    /// Returns whether the task has terminated.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.join.is_finished()
    }

    /// Cancels and joins the task within `timeout`.
    ///
    /// Returns `true` when the task terminated. Because the task always
    /// awaits its in-flight `spawn_blocking` pass before returning, a `true`
    /// result also means that pass finished - the shutdown final pass can
    /// then run without ever sharing the store mutex with residual
    /// maintenance.
    ///
    /// Returns `false` when the join times out (a pathological pass stuck on
    /// the filesystem); the caller must then skip the final pass rather than
    /// contend with the orphaned work.
    ///
    /// # Panics
    ///
    /// Never panics: a top-level task panic also counts as terminated.
    pub async fn shutdown_within(self, timeout: Duration) -> bool {
        self.cancel();
        matches!(tokio::time::timeout(timeout, self.join).await, Ok(_))
    }

    /// Cancels and joins the task within [`RETENTION_JOIN_TIMEOUT`].
    pub async fn shutdown(self) -> bool {
        self.shutdown_within(RETENTION_JOIN_TIMEOUT).await
    }
}

/// Starts the retention lifecycle: the startup catch-up, then the periodic
/// task.
///
/// The composition root awaits this before admitting requests. The task's
/// first gate check is scheduled after [`RetentionSchedule::failure_retry`]
/// when the catch-up did not complete, and after
/// [`RetentionSchedule::check_interval`] otherwise.
#[must_use]
pub async fn start(
    pass: RetentionPass,
    schedule: RetentionSchedule,
    report: RetentionReport,
) -> RetentionTask {
    let first_check = match run_startup_catchup(&pass, &report).await {
        MaintenanceOutcome::Failed(_) | MaintenanceOutcome::Contended => schedule.failure_retry,
        MaintenanceOutcome::Ran | MaintenanceOutcome::NotDue => schedule.check_interval,
    };
    RetentionTask::spawn(pass, schedule, report, first_check)
}

/// Runs one gated pass before UDS admission begins.
///
/// The first pass after a hard kill can prune a large historical backlog, and
/// the daemon's request audit writes share the store's connection mutex, so
/// the composition root awaits this before calling `serve`. A failed,
/// contended, or panicked catch-up does not block admission: the periodic
/// task retries it after [`RetentionSchedule::failure_retry`].
pub async fn run_startup_catchup(
    pass: &RetentionPass,
    report: &RetentionReport,
) -> MaintenanceOutcome {
    let pass = Arc::clone(pass);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |delta| delta.as_secs_f64());
    match tokio::task::spawn_blocking(move || pass(now)).await {
        Ok(MaintenanceOutcome::Failed(error)) => {
            report(&format!(
                "agent-sec-daemon: security event sqlite retention catch-up failed, retrying: {error}"
            ));
            MaintenanceOutcome::Failed(error)
        }
        Ok(MaintenanceOutcome::Contended) => {
            report(
                "agent-sec-daemon: security event sqlite retention catch-up found the gate lock held, retrying",
            );
            MaintenanceOutcome::Contended
        }
        Ok(MaintenanceOutcome::Ran) => {
            report("agent-sec-daemon: security event sqlite retention catch-up pass completed");
            MaintenanceOutcome::Ran
        }
        Ok(MaintenanceOutcome::NotDue) => MaintenanceOutcome::NotDue,
        Err(problem) => {
            report(&format!(
                "agent-sec-daemon: security event sqlite retention catch-up panicked: {problem}"
            ));
            MaintenanceOutcome::Failed(format!("startup catch-up panicked: {problem}"))
        }
    }
}

async fn run_periodic(
    pass: RetentionPass,
    schedule: RetentionSchedule,
    report: RetentionReport,
    first_check: Duration,
    mut cancelled: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval_at(
        tokio::time::Instant::now() + first_check,
        schedule.check_interval,
    );
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = cancelled.changed() => break,
        }
        loop {
            let attempt = {
                let pass = Arc::clone(&pass);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0.0, |delta| delta.as_secs_f64());
                tokio::task::spawn_blocking(move || pass(now)).await
            };
            match attempt {
                Ok(MaintenanceOutcome::Failed(error)) => {
                    report(&format!(
                        "agent-sec-daemon: security event sqlite retention failed, retrying: {error}"
                    ));
                    if sleep_or_cancel(&mut cancelled, schedule.failure_retry).await {
                        return;
                    }
                }
                Ok(MaintenanceOutcome::Contended) => {
                    report(
                        "agent-sec-daemon: security event sqlite retention lock is held by another process, retrying",
                    );
                    if sleep_or_cancel(&mut cancelled, schedule.failure_retry).await {
                        return;
                    }
                }
                Ok(MaintenanceOutcome::Ran) => {
                    report("agent-sec-daemon: security event sqlite retention pass completed");
                    break;
                }
                Ok(MaintenanceOutcome::NotDue) => break,
                Err(problem) => {
                    report(&format!(
                        "agent-sec-daemon: security event sqlite retention task panicked: {problem}"
                    ));
                    // A panic is a bug, not a retryable failure: the next
                    // attempt waits for the regular cadence instead of
                    // hammering a broken pass every backoff.
                    break;
                }
            }
        }
    }
}

/// Sleeps for `delay`, returning `true` when cancellation won the race.
async fn sleep_or_cancel(cancelled: &mut watch::Receiver<bool>, delay: Duration) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(delay) => false,
        _ = cancelled.changed() => true,
    }
}
