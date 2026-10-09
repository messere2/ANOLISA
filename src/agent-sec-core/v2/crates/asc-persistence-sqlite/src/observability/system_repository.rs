//! Owner-scoped reads for the v2 system observability store.
//!
//! The v1-parity [`super::repository`] serves the per-user stream's wire
//! contract, whose table has no owner column. The **system** store is a
//! different database: many owners' history centralized behind the daemon, so
//! every read here requires a [`QueryScope`] and puts the owner predicate
//! first, exactly like the security-event repository (issue #6608). These
//! queries are only valid over [`super::table::SYSTEM_OBSERVABILITY_TABLES`]:
//! the `owner` column is the system store's convergent addition and does not
//! exist in a v1-shaped file.

use asc_observability::{RunSummary, SessionSummary};
use asc_sqlite_kernel::{KernelError, RecordRepository, TableSpec};
use rusqlite::Connection;
use rusqlite::types::Value as SqlValue;

use super::repository::{EpochWindow, ObservabilityEventRow, Page, SELECT_COLUMNS};
use super::table::SYSTEM_OBSERVABILITY_TABLES;
use crate::scope::QueryScope;

/// Owner-scoped reads of the system `observability_events` table.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemObservabilityRepository;

impl RecordRepository for SystemObservabilityRepository {
    type Record = asc_observability::ObservabilityRecord;

    fn tables(&self) -> &'static [TableSpec] {
        SYSTEM_OBSERVABILITY_TABLES
    }

    fn insert_or_raise(
        &self,
        _conn: &Connection,
        _record: &Self::Record,
    ) -> Result<bool, KernelError> {
        // The system store is written by the state migrator, which stamps the
        // verified owner itself; this repository is the read path only.
        Err(KernelError::Malformed(
            "the system observability store is read-only through this repository".to_owned(),
        ))
    }

    fn prune(
        &self,
        _conn: &Connection,
        _max_age_days: u32,
        _now: f64,
    ) -> Result<usize, KernelError> {
        Err(KernelError::Malformed(
            "the system observability store is read-only through this repository".to_owned(),
        ))
    }
}

impl SystemObservabilityRepository {
    /// Appends the scope predicate — always the first clause — plus the
    /// window's clauses, and returns them with their bound parameters.
    fn scoped_clauses(scope: QueryScope, window: EpochWindow) -> (Vec<String>, Vec<SqlValue>) {
        let mut clauses = Vec::new();
        let mut params = Vec::new();
        params.push(SqlValue::Integer(i64::from(scope.owner_uid())));
        clauses.push(format!("owner = ?{}", params.len()));
        window.apply(&mut clauses, &mut params);
        (clauses, params)
    }

    /// Returns the number of distinct sessions of one owner scope in `window`.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::Sqlite`] when the query cannot run.
    pub fn count_sessions(
        &self,
        conn: &Connection,
        window: EpochWindow,
        scope: QueryScope,
    ) -> Result<u64, KernelError> {
        let (clauses, params) = Self::scoped_clauses(scope, window);
        let sql = format!(
            "SELECT COUNT(DISTINCT session_id) FROM observability_events{}",
            where_clause(&clauses)
        );
        let count: i64 =
            conn.query_row(&sql, rusqlite::params_from_iter(params.iter()), |row| {
                row.get(0)
            })?;
        Ok(count.try_into().unwrap_or_default())
    }

    /// Returns the number of distinct runs of `session_id` in one owner scope.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::Sqlite`] when the query cannot run.
    pub fn count_runs(
        &self,
        conn: &Connection,
        session_id: &str,
        window: EpochWindow,
        scope: QueryScope,
    ) -> Result<u64, KernelError> {
        let (mut clauses, mut params) = Self::scoped_clauses(scope, window);
        params.push(SqlValue::Text(session_id.to_owned()));
        clauses.push(format!("session_id = ?{}", params.len()));
        let sql = format!(
            "SELECT COUNT(DISTINCT run_id) FROM observability_events{}",
            where_clause(&clauses)
        );
        let count: i64 =
            conn.query_row(&sql, rusqlite::params_from_iter(params.iter()), |row| {
                row.get(0)
            })?;
        Ok(count.try_into().unwrap_or_default())
    }

    /// Returns one owner scope's sessions, most recent activity first.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::Sqlite`] when the query cannot run.
    pub fn list_sessions(
        &self,
        conn: &Connection,
        window: EpochWindow,
        page: Page,
        scope: QueryScope,
    ) -> Result<Vec<SessionSummary>, KernelError> {
        let (clauses, params) = Self::scoped_clauses(scope, window);
        let sql = format!(
            "SELECT session_id, MIN(observed_at_epoch) AS first_seen, \
             MAX(observed_at_epoch) AS last_seen, COUNT(DISTINCT run_id) AS turn_count, \
             COUNT(*) AS event_count FROM observability_events{} \
             GROUP BY session_id ORDER BY MAX(observed_at_epoch) DESC{}",
            where_clause(&clauses),
            page.render()
        );

        let mut statement = conn.prepare(&sql)?;
        let mut rows = statement.query(rusqlite::params_from_iter(params.iter()))?;
        let mut sessions = Vec::new();
        while let Some(row) = rows.next()? {
            sessions.push(SessionSummary {
                session_id: row.get(0)?,
                first_seen_epoch: row.get(1)?,
                last_seen_epoch: row.get(2)?,
                turn_count: row.get::<_, i64>(3)?.try_into().unwrap_or_default(),
                event_count: row.get::<_, i64>(4)?.try_into().unwrap_or_default(),
            });
        }
        Ok(sessions)
    }

    /// Returns one owner scope's runs of `session_id`, in chronological order.
    ///
    /// Two statements, constant regardless of run count: one `GROUP BY` for the
    /// stats and one window query for each run's first `before_agent_run`
    /// metrics blob, mirroring the v1-parity repository.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::Sqlite`] when either query cannot run.
    pub fn list_runs(
        &self,
        conn: &Connection,
        session_id: &str,
        window: EpochWindow,
        page: Page,
        scope: QueryScope,
    ) -> Result<Vec<RunSummary>, KernelError> {
        let (mut clauses, mut params) = Self::scoped_clauses(scope, window);
        params.push(SqlValue::Text(session_id.to_owned()));
        clauses.push(format!("session_id = ?{}", params.len()));
        let filter = where_clause(&clauses);

        let stats_sql = format!(
            "SELECT run_id, MIN(observed_at_epoch) AS started_at, \
             MAX(observed_at_epoch) AS ended_at, COUNT(*) AS event_count \
             FROM observability_events{filter} \
             GROUP BY run_id ORDER BY MIN(observed_at_epoch) ASC{}",
            page.render()
        );
        let preview_sql = format!(
            "SELECT run_id, metrics_json FROM (\
             SELECT run_id, metrics_json, ROW_NUMBER() OVER (\
             PARTITION BY run_id ORDER BY observed_at_epoch ASC, id ASC) AS rn \
             FROM observability_events{filter} AND hook = 'before_agent_run') WHERE rn = 1"
        );

        let mut previews: std::collections::HashMap<String, Option<String>> =
            std::collections::HashMap::new();
        {
            let mut statement = conn.prepare(&preview_sql)?;
            let mut rows = statement.query(rusqlite::params_from_iter(params.iter()))?;
            while let Some(row) = rows.next()? {
                previews.insert(row.get(0)?, row.get(1)?);
            }
        }

        let mut statement = conn.prepare(&stats_sql)?;
        let mut rows = statement.query(rusqlite::params_from_iter(params.iter()))?;
        let mut runs = Vec::new();
        while let Some(row) = rows.next()? {
            let run_id: String = row.get(0)?;
            let preview = previews
                .get(&run_id)
                .and_then(|metrics| metrics.as_deref())
                .and_then(super::repository::extract_user_input_preview);
            runs.push(RunSummary {
                run_id,
                started_at_epoch: row.get(1)?,
                ended_at_epoch: row.get(2)?,
                user_input_preview: preview,
                event_count: row.get::<_, i64>(3)?.try_into().unwrap_or_default(),
            });
        }
        Ok(runs)
    }

    /// Returns one owner scope's rows of one run, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::Sqlite`] when the query cannot run.
    pub fn list_events(
        &self,
        conn: &Connection,
        session_id: &str,
        run_id: &str,
        window: EpochWindow,
        page: Page,
        scope: QueryScope,
    ) -> Result<Vec<ObservabilityEventRow>, KernelError> {
        let (mut clauses, mut params) = Self::scoped_clauses(scope, window);
        params.push(SqlValue::Text(session_id.to_owned()));
        clauses.push(format!("session_id = ?{}", params.len()));
        params.push(SqlValue::Text(run_id.to_owned()));
        clauses.push(format!("run_id = ?{}", params.len()));
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM observability_events{} \
             ORDER BY observed_at_epoch ASC{}",
            where_clause(&clauses),
            page.render()
        );

        let mut statement = conn.prepare(&sql)?;
        let mut rows = statement.query(rusqlite::params_from_iter(params.iter()))?;
        let mut events = Vec::new();
        while let Some(row) = rows.next()? {
            events.push(ObservabilityEventRow {
                id: row.get(0)?,
                hook: row.get(1)?,
                observed_at: row.get(2)?,
                observed_at_epoch: row.get(3)?,
                session_id: row.get(4)?,
                run_id: row.get(5)?,
                metrics_json: row.get(6)?,
                metadata_json: row.get(7)?,
                call_id: row.get(8)?,
                tool_call_id: row.get(9)?,
            });
        }
        Ok(events)
    }
}

fn where_clause(clauses: &[String]) -> String {
    if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::table::SYSTEM_OBSERVABILITY_SQLITE_SCHEMA_VERSION;
    use asc_sqlite_kernel::SqliteStore;
    use std::path::Path;
    use tempfile::TempDir;

    const INSERT_SQL: &str = "INSERT INTO observability_events (hook, observed_at, \
         observed_at_epoch, session_id, run_id, metrics_json, metadata_json, call_id, \
         tool_call_id, owner) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";

    /// Seeds the system store with two owners' rows in one session shape.
    ///
    /// Owner A: session "s-a" with runs "r-a1"/"r-a2"; owner B: session "s-b"
    /// with run "r-b1". Every row carries its owner explicitly because the
    /// system store's writes come from the migrator, not from this repository.
    fn seed_two_owners(path: &Path) {
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
                for (hook, epoch, session, run, owner) in [
                    ("before_agent_run", 100.0, "s-a", "r-a1", 1000u32),
                    ("after_agent_run", 110.0, "s-a", "r-a1", 1000),
                    ("before_agent_run", 200.0, "s-a", "r-a2", 1000),
                    ("before_agent_run", 150.0, "s-b", "r-b1", 2000),
                ] {
                    conn.execute(
                        INSERT_SQL,
                        rusqlite::params![
                            hook,
                            format!("2026-01-01T00:00:{epoch:.2}Z"),
                            epoch,
                            session,
                            run,
                            format!("{{\"user_input\":\"u-{epoch}\"}}"),
                            "{}",
                            Option::<String>::None,
                            Option::<String>::None,
                            owner,
                        ],
                    )?;
                }
                Ok(())
            })
            .expect("seed");
    }

    fn connect(path: &Path) -> Connection {
        Connection::open(path).expect("connection")
    }

    #[test]
    fn sessions_and_runs_never_cross_the_owner_boundary() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("observability.db");
        seed_two_owners(&path);
        let conn = connect(&path);
        let repository = SystemObservabilityRepository;

        let owner_a = QueryScope::Owner(1000);
        let owner_b = QueryScope::Owner(2000);

        let sessions_a = repository
            .list_sessions(&conn, EpochWindow::default(), Page::default(), owner_a)
            .expect("sessions");
        assert_eq!(sessions_a.len(), 1, "one session for owner A");
        assert_eq!(sessions_a[0].session_id, "s-a");
        assert_eq!(sessions_a[0].event_count, 3);
        assert_eq!(sessions_a[0].turn_count, 2);

        let sessions_b = repository
            .list_sessions(&conn, EpochWindow::default(), Page::default(), owner_b)
            .expect("sessions");
        assert_eq!(sessions_b.len(), 1);
        assert_eq!(sessions_b[0].session_id, "s-b");

        assert_eq!(
            repository
                .count_sessions(&conn, EpochWindow::default(), owner_a)
                .expect("count"),
            1
        );
        assert_eq!(
            repository
                .count_sessions(&conn, EpochWindow::default(), owner_b)
                .expect("count"),
            1
        );

        // A foreign session id yields nothing: the owner predicate precedes
        // the session predicate.
        let foreign = repository
            .list_runs(
                &conn,
                "s-b",
                EpochWindow::default(),
                Page::default(),
                owner_a,
            )
            .expect("runs");
        assert!(
            foreign.is_empty(),
            "owner A cannot enumerate owner B's runs"
        );

        let runs_a = repository
            .list_runs(
                &conn,
                "s-a",
                EpochWindow::default(),
                Page::default(),
                owner_a,
            )
            .expect("runs");
        assert_eq!(runs_a.len(), 2);
        assert_eq!(runs_a[0].run_id, "r-a1");
        assert_eq!(
            runs_a[0].user_input_preview.as_deref(),
            Some("u-100"),
            "the preview comes from the first before_agent_run metrics blob"
        );

        let events = repository
            .list_events(
                &conn,
                "s-a",
                "r-a1",
                EpochWindow::default(),
                Page::default(),
                owner_a,
            )
            .expect("events");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].hook, "before_agent_run");
    }

    #[test]
    fn windows_and_pages_apply_after_the_owner_predicate() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("observability.db");
        seed_two_owners(&path);
        let conn = connect(&path);
        let repository = SystemObservabilityRepository;
        let owner_a = QueryScope::Owner(1000);

        let late_only = EpochWindow {
            start_epoch: Some(150.0),
            end_epoch: None,
        };
        let sessions = repository
            .list_sessions(&conn, late_only, Page::default(), owner_a)
            .expect("sessions");
        assert_eq!(sessions.len(), 1, "only r-a2's session survives the window");
        assert!(
            (sessions[0].last_seen_epoch - 200.0).abs() < f64::EPSILON,
            "the late window keeps only the 200.0 row"
        );

        let paged = repository
            .list_runs(
                &conn,
                "s-a",
                EpochWindow::default(),
                Page {
                    limit: Some(1),
                    offset: 0,
                },
                owner_a,
            )
            .expect("runs");
        assert_eq!(paged.len(), 1, "the page caps the owner's own rows only");
    }

    #[test]
    fn the_read_repository_refuses_to_write() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("observability.db");
        seed_two_owners(&path);
        let conn = connect(&path);
        let repository = SystemObservabilityRepository;
        assert!(repository.insert_or_raise(&conn, &record()).is_err());
        assert!(repository.prune(&conn, 7, 0.0).is_err());
    }

    fn record() -> asc_observability::ObservabilityRecord {
        use asc_observability::{ObservabilityHook, ObservabilityMetadata};
        let observed_at = chrono::TimeZone::with_ymd_and_hms(
            &chrono::FixedOffset::east_opt(0).expect("utc"),
            2026,
            1,
            1,
            0,
            0,
            0,
        )
        .single()
        .expect("timestamp");
        let mut metrics = serde_json::Map::new();
        metrics.insert("user_input".to_owned(), serde_json::json!("x"));
        asc_observability::ObservabilityRecord::new(
            ObservabilityHook::BeforeAgentRun,
            observed_at,
            ObservabilityMetadata::new("s", "r"),
            metrics,
        )
        .expect("record")
    }
}
