//! Read-only, owner-scoped access to the v2 system observability store.
//!
//! The v1-parity [`super::reader::ObservabilityReader`] serves the per-user
//! stream's wire contract. This facade serves the **system** store the state
//! migrator fills (#6605): the v1 shape plus the converged `owner` column, so
//! every read carries a [`QueryScope`] whose predicate is the first `WHERE`
//! clause (issue #6608).
//!
//! The store is opened read-only and is never created or migrated here. A
//! missing database — normal before the first migration — degrades to empty
//! results, and a v1-shaped file at the system path degrades the same way:
//! without the `owner` column there is no owner-safe answer to give, and
//! failing closed is the only correct one.

use std::path::Path;
use std::sync::Arc;

use asc_observability::{OBSERVABILITY_LOG_PREFIX, RunSummary, SessionSummary};
use asc_sqlite_kernel::{KernelError, ReadOnlySource, SqliteStore};

use super::repository::{EpochWindow, ObservabilityEventRow, Page};
use super::system_repository::SystemObservabilityRepository;
use super::table::{SYSTEM_OBSERVABILITY_SQLITE_SCHEMA_VERSION, SYSTEM_OBSERVABILITY_TABLES};
use crate::scope::QueryScope;

/// Owner-scoped reads of the system observability index.
#[derive(Debug)]
pub struct SystemObservabilityReader {
    source: ReadOnlySource<SystemObservabilityRepository>,
}

impl SystemObservabilityReader {
    /// Opens a reader over `path`.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError`] when the path cannot be normalized.
    pub fn new(path: &Path) -> Result<Self, KernelError> {
        let store = Arc::new(SqliteStore::new(
            path,
            true,
            SYSTEM_OBSERVABILITY_SQLITE_SCHEMA_VERSION,
            SYSTEM_OBSERVABILITY_TABLES,
            None,
            OBSERVABILITY_LOG_PREFIX,
        )?);
        Ok(Self {
            source: ReadOnlySource::new(store, SystemObservabilityRepository),
        })
    }

    /// Returns the database path.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.source.store().path()
    }

    /// Returns the number of distinct sessions of one owner scope in `window`.
    #[must_use]
    pub fn count_sessions(&self, window: EpochWindow, scope: QueryScope) -> u64 {
        self.source
            .query_or(0, |repo, conn| repo.count_sessions(conn, window, scope))
    }

    /// Returns the number of distinct runs of `session_id` in one owner scope.
    #[must_use]
    pub fn count_runs(&self, session_id: &str, window: EpochWindow, scope: QueryScope) -> u64 {
        self.source.query_or(0, |repo, conn| {
            repo.count_runs(conn, session_id, window, scope)
        })
    }

    /// Returns one owner scope's sessions, most recent activity first.
    #[must_use]
    pub fn list_sessions(
        &self,
        window: EpochWindow,
        page: Page,
        scope: QueryScope,
    ) -> Vec<SessionSummary> {
        self.source
            .query_or_default(|repo, conn| repo.list_sessions(conn, window, page, scope))
    }

    /// Returns one owner scope's runs of `session_id`, in chronological order.
    #[must_use]
    pub fn list_runs(
        &self,
        session_id: &str,
        window: EpochWindow,
        page: Page,
        scope: QueryScope,
    ) -> Vec<RunSummary> {
        self.source
            .query_or_default(|repo, conn| repo.list_runs(conn, session_id, window, page, scope))
    }

    /// Returns one owner scope's rows of one run, oldest first.
    #[must_use]
    pub fn list_events(
        &self,
        session_id: &str,
        run_id: &str,
        window: EpochWindow,
        page: Page,
        scope: QueryScope,
    ) -> Vec<ObservabilityEventRow> {
        self.source.query_or_default(|repo, conn| {
            repo.list_events(conn, session_id, run_id, window, page, scope)
        })
    }

    /// Drops the cached read-only connection.
    pub fn close(&self) {
        self.source.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn a_reader_over_a_missing_database_returns_empty_results() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("absent.db");
        let reader = SystemObservabilityReader::new(&path).expect("reader");
        let scope = QueryScope::Owner(1000);

        assert_eq!(reader.count_sessions(EpochWindow::default(), scope), 0);
        assert_eq!(reader.count_runs("s-1", EpochWindow::default(), scope), 0);
        assert!(
            reader
                .list_sessions(EpochWindow::default(), Page::default(), scope)
                .is_empty()
        );
        assert!(
            reader
                .list_runs("s-1", EpochWindow::default(), Page::default(), scope)
                .is_empty()
        );
        assert!(
            reader
                .list_events("s-1", "r-1", EpochWindow::default(), Page::default(), scope)
                .is_empty()
        );
        assert!(
            !path.exists(),
            "a read-only store must never create the database"
        );
    }

    #[test]
    fn a_v1_shaped_file_fails_closed_instead_of_crossing_owners() {
        // A v1-shaped database has no `owner` column. The system reader must
        // answer nothing rather than answer for everyone: the scoped SQL
        // cannot run, and the degraded empty result is the fail-closed answer.
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("observability.db");
        let v1 = rusqlite::Connection::open(&path).expect("connection");
        v1.execute(
            "CREATE TABLE observability_events (id INTEGER NOT NULL PRIMARY KEY, \
             hook TEXT NOT NULL, observed_at TEXT NOT NULL, observed_at_epoch FLOAT NOT NULL, \
             session_id TEXT NOT NULL, run_id TEXT NOT NULL, metrics_json TEXT NOT NULL, \
             metadata_json TEXT NOT NULL, call_id TEXT, tool_call_id TEXT)",
            [],
        )
        .expect("v1 table");
        v1.execute(
            "INSERT INTO observability_events (hook, observed_at, observed_at_epoch, \
             session_id, run_id, metrics_json, metadata_json) \
             VALUES ('before_agent_run', '2026-01-01T00:00:00Z', 1.0, 's', 'r', '{}', '{}')",
            [],
        )
        .expect("v1 row");
        drop(v1);

        let reader = SystemObservabilityReader::new(&path).expect("reader");
        let scope = QueryScope::Owner(1000);
        assert_eq!(reader.count_sessions(EpochWindow::default(), scope), 0);
        assert!(
            reader
                .list_sessions(EpochWindow::default(), Page::default(), scope)
                .is_empty()
        );
    }
}
