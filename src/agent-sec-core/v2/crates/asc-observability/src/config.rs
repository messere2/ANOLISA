//! Stream configuration for observability persistence.
//!
//! Migrated from v1 `observability/config.py`, which reuses the
//! security-events data-directory resolution rather than defining its own.

use std::path::{Path, PathBuf};

use asc_security_events::ConfigError;
use asc_security_events::config::{
    get_stream_db_path, get_stream_log_path, stream_db_path_in, stream_log_path_in,
};

/// Stream name for observability records.
pub const OBSERVABILITY_STREAM: &str = "observability";

/// Prefix used on observability diagnostic lines.
pub const OBSERVABILITY_LOG_PREFIX: &str = "[observability]";

/// Retention window applied by the observability `SQLite` writer, in days.
pub const DEFAULT_OBSERVABILITY_RETENTION_DAYS: u32 = 7;

/// Returns the `JSONL` path for the observability stream.
///
/// # Errors
///
/// Propagates the data-directory resolution failure from the security-events
/// config layer.
pub fn get_observability_log_path() -> Result<PathBuf, ConfigError> {
    get_stream_log_path(OBSERVABILITY_STREAM)
}

/// Returns the `SQLite` path for the observability stream.
///
/// # Errors
///
/// Propagates the data-directory resolution failure from the security-events
/// config layer.
pub fn get_observability_db_path() -> Result<PathBuf, ConfigError> {
    get_stream_db_path(OBSERVABILITY_STREAM)
}

/// Returns the observability `JSONL` path under an explicit data directory.
///
/// Tests use this form so they never have to mutate process environment.
///
/// # Errors
///
/// Returns an error only if the stream name fails validation, which cannot
/// happen for the built-in stream.
pub fn observability_log_path_in(data_dir: &Path) -> Result<PathBuf, ConfigError> {
    stream_log_path_in(data_dir, OBSERVABILITY_STREAM)
}

/// Returns the observability `SQLite` path under an explicit data directory.
///
/// # Errors
///
/// Returns an error only if the stream name fails validation, which cannot
/// happen for the built-in stream.
pub fn observability_db_path_in(data_dir: &Path) -> Result<PathBuf, ConfigError> {
    stream_db_path_in(data_dir, OBSERVABILITY_STREAM)
}

/// Returns the observability database that shares a security-events database's
/// directory.
///
/// Both streams live in the same data directory, so callers that already hold
/// the security-events database path — the daemon's composition root, the
/// state migrator — derive the observability sibling from it instead of
/// resolving the data directory twice. The rule is the one
/// [`observability_db_path_in`] applies inside one data directory:
/// `observability.db` beside the named file.
#[must_use]
pub fn observability_db_beside(security_db: &Path) -> PathBuf {
    security_db
        .parent()
        .unwrap_or(security_db)
        .join("observability.db")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_v1() {
        assert_eq!(OBSERVABILITY_STREAM, "observability");
        assert_eq!(OBSERVABILITY_LOG_PREFIX, "[observability]");
        assert_eq!(DEFAULT_OBSERVABILITY_RETENTION_DAYS, 7);
    }

    #[test]
    fn injected_paths_use_the_observability_stream() {
        let dir = Path::new("/tmp/asc-test-data");
        assert_eq!(
            observability_log_path_in(dir).expect("valid stream"),
            dir.join("observability.jsonl")
        );
        assert_eq!(
            observability_db_path_in(dir).expect("valid stream"),
            dir.join("observability.db")
        );
    }

    #[test]
    fn the_sibling_rule_matches_the_data_directory_rule() {
        let data_dir = Path::new("/var/lib/agent-sec");
        let security_db = data_dir.join("security-events.db");
        assert_eq!(
            observability_db_beside(&security_db),
            observability_db_path_in(data_dir).expect("valid stream"),
            "beside(security db) and in(data dir) must name the same file"
        );
    }

    #[test]
    fn a_parentless_security_db_still_yields_a_sibling() {
        assert_eq!(
            observability_db_beside(Path::new("security-events.db")),
            Path::new("observability.db")
        );
    }
}
