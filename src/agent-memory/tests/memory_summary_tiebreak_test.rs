//! The summary's concept and file rankings must be a function of the
//! memory set, not of HashMap iteration order (which is randomized per
//! process): a 12-way tie used to yield an arbitrary top-10 membership
//! and order, and which of the tied entries made the cut changed on
//! every run.

use tempfile::tempdir;

use agent_memory::config::{AppConfig, Profile};
use agent_memory::mount::MountStrategyKind;
use agent_memory::service::MemoryService;
use agent_memory::tools::memory_summary_tool::memory_summary;

fn setup() -> (tempfile::TempDir, MemoryService) {
    let tmp = tempdir().unwrap();
    let mut cfg = AppConfig::default();
    cfg.global.user_id = "tester".into();
    cfg.memory.profile = Profile::Advanced;
    cfg.memory.paths.base_dir = tmp.path().to_string_lossy().into();
    cfg.memory.mount.strategy = MountStrategyKind::Userland;
    let svc = MemoryService::new(cfg).unwrap();
    (tmp, svc)
}

fn write_memory(svc: &MemoryService, name: &str, concepts: &str, files: &str) {
    let body = format!(
        "---\ntitle: {name}\ncategory: lesson\nsource: manual-observe\nconcepts: {concepts}\nfiles: {files}\n---\n\nbody of {name}.\n"
    );
    svc.write(name, &body, false).unwrap();
}

#[test]
fn tied_concepts_and_files_rank_by_name() {
    let (_t, svc) = setup();
    // Twelve concepts and twelve file references, one occurrence each:
    // every ranking slot is tied, so only a name tiebreak yields a stable
    // top-10 membership and order.
    for i in 1..=12 {
        write_memory(
            &svc,
            &format!("mem{i:02}.md"),
            &format!("[c{i:02}]"),
            &format!("[\"f{i:02}.rs\"]"),
        );
    }
    let summary = memory_summary(&svc, 5).unwrap();
    assert_eq!(summary.total_memories, 12);
    let got: Vec<&str> = summary
        .top_concepts
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(
        got,
        vec![
            "c01", "c02", "c03", "c04", "c05", "c06", "c07", "c08", "c09", "c10"
        ],
        "tied concepts must be ranked by name, dropping the tail deterministically"
    );
    let got_files: Vec<&str> = summary
        .top_files
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(
        got_files,
        vec![
            "f01.rs", "f02.rs", "f03.rs", "f04.rs", "f05.rs", "f06.rs", "f07.rs", "f08.rs",
            "f09.rs", "f10.rs"
        ],
        "tied file references must be ranked by name"
    );
}
