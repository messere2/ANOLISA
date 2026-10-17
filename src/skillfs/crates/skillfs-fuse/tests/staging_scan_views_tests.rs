//! Integration tests: scan-loaded staging content stays out of the
//! ordinary skill views.
//!
//! The staging contract (I2) keeps installer staging roots private: they
//! are "hidden from `/skills` readdir/opendir" and "must not participate
//! in ... skill-discover". The store loader enforces no staging rule of
//! its own — it only skips dot-prefixed top-level directories — and the
//! staging validator accepts non-dot patterns (it rejects only sensitive
//! namespaces, `/`, `..` and stray `*`). A staging root pre-seeded on
//! disk (an installer that stages before the mount, or the residue of a
//! crashed install) is therefore classified as a category and its nested
//! skills are scanned into the store under their bare leaf names. The
//! name-level staging filters in the `/skills` listing and the
//! `skill-discover` simple listing then see only the leaf, and the
//! staged half-install surfaces in the ordinary views.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use skillfs_core::{ParseConfig, SharedSkillStore, store::SkillStore};
use skillfs_fuse::security::{StagingConfig, StagingMatcher, StagingPattern};
use skillfs_fuse::{MountConfig, MountHandle, MountOptions, mount_background_configured};

fn wait_for(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if predicate() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    predicate()
}

fn write_manifest_skill(dir: &Path, name: &str) {
    let skill_dir = dir.join(name);
    std::fs::create_dir_all(&skill_dir).expect("create skill dir");
    std::fs::write(
        skill_dir.join("SKILL.md"),
        format!("---\nname: {name}\ndescription: test\n---\nbody\n"),
    )
    .expect("write SKILL.md");
}

/// Mounts a flat workspace with a non-dot `Exact("pip-staging")` staging
/// pattern and a pre-seeded staging category on disk.
struct StagingScanMount {
    #[allow(dead_code)]
    source: tempfile::TempDir,
    mountpoint: tempfile::TempDir,
    handle: Option<MountHandle>,
}

impl StagingScanMount {
    fn new(seed: impl FnOnce(&Path)) -> Self {
        let source = tempfile::tempdir().expect("source tempdir");
        seed(source.path());

        let mut store = SkillStore::new();
        store.load_from_directory(source.path(), &ParseConfig::default());
        let shared: SharedSkillStore = Arc::new(RwLock::new(store));

        let mountpoint = tempfile::tempdir().expect("mountpoint tempdir");

        let staging_config = StagingConfig {
            patterns: vec![StagingPattern::Exact("pip-staging".to_string())],
            ..StagingConfig::default()
        };
        let matcher = Arc::new(StagingMatcher::new(staging_config));

        let config = MountConfig {
            staging_matcher: Some(matcher),
            ..MountConfig::default()
        };

        let handle = mount_background_configured(
            mountpoint.path(),
            source.path(),
            shared,
            MountOptions::default(),
            false,
            config,
        )
        .expect("mount flat workspace with exact staging pattern");

        Self {
            source,
            mountpoint,
            handle: Some(handle),
        }
    }

    fn mount_path(&self, rel: &str) -> PathBuf {
        self.mountpoint.path().join(rel)
    }
}

impl Drop for StagingScanMount {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            drop(h);
        }
        let mp = self.mountpoint.path().to_path_buf();
        std::thread::sleep(Duration::from_millis(150));
        let _ = std::process::Command::new("fusermount3")
            .args(["-u", &mp.to_string_lossy()])
            .output();
    }
}

/// The on-disk shape under test: a real flat skill, a real categorized
/// skill, and an installer staging category pre-seeded with a
/// half-installed skill.
fn seed_workspace_with_category(src: &Path, staging_root: &str) {
    write_manifest_skill(src, "zeta");
    let alpha = src.join("alpha");
    std::fs::create_dir_all(&alpha).expect("create category");
    write_manifest_skill(&alpha, "notes");
    // The staging root: no SKILL.md of its own, a nested skill inside —
    // exactly the category shape the loader scans into the store.
    let staging = src.join(staging_root);
    std::fs::create_dir_all(&staging).expect("create staging root");
    write_manifest_skill(&staging, "web");
    std::fs::write(staging.join("notes.txt"), "staging\n").expect("probe file");
}

fn seed_workspace(src: &Path) {
    seed_workspace_with_category(src, "pip-staging");
}

fn list_dir_names(path: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(path)
        .expect("read dir")
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    names
}

/// A pre-seeded staging category's nested skills must stay out of the
/// ordinary `/skills` listing: staging roots are installer-private
/// workspaces, not skills. The staging root itself is already hidden by
/// the name-level filter; its scanned content must not surface under
/// the bare leaf name either.
#[test]
fn scan_loaded_staging_content_stays_out_of_the_skills_listing() {
    skip_if_no_fuse!();

    let m = StagingScanMount::new(seed_workspace);
    assert!(
        wait_for(Duration::from_secs(30), || {
            std::fs::read_to_string(m.mount_path("skills/zeta/SKILL.md")).is_ok()
        }),
        "flat mount never served skills/zeta/SKILL.md"
    );

    let entries = list_dir_names(&m.mount_path("skills"));
    assert!(
        !entries.iter().any(|n| n == "web"),
        "a skill staged inside a pre-seeded staging root must not appear in /skills, got: {entries:?}"
    );
    assert!(
        !entries.iter().any(|n| n == "pip-staging"),
        "the staging root itself must stay hidden from /skills, got: {entries:?}"
    );
    // Reverse: ordinary flat and categorized skills stay listed.
    assert!(
        entries.iter().any(|n| n == "zeta"),
        "an ordinary flat skill must stay listed, got: {entries:?}"
    );
    assert!(
        entries.iter().any(|n| n == "notes"),
        "an ordinary categorized skill must stay listed, got: {entries:?}"
    );
}

/// `skill-discover` broadcasts the store listing to every consumer; the
/// I2 contract keeps staging roots out of it. The staged half-install
/// must not be advertised there, while ordinary skills stay listed.
#[test]
fn scan_loaded_staging_content_stays_out_of_skill_discover() {
    skip_if_no_fuse!();

    let m = StagingScanMount::new(seed_workspace);
    assert!(
        wait_for(Duration::from_secs(30), || {
            std::fs::read_to_string(m.mount_path("skills/zeta/SKILL.md")).is_ok()
        }),
        "flat mount never served skills/zeta/SKILL.md"
    );

    let discover =
        std::fs::read_to_string(m.mount_path("skills/skill-discover/SKILL.md")).expect("discover");
    assert!(
        !discover.contains("| web |"),
        "a skill staged inside a pre-seeded staging root must not be broadcast by skill-discover, got:\n{discover}"
    );
    assert!(
        discover.contains("| zeta |"),
        "an ordinary flat skill must stay discoverable, got:\n{discover}"
    );
    assert!(
        discover.contains("| notes |"),
        "an ordinary categorized skill must stay discoverable, got:\n{discover}"
    );
}

/// The same scan-loaded leak through a non-dot `PrefixStar` staging
/// pattern: the pattern names the top-level staging root, the store key
/// is the nested skill's bare leaf, so the name-level filters miss it.
#[test]
fn prefix_star_staging_content_stays_out_of_the_skill_views() {
    skip_if_no_fuse!();

    let source = tempfile::tempdir().expect("source tempdir");
    seed_workspace_with_category(source.path(), "build-tmp");

    let mut store = SkillStore::new();
    store.load_from_directory(source.path(), &ParseConfig::default());
    let shared: SharedSkillStore = Arc::new(RwLock::new(store));

    let mountpoint = tempfile::tempdir().expect("mountpoint tempdir");
    let staging_config = StagingConfig {
        patterns: vec![StagingPattern::PrefixStar("build-".to_string())],
        ..StagingConfig::default()
    };
    let matcher = Arc::new(StagingMatcher::new(staging_config));
    let config = MountConfig {
        staging_matcher: Some(matcher),
        ..MountConfig::default()
    };
    let handle = mount_background_configured(
        mountpoint.path(),
        source.path(),
        shared,
        MountOptions::default(),
        false,
        config,
    )
    .expect("mount flat workspace with prefix-star staging pattern");

    assert!(
        wait_for(Duration::from_secs(30), || {
            std::fs::read_to_string(mountpoint.path().join("skills/zeta/SKILL.md")).is_ok()
        }),
        "flat mount never served skills/zeta/SKILL.md"
    );

    let entries = list_dir_names(&mountpoint.path().join("skills"));
    assert!(
        !entries.iter().any(|n| n == "web"),
        "a skill staged inside a pre-seeded staging category must not appear in /skills, got: {entries:?}"
    );
    let discover = std::fs::read_to_string(mountpoint.path().join("skills/skill-discover/SKILL.md"))
        .expect("discover");
    assert!(
        !discover.contains("| web |"),
        "a skill staged inside a pre-seeded staging category must not be broadcast by skill-discover, got:\n{discover}"
    );

    drop(handle);
    let mp = mountpoint.path().to_path_buf();
    std::thread::sleep(Duration::from_millis(150));
    let _ = std::process::Command::new("fusermount3")
        .args(["-u", &mp.to_string_lossy()])
        .output();
}
