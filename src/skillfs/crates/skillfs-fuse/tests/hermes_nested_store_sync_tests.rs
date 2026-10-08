//! Integration tests: Hermes nested manifest mutations sync the store.
//!
//! Every write-path mutation of a flat manifest — `write`, `create`,
//! `setattr`-truncate, open `O_TRUNC`, and a file-level rename — enqueues a
//! [`SyncEvent::Reparse`] so the background worker re-parses the manifest
//! into the shared store. The store holds Hermes nested skills too (keyed by
//! their directory leaf name, exactly like the categorized loader inserts
//! them), and the nested write paths share all the plumbing — but they never
//! enqueued the re-parse: the physical file changed while the store, and with
//! it the skill-discover document rendered from the store, kept serving the
//! pre-mutation manifest until remount.
//!
//! These tests require `/dev/fuse` and `fusermount3` (skipped gracefully
//! otherwise). The background mount runs the environment-profile probe loop
//! before the FUSE session comes up, which can take seconds on a loaded
//! host, so readiness is polled instead of assumed after a fixed delay.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use skillfs_core::{ParseConfig, SharedSkillStore, store::SkillStore};
use skillfs_fuse::{MountConfig, MountOptions, SkillLayout, mount_background_configured};

#[path = "common/mod.rs"]
mod common;

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

struct HermesMount {
    source: tempfile::TempDir,
    mountpoint: tempfile::TempDir,
    store: SharedSkillStore,
    _handle: skillfs_fuse::MountHandle,
}

impl HermesMount {
    /// Mount a Hermes workspace seeded by `seed` (which receives the source
    /// dir) and poll until `served` is readable through the mount.
    fn new(seed: impl FnOnce(&std::path::Path), served: &str) -> Self {
        let source = tempfile::tempdir().expect("source tempdir");
        seed(source.path());
        let mut store = SkillStore::new();
        store.load_from_directory(source.path(), &ParseConfig::default());
        let store: SharedSkillStore = Arc::new(RwLock::new(store));

        let mountpoint = tempfile::tempdir().expect("mountpoint tempdir");
        let config = MountConfig {
            skill_layout: Some(SkillLayout::Hermes),
            ..MountConfig::default()
        };
        let _handle = mount_background_configured(
            mountpoint.path(),
            source.path(),
            store.clone(),
            MountOptions::default(),
            true,
            config,
        )
        .expect("mount hermes workspace");

        let probe = mountpoint.path().join(served);
        assert!(
            wait_for(Duration::from_secs(30), || {
                std::fs::read_to_string(&probe).is_ok()
            }),
            "hermes mount never served {served}"
        );
        Self {
            source,
            mountpoint,
            store,
            _handle,
        }
    }

    fn mount_path(&self, rel: &str) -> PathBuf {
        self.mountpoint.path().join(rel)
    }

    fn entry_body(&self, key: &str) -> Option<String> {
        self.store.read().get(key).map(|e| e.body.clone())
    }
}

#[test]
fn nested_manifest_appends_refresh_the_store_entry() {
    skip_if_no_fuse!();

    let m = HermesMount::new(
        |src| {
            std::fs::create_dir_all(src.join("cloud/web")).expect("nested skill dir");
            std::fs::write(
                src.join("cloud/web/SKILL.md"),
                "---\nname: web\ndescription: nested\n---\noriginal body\n",
            )
            .expect("seed SKILL.md");
        },
        "cloud/web/SKILL.md",
    );

    let mut md = std::fs::OpenOptions::new()
        .append(true)
        .open(m.mount_path("cloud/web/SKILL.md"))
        .expect("append nested SKILL.md");
    md.write_all(b"appended through the hermes mount\n")
        .expect("write nested SKILL.md");
    drop(md);

    assert!(
        wait_for(Duration::from_secs(5), || {
            m.entry_body("web")
                .is_some_and(|body| body.contains("appended through the hermes mount"))
        }),
        "nested manifest append must re-parse into the store (leaf key), body is still {:?}",
        m.entry_body("web")
    );
    assert!(
        std::fs::read_to_string(m.source.path().join("cloud/web/SKILL.md"))
            .expect("physical SKILL.md")
            .contains("appended through the hermes mount")
    );
}

#[test]
fn nested_manifest_creates_refresh_the_store_entry() {
    skip_if_no_fuse!();

    let m = HermesMount::new(
        |src| {
            // A plain category child directory: present on disk, but the
            // store has no entry for it until a manifest appears.
            std::fs::create_dir_all(src.join("cloud/newbie")).expect("plain category child");
            std::fs::create_dir_all(src.join("cloud/web")).expect("served nested skill dir");
            std::fs::write(
                src.join("cloud/web/SKILL.md"),
                "---\nname: web\ndescription: nested\n---\noriginal body\n",
            )
            .expect("seed SKILL.md");
        },
        "cloud/web/SKILL.md",
    );

    let mut md = std::fs::File::create(m.mount_path("cloud/newbie/SKILL.md"))
        .expect("create nested SKILL.md");
    md.write_all(b"---\nname: newbie\ndescription: created\n---\ncreated body\n")
        .expect("write created SKILL.md");
    drop(md);

    assert!(
        wait_for(Duration::from_secs(5), || {
            m.entry_body("newbie")
                .is_some_and(|body| body.contains("created body"))
        }),
        "nested manifest create must re-parse into the store (leaf key)"
    );
}

#[test]
fn nested_manifest_renames_drop_and_restore_the_store_entry() {
    skip_if_no_fuse!();

    let m = HermesMount::new(
        |src| {
            std::fs::create_dir_all(src.join("cloud/web")).expect("nested skill dir");
            std::fs::write(
                src.join("cloud/web/SKILL.md"),
                "---\nname: web\ndescription: nested\n---\noriginal body\n",
            )
            .expect("seed SKILL.md");
        },
        "cloud/web/SKILL.md",
    );

    let md = m.mount_path("cloud/web/SKILL.md");
    let disabled = m.mount_path("cloud/web/DISABLED.md");

    // Renaming the manifest away disables the skill: the store must forget
    // the leaf entry (identity-gated, like the directory-rename arm).
    std::fs::rename(&md, &disabled).expect("rename manifest away");
    assert!(
        wait_for(Duration::from_secs(5), || {
            m.store.read().get("web").is_none()
        }),
        "renaming the nested manifest away must drop the store entry"
    );

    // Renaming it back re-enables the skill: the store must re-learn it.
    std::fs::rename(&disabled, &md).expect("rename manifest back");
    assert!(
        wait_for(Duration::from_secs(5), || {
            m.entry_body("web")
                .is_some_and(|body| body.contains("original body"))
        }),
        "renaming the nested manifest back must restore the store entry"
    );
}
