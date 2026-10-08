use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

struct Tree(std::path::PathBuf);
impl Tree {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("ktuner-memory-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn write(&self, rel: &str, value: &str) {
        let path = self.0.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, value).unwrap();
    }
}
impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn v1_membership_path_may_contain_colons() {
    // kernfs only forbids '/' and '\0' in cgroup directory names, so the
    // path field of a v1 membership line runs to the end of the line:
    // `11:memory:/lxc:web` names `/lxc:web`, not the colon-free prefix
    // `/lxc` of an unrelated sibling.
    assert_eq!(
        cgroup_v1_relative_path("11:memory:/lxc:web\n"),
        Some("/lxc:web".to_string())
    );
    // The colon-free shape is unchanged, and other controllers still do
    // not match.
    assert_eq!(
        cgroup_v1_relative_path("11:memory:/system.slice/app\n"),
        Some("/system.slice/app".to_string())
    );
    assert_eq!(
        cgroup_v1_relative_path("3:cpu,cpuacct:/system.slice/app.service\n"),
        None
    );
}

#[test]
fn colon_named_memory_cgroup_reads_its_own_limit() {
    let t = Tree::new();
    t.write("memory/lxc:web/memory.limit_in_bytes", "2147483648");
    t.write("memory/lxc/memory.limit_in_bytes", "8589934592");
    // The colon-named cgroup holds 2 GB; its colon-free sibling holds
    // 8 GB. The walk must read the cgroup's own chain (2 GB), not the
    // sibling the truncated path navigates to (8 GB).
    assert_eq!(
        cgroup_memory_limit_kb_from(&t.0, "11:memory:/lxc:web\n"),
        2 * 1024 * 1024
    );
}

#[test]
fn membership_paths_may_not_escape_the_mount() {
    let t = Tree::new();
    t.write("root/memory.max", "4294967296");
    t.write("outside/memory.max", "1048576");
    // A membership path carrying a parent component must be refused:
    // cpu_chain_limit carries this guard ("Namespace-relative parent
    // components must never walk above this mount"), and the memory walk
    // is the same navigation — it must not read limit files outside the
    // root it was given.
    assert_eq!(
        chain_limit_kb(
            &t.0.join("root"),
            "/../outside",
            "memory.max",
            cgroup_v2_limit_kb
        ),
        None
    );
    // Plain relative paths are still walked.
    assert_eq!(
        chain_limit_kb(&t.0.join("root"), "/", "memory.max", cgroup_v2_limit_kb),
        Some(4 * 1024 * 1024)
    );
}
