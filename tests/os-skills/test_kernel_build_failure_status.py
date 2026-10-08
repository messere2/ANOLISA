#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regression tests for build-kernel.sh build-failure propagation.

build-kernel.sh had two ways of lying about a build:

1. get_latest_kernel() printed its warn/success progress lines on
   stdout, which the callers capture with $(...): the resolved
   "version" was a multi-line garbage string, so the default
   `upstream latest` invocation (and `install` with default version)
   built a nonsense URL and always failed, both when kernel.org was
   reachable and when it was not. Diagnostics must go to stderr.
2. The two long build steps ran as `cmd | tee -a LOG &` followed by
   `wait $build_pid`. `$!` is the PID of tee, and without pipefail the
   waited-on status is tee's, so a failed rpmbuild/make was silently
   turned into success: the script printed "SRPM build completed" /
   "Upstream build completed" and exited 0. The foreground
   `cmd | tee` call sites had the same masking.

All build commands (make, rpmbuild, rpm, yum, wget, curl, uname) are
stubbed into a private fixture PATH; the /root work directories the
script hardcodes are created on demand and removed afterwards. Tests
are skipped unless run as root or when those paths already exist.

Baseline on unchanged main: 5 failures / 1 passing control.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "os-skills"
    / "devops"
    / "kernel-dev"
    / "scripts"
    / "build-kernel.sh"
)

WORK_DIR = Path("/root/upstream-kernel")
OUTPUT_DIR = Path("/root/rpmbuild")
LOG_FILE = Path("/tmp/kernel-build.log")

SRC_DIR = WORK_DIR / "linux-6.12.9"
TARBALL = WORK_DIR / "linux-6.12.9.tar.xz"
SRC_RPM = OUTPUT_DIR / "SRPMS" / "kernel-6.12.9.src.rpm"


class KernelBuildFailureTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() != 0:
            raise unittest.SkipTest("build-kernel.sh hardcodes /root paths; run as root")
        if not Path("/bin/bash").exists():
            raise unittest.SkipTest("/bin/bash not present on this host")
        for path in (SRC_DIR, TARBALL, SRC_RPM):
            if path.exists():
                raise unittest.SkipTest(
                    f"refusing to touch pre-existing {path}"
                )
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.stubs = Path(self.tmp.name) / "stubs"
        self.stubs.mkdir()
        self.created = []

        # Work layout the script expects to find (download/extract skipped).
        self.ensure_dir(SRC_DIR)
        self.ensure_file(TARBALL)
        self.ensure_file(SRC_RPM)
        self.ensure_dir(OUTPUT_DIR / "SPECS")
        self.addCleanup(self.cleanup_created)
        if LOG_FILE.exists():
            LOG_FILE.unlink()

        self.write_stub(
            "uname",
            "#!/bin/sh\ncase \"$1\" in\n"
            "  -m) echo x86_64 ;;\n"
            "  -r) echo 6.12.9-alnx4 ;;\n"
            "  *) /usr/bin/uname \"$@\" ;;\n"
            "esac\n",
        )
        self.write_stub("yum", "#!/bin/sh\nexit 0\n")
        self.write_stub("rpm", "#!/bin/sh\nexit 0\n")
        self.write_stub("wget", "#!/bin/sh\nexit 1\n")
        self.write_stub(
            "curl",
            '#!/bin/sh\nif [ -n "${CURL_BODY_FILE:-}" ]; then cat "$CURL_BODY_FILE"; fi\n'
            'exit "${CURL_STATUS:-7}"\n',
        )
        self.write_stub(
            "make",
            "#!/bin/sh\nfor a in \"$@\"; do\n"
            "  case \"$a\" in\n"
            "    defconfig|tinyconfig|olddefconfig|menuconfig) exit 0 ;;\n"
            "    bzImage|Image) exit \"${BZIMAGE_STATUS:-0}\" ;;\n"
            "    modules) exit \"${MODULES_STATUS:-0}\" ;;\n"
            "  esac\ndone\nexit 0\n",
        )
        self.write_stub(
            "rpmbuild",
            "#!/bin/sh\ncase \" $* \" in\n"
            "  *' -bp '*) exit 0 ;;\n"
            "  *' -bc '*) exit \"${RPMBUILD_BC_STATUS:-0}\" ;;\n"
            "esac\nexit 0\n",
        )

    def ensure_dir(self, path):
        if not path.exists():
            path.mkdir(parents=True)
            self.created.append(path)

    def ensure_file(self, path):
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("", encoding="utf-8")
            self.created.append(path)

    def cleanup_created(self):
        for path in reversed(self.created):
            try:
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
            except OSError:
                pass

    def write_stub(self, name, text):
        path = self.stubs / name
        path.write_text(text, encoding="utf-8")
        path.chmod(0o755)

    def run_build(self, args, **status_overrides):
        env = dict(os.environ)
        env["PATH"] = f"{self.stubs}:/usr/bin:/bin"
        env.update({k: str(v) for k, v in status_overrides.items()})
        return subprocess.run(
            ["/bin/bash", str(SCRIPT)] + args,
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )

    def test_upstream_image_failure_aborts(self):
        """A failed kernel image build must not be reported as completed."""
        result = self.run_build(
            ["upstream", "6.12.9", "4", "defconfig"], BZIMAGE_STATUS=1
        )
        self.assertNotEqual(result.returncode, 0, result.stdout[-800:])
        self.assertNotIn("Upstream build completed", result.stdout)
        self.assertNotIn("Building kernel modules", result.stdout)
        self.assertIn("Kernel image build failed", result.stdout)

    def test_upstream_modules_failure_aborts(self):
        """A failed modules build must not be reported as completed."""
        result = self.run_build(
            ["upstream", "6.12.9", "4", "defconfig"], MODULES_STATUS=1
        )
        self.assertNotEqual(result.returncode, 0, result.stdout[-800:])
        self.assertNotIn("Upstream build completed", result.stdout)

    def test_srpm_failure_aborts(self):
        """A failed SRPM build must not be reported as completed."""
        result = self.run_build(
            ["srpm", "6.12.9", "4"], RPMBUILD_BC_STATUS=1
        )
        self.assertNotEqual(result.returncode, 0, result.stdout[-800:])
        self.assertNotIn("SRPM build completed", result.stdout)
        self.assertIn("SRPM kernel build failed", result.stdout)

    def test_upstream_success_control(self):
        """Control: a fully successful build still completes."""
        result = self.run_build(["upstream", "6.12.9", "4", "defconfig"])
        self.assertEqual(result.returncode, 0, result.stdout[-800:])
        self.assertIn("Upstream build completed", result.stdout)

    def test_latest_version_fallback_control(self):
        """Control: the kernel.org fallback yields a usable version."""
        result = self.run_build(["upstream", "latest", "4", "defconfig"])
        self.assertEqual(
            result.returncode, 0, result.stdout[-800:] + result.stderr[-400:]
        )
        self.assertIn("fallback: 6.12.9", result.stderr)
        # The fallback warning must not leak into the captured version.
        self.assertNotIn("Could not fetch", result.stdout)
        self.assertIn("Upstream build completed", result.stdout)

    def test_latest_version_probe_control(self):
        """Control: a successful kernel.org probe resolves a clean version."""
        body = Path(self.tmp.name) / "kernelorg.html"
        body.write_text(
            '<a href="/pub/linux/kernel/v6.x/linux-6.12.9.tar.xz">stable</a>\n',
            encoding="utf-8",
        )
        result = self.run_build(
            ["upstream", "latest", "4", "defconfig"],
            CURL_STATUS=0,
            CURL_BODY_FILE=str(body),
        )
        self.assertEqual(
            result.returncode, 0, result.stdout[-800:] + result.stderr[-400:]
        )
        # The progress line must not leak into the captured version.
        self.assertIn("Building kernel: 6.12.9", result.stdout)
        self.assertNotIn("Latest stable kernel:", result.stdout)
        self.assertIn("Upstream build completed", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2, exit=False)
