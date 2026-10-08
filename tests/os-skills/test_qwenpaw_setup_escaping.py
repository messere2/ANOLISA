#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regression tests for install-qwenpaw setup.sh credential escaping.

setup.sh renders config.json / dashscope.json by interpolating the
user-supplied DingTalk client id/secret and the DashScope API key into
a sed *replacement* string without escaping. In a sed replacement `&`
means "the matched text", so a secret containing `&` silently writes
the `{PLACEHOLDER}` back into the config — valid JSON, wrong credential,
and the bot later fails DingTalk auth with no hint why. A backslash eats
the following character the same way, and a pipe would terminate the s
command outright.

The script runs end-to-end against a fixture HOME with stubbed
uv/qwenpaw/pgrep/curl/sleep; templates come from the real skill tree.
Baseline on unchanged main: 2 failures / 1 passing control.
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "os-skills"
    / "ai"
    / "install-qwenpaw"
    / "scripts"
    / "setup.sh"
)

AMP_SECRET = "ding&secret&value"
BACKSLASH_ID = "ding\\id\\123"
PLAIN_ID = "dingclient123"
PLAIN_SECRET = "plainsecret456"
PLAIN_KEY = "sk-abcdef123456"


class QwenpawSetupEscapingTests(unittest.TestCase):
    def setUp(self):
        if not Path("/bin/bash").exists():
            raise unittest.SkipTest("/bin/bash not present on this host")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.stubs = self.root / "stubs"
        self.stubs.mkdir()
        for name, text in (
            ("uv", "#!/bin/sh\necho 'uv 0.5.1'\n"),
            ("qwenpaw", "#!/bin/sh\necho 'qwenpaw 1.0.0'\n"),
            ("pgrep", "#!/bin/sh\nexit 1\n"),
            ("curl", "#!/bin/sh\necho 200\n"),
            ("sleep", "#!/bin/sh\nexit 0\n"),
        ):
            path = self.stubs / name
            path.write_text(text, encoding="utf-8")
            path.chmod(0o755)

    def run_setup(self, key, client_id, client_secret):
        env = dict(os.environ)
        env["PATH"] = f"{self.stubs}:/usr/bin:/bin"
        env["HOME"] = str(self.home)
        return subprocess.run(
            [
                "/bin/bash",
                str(SCRIPT),
                key,
                client_id,
                client_secret,
            ],
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )

    def read_json(self, relpath):
        path = self.home / relpath
        self.assertTrue(path.is_file(), f"{path} missing")
        return json.loads(path.read_text(encoding="utf-8"))

    def test_ampersand_in_credentials_is_written_verbatim(self):
        result = self.run_setup("sk-key&with&amp", "id&1", AMP_SECRET)
        self.assertEqual(result.returncode, 0, result.stdout[-600:] + result.stderr[-300:])
        config = self.read_json(".qwenpaw/config.json")
        self.assertEqual(config["channels"]["dingtalk"]["client_id"], "id&1")
        self.assertEqual(config["channels"]["dingtalk"]["client_secret"], AMP_SECRET)
        provider = self.read_json(".qwenpaw.secret/providers/builtin/dashscope.json")
        self.assertEqual(provider["api_key"], "sk-key&with&amp")

    def test_backslash_in_credentials_is_written_verbatim(self):
        result = self.run_setup("sk-plain", BACKSLASH_ID, "secret\\123")
        self.assertEqual(result.returncode, 0, result.stdout[-600:] + result.stderr[-300:])
        config = self.read_json(".qwenpaw/config.json")
        self.assertEqual(config["channels"]["dingtalk"]["client_id"], BACKSLASH_ID)
        self.assertEqual(config["channels"]["dingtalk"]["client_secret"], "secret\\123")

    def test_plain_credentials_are_unchanged(self):
        """Control: ordinary alphanumeric credentials keep working."""
        result = self.run_setup(PLAIN_KEY, PLAIN_ID, PLAIN_SECRET)
        self.assertEqual(result.returncode, 0, result.stdout[-600:] + result.stderr[-300:])
        config = self.read_json(".qwenpaw/config.json")
        self.assertEqual(config["channels"]["dingtalk"]["client_id"], PLAIN_ID)
        self.assertEqual(config["channels"]["dingtalk"]["client_secret"], PLAIN_SECRET)
        provider = self.read_json(".qwenpaw.secret/providers/builtin/dashscope.json")
        self.assertEqual(provider["api_key"], PLAIN_KEY)
        model = self.read_json(".qwenpaw.secret/providers/active_model.json")
        self.assertTrue(model, "active model written")


if __name__ == "__main__":
    unittest.main(verbosity=2, exit=False)
