# Copyright 2026 Alibaba Cloud
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for the OpenClaw external agent's no-output guard and its retry.

Covers (issue #6569):
- The no-output guard returns its reason in the child's stderr, so
  ``_run_agent_loop``'s one-retry policy can key on it (before the fix the
  reason only reached the log and a real hang exited -9 immediately).
- The child's own stderr is preserved alongside the appended reason.
- The retry flow end to end: hang -> retry -> command executed ->
  TASK_COMPLETE, with the retry's sessionId carried to the next turn.
- Two consecutive hangs stop after exactly the one retry.
- An ordinary failure is not retried.

The Harbor interfaces are stubbed (the adapter only runs under Harbor at
runtime); children are harmless local ``python -c`` sleepers, and the
agent's profile directories are redirected to a temporary home.
"""

import asyncio
import importlib.util
import json
import logging
import sys
import types
from pathlib import Path

# Stub Harbor before importing the runner module (not installed here).
for _name in ("harbor", "harbor.agents", "harbor.agents.base",
              "harbor.environments", "harbor.environments.base",
              "harbor.models", "harbor.models.agent",
              "harbor.models.agent.context"):
    sys.modules.setdefault(_name, types.ModuleType(_name))
sys.modules["harbor.agents.base"].BaseAgent = object
sys.modules["harbor.environments.base"].BaseEnvironment = object
sys.modules["harbor.models.agent.context"].AgentContext = object

_SOURCE = (
    Path(__file__).resolve().parents[1]
    / "external_agent" / "openclaw_external_agent.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "openclaw_external_agent_uut", _SOURCE
)
runner = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(runner)

_HANG_STDERR = "\nOpenClaw: no stdout for 1s (likely API hang)\n"


class _Env:
    """Minimal Harbor environment double."""

    async def exec(self, command: str):
        class _Result:
            exit_code = 0
            stdout = "ok"
            stderr = ""

        return _Result()


def _make_agent(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = runner.OpenClawExternalAgent()
    agent.logger = logging.getLogger("openclaw-external-test")
    agent.model_name = ""
    agent._harbor_container_id = "fixture-container"
    agent._profile_name = "fixture-profile"
    agent._harbor_image = None
    return agent


class TestNoOutputGuardReason:
    """The guard's reason must reach the caller, not only the log."""

    def test_no_output_kill_returns_reason_in_stderr(self, monkeypatch):
        monkeypatch.setenv("OPENCLAW_NO_OUTPUT_TIMEOUT", "1")
        returncode, stdout, stderr = (
            runner.OpenClawExternalAgent._sync_run_openclaw(
                [sys.executable, "-c", "import time; time.sleep(5)"])
        )
        assert returncode == -9
        assert stdout == ""
        assert "no stdout for" in stderr
        assert "likely API hang" in stderr

    def test_child_stderr_preserved_with_reason(self, monkeypatch):
        """The child's own stderr survives next to the appended reason."""
        monkeypatch.setenv("OPENCLAW_NO_OUTPUT_TIMEOUT", "1")
        returncode, stdout, stderr = (
            runner.OpenClawExternalAgent._sync_run_openclaw(
                [sys.executable, "-c",
                 "import sys, time; sys.stderr.write('booting\\n'); "
                 "sys.stderr.flush(); time.sleep(5)"])
        )
        assert returncode == -9
        assert "booting" in stderr
        assert "no stdout for" in stderr
        assert "likely API hang" in stderr


class TestAgentLoopRetry:
    """The loop's one-retry policy and session continuity."""

    def test_retry_recovers_and_keeps_session(self, tmp_path, monkeypatch):
        """Hang -> retry returns commands -> TASK_COMPLETE, and the retry's
        sessionId is passed as --session-id on the following turn."""
        agent = _make_agent(tmp_path, monkeypatch)
        calls = []
        responses = [
            # The shape the fixed guard returns for a real no-output hang.
            (-9, "", _HANG_STDERR),
            # The retry succeeds and establishes a session.
            (0, json.dumps({
                "meta": {
                    "agentMeta": {"sessionId": "fixture-session"},
                    "finalAssistantVisibleText": "```bash\necho done\n```",
                },
            }), ""),
            # The next turn completes the task.
            (0, json.dumps({
                "meta": {"finalAssistantVisibleText": "TASK_COMPLETE"},
            }), ""),
        ]

        def fake_sync_run(cmd, extra_env=None):
            calls.append(list(cmd))
            return responses.pop(0)

        agent._sync_run_openclaw = fake_sync_run

        result = asyncio.run(
            agent._run_agent_loop("do the task", _Env())
        )

        assert len(calls) == 3, calls
        assert result["returncode"] == 0
        assert len(result["harbor_executions"]) == 1
        # The session established by the *retry* must reach the next turn.
        third = calls[2]
        assert "--session-id" in third, third
        assert third[third.index("--session-id") + 1] == "fixture-session"

    def test_double_hang_stops_after_one_retry(self, tmp_path, monkeypatch):
        agent = _make_agent(tmp_path, monkeypatch)
        calls = []

        def fake_sync_run(cmd, extra_env=None):
            calls.append(list(cmd))
            return (-9, "", _HANG_STDERR)

        agent._sync_run_openclaw = fake_sync_run

        result = asyncio.run(
            agent._run_agent_loop("do the task", _Env())
        )

        assert len(calls) == 2, calls
        assert result["returncode"] == -9

    def test_ordinary_failure_not_retried(self, tmp_path, monkeypatch):
        agent = _make_agent(tmp_path, monkeypatch)
        calls = []

        def fake_sync_run(cmd, extra_env=None):
            calls.append(list(cmd))
            return (-1, "", "boom")

        agent._sync_run_openclaw = fake_sync_run

        result = asyncio.run(
            agent._run_agent_loop("do the task", _Env())
        )

        assert len(calls) == 1, calls
        assert result["returncode"] == -1
