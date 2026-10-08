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

"""Test batch result aggregation and statistics.

Covers:
- pass_at_k calculation
- batch_results.json structure
- batch_summary.json structure  
- Multi-trial aggregation
- Error handling

Task type coverage:
- T tasks: single/multi trial
- M tasks: sandbox flag + env_snapshot
- C tasks: user_agent_rounds
"""

import pytest
import math

class TestPassAtK:
    """Test pass@k estimator."""

    def test_pass_at_k_all_pass(self):
        """All trials pass -> pass@k = 1.0."""
        from ce_runner.batch_runner import pass_at_k
        assert pass_at_k(5, 5, 1) == 1.0

    def test_pass_at_k_none_pass(self):
        """No trials pass -> pass@k = 0.0."""
        from ce_runner.batch_runner import pass_at_k
        assert pass_at_k(5, 0, 1) == 0.0

    def test_pass_at_k_partial(self):
        """Partial pass rate."""
        from ce_runner.batch_runner import pass_at_k
        result = pass_at_k(10, 5, 1)
        assert 0.0 < result < 1.0

    def test_pass_at_k_k_greater_than_n_minus_c(self):
        """k > n-c returns 1.0."""
        from ce_runner.batch_runner import pass_at_k
        # n=5, c=4, k=2 -> n-c=1 < k -> returns 1.0
        assert pass_at_k(5, 4, 2) == 1.0


class TestAggregateTaskResults:
    """Per-task trial lists must be ordered by trial number.

    Under --grade-parallel the flat batch_results list is appended in
    grading completion order, but the report renderers label each task's
    trial rows positionally (#1, #2, ...), so the aggregated trials must
    come back sorted by their trial number.
    """

    @staticmethod
    def _entry(tid, number, score):
        """One flat batch_results entry shaped like _collect_completed's."""
        return {
            "task_id": tid,
            "trial": {
                "trial": number,
                "task_score": score,
                "passed": score >= 0.75,
                "completion": score,
                "robustness": score,
                "communication": score,
                "safety": score,
                "error": None,
                "wall_time_s": 1.0,
                "session_id": "s1",
                "trace_file": None,
                "session_archive_file": None,
                "session_origin_file": None,
            },
        }

    def test_trials_sorted_by_trial_number(self):
        """Completion order [2, 1] must aggregate to trial order [1, 2]."""
        from ce_runner.batch_runner import aggregate_task_results
        batch = [self._entry("T001", 2, 0.9), self._entry("T001", 1, 0.2)]
        tr = aggregate_task_results(batch)["T001"]
        assert [t["trial"] for t in tr["trials"]] == [1, 2]

    def test_three_trials_reverse_completion(self):
        """Completion order [3, 2, 1] must aggregate to [1, 2, 3]."""
        from ce_runner.batch_runner import aggregate_task_results
        batch = [
            self._entry("T001", 3, 0.5),
            self._entry("T001", 2, 0.9),
            self._entry("T001", 1, 0.2),
        ]
        tr = aggregate_task_results(batch)["T001"]
        assert [t["trial"] for t in tr["trials"]] == [1, 2, 3]

    def test_tasks_grouped_separately(self):
        """Interleaved tasks keep their own sorted trial lists."""
        from ce_runner.batch_runner import aggregate_task_results
        batch = [
            self._entry("T002", 2, 0.9),
            self._entry("T001", 1, 0.2),
            self._entry("T002", 1, 0.5),
            self._entry("T001", 2, 0.8),
        ]
        out = aggregate_task_results(batch)
        assert sorted(out.keys()) == ["T001", "T002"]
        assert [t["trial"] for t in out["T001"]["trials"]] == [1, 2]
        assert [t["trial"] for t in out["T002"]["trials"]] == [1, 2]

    def test_single_trial_unchanged(self):
        """A single trial keeps its record and task_id."""
        from ce_runner.batch_runner import aggregate_task_results
        batch = [self._entry("T001", 1, 0.2)]
        out = aggregate_task_results(batch)
        assert out["T001"]["task_id"] == "T001"
        assert [t["trial"] for t in out["T001"]["trials"]] == [1]

    def test_report_labels_match_trial_numbers(self):
        """User-visible contract: fed to summarize_results.build_table, the
        positional #n label must carry trial n's score regardless of the
        completion order recorded in batch_results."""
        import importlib.util
        from pathlib import Path

        from ce_runner.batch_runner import aggregate_task_results

        script = Path(__file__).resolve().parents[1] / "scripts" / "summarize_results.py"
        spec = importlib.util.spec_from_file_location("summarize_results_uut", script)
        summary = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(summary)

        batch = [self._entry("T001", 2, 0.9), self._entry("T001", 1, 0.2)]
        data = [dict(aggregate_task_results(batch)["T001"],
                     task_name="demo", difficulty="easy")]
        rows = summary.build_table(data)[1:]
        by_label = {row[3]: row[15] for row in rows}
        assert by_label["#1"] == "0.20", by_label
        assert by_label["#2"] == "0.90", by_label
