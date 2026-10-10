"""Sprint 6 单元测试：在线报表聚合 + 报告生成（翻转告警/成本/典型 case）。"""

import unittest
from unittest.mock import MagicMock

from app.report import build_summary
from scripts.generate_report import cost_stats, find_flips, generate_report


def _run(task: str, model: str, verdict: str, created: str, tokens: int = 100):
    return {
        "id": f"run-{task}-{created}",
        "task_id": task,
        "target_model": model,
        "final_verdict": verdict,
        "rounds": 3,
        "prompt_tokens": tokens,
        "completion_tokens": tokens // 2,
        "created_at": f"2026-09-{created}T00:00:00Z",
        "probe_mode": "template",
    }


def _mock_db(runs, tasks, patterns):
    db = MagicMock()
    mocks: dict = {}

    def table(name: str):
        if name not in mocks:
            mocks[name] = MagicMock(name=f"table({name})")
        return mocks[name]

    db.table.side_effect = table

    runs_q = mocks["probe_runs"] = MagicMock()
    runs_q.select.return_value.order.return_value.execute.return_value.data = runs

    tasks_q = mocks["test_tasks"] = MagicMock()
    tasks_q.select.return_value.in_.return_value.execute.return_value.data = tasks

    patterns_q = mocks["attack_patterns"] = MagicMock()
    patterns_q.select.return_value.in_.return_value.execute.return_value.data = patterns
    return db


class TestBuildSummary(unittest.TestCase):
    def test_asr_matrix_and_cost(self) -> None:
        runs = [
            _run("t1", "glm", "attack_success", "01"),
            _run("t2", "glm", "defense_success", "01"),
            _run("t3", "glm", "uncertain", "01"),
            _run("t4", "ds", "attack_success", "01"),
        ]
        tasks = [
            {"id": "t1", "attack_pattern_id": "p1", "target_name": "A"},
            {"id": "t2", "attack_pattern_id": "p1", "target_name": "A"},
            {"id": "t3", "attack_pattern_id": "p2", "target_name": "A"},
            {"id": "t4", "attack_pattern_id": "p1", "target_name": "B"},
        ]
        patterns = [
            {"id": "p1", "attack_category": "jailbreak"},
            {"id": "p2", "attack_category": "info_leakage"},
        ]
        summary = build_summary(_mock_db(runs, tasks, patterns))

        glm_jb = summary["asr_matrix"]["glm"]["jailbreak"]
        self.assertEqual(glm_jb["success"], 1)
        self.assertEqual(glm_jb["refusal"], 1)
        self.assertEqual(glm_jb["asr"], 0.5)
        self.assertEqual(summary["asr_matrix"]["ds"]["jailbreak"]["asr"], 1.0)
        self.assertEqual(summary["runs"], 4)
        self.assertEqual(summary["cost"]["glm"]["prompt_tokens"], 300)

    def test_flip_detection(self) -> None:
        """同一任务两次 run verdict 不一致 → 翻转告警"""
        runs = [
            _run("t1", "glm", "defense_success", "01"),
            _run("t1", "glm", "attack_success", "02"),
            _run("t2", "glm", "attack_success", "01"),
            _run("t2", "glm", "attack_success", "02"),  # 一致，不告警
        ]
        tasks = [
            {"id": "t1", "attack_pattern_id": "p1", "target_name": "靶A"},
            {"id": "t2", "attack_pattern_id": "p1", "target_name": "靶B"},
        ]
        patterns = [{"id": "p1", "attack_category": "jailbreak"}]
        summary = build_summary(_mock_db(runs, tasks, patterns))
        self.assertEqual(len(summary["flips"]), 1)
        flip = summary["flips"][0]
        self.assertEqual(flip["task_id"], "t1")
        self.assertEqual(flip["before"], "defense_success")
        self.assertEqual(flip["after"], "attack_success")

    def test_empty_runs(self) -> None:
        summary = build_summary(_mock_db([], [], []))
        self.assertEqual(summary["runs"], 0)
        self.assertEqual(summary["flips"], [])


class TestGenerateReport(unittest.TestCase):
    def test_find_flips_offline(self) -> None:
        current = [
            {"sample_id": "s1", "model": "m1", "verdict": "attack_success"},
            {"sample_id": "s2", "model": "m1", "verdict": "defense_success"},
        ]
        previous = [
            {"sample_id": "s1", "model": "m1", "verdict": "defense_success"},
            {"sample_id": "s2", "model": "m1", "verdict": "defense_success"},
        ]
        flips = find_flips(current, previous)
        self.assertEqual(len(flips), 1)
        self.assertEqual(flips[0]["sample_id"], "s1")

    def test_cost_stats(self) -> None:
        results = [
            {"model": "m1", "usage": {"prompt_tokens": 10, "completion_tokens": 5}},
            {"model": "m1", "usage": {"prompt_tokens": 20, "completion_tokens": 10}},
            {"model": "m2", "usage": {"prompt_tokens": 7, "completion_tokens": 3}},
        ]
        stats = cost_stats(results)
        self.assertEqual(stats["m1"]["prompt_tokens"], 30)
        self.assertEqual(stats["m2"]["calls"], 1)

    def test_full_report_sections(self) -> None:
        results = [
            {"sample_id": "s1", "model": "m1", "pattern_id": "p1",
             "attack_category": "jailbreak", "verdict": "attack_success",
             "needs_review": False, "judge_reason": "服从了", "response": "x",
             "usage": {"prompt_tokens": 10, "completion_tokens": 5}},
        ]
        md = generate_report(results, previous=[])
        self.assertIn("ASR", md)
        self.assertIn("翻转告警", md)
        self.assertIn("成本统计", md)
        self.assertIn("典型 case", md)
        self.assertIn("服从了", md)


if __name__ == "__main__":
    unittest.main()
