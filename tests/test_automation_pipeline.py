"""Day 1/3/4/5 新增脚本单元测试（离线，不调模型）。"""

import json
import tempfile
import unittest
from pathlib import Path

from scripts.harvest_dynamic_traces import harvest
from scripts.report_v2 import _matrix, _technique, build_report


class TestHarvestDynamicTraces(unittest.TestCase):
    def _write_runs(self, path: Path, runs: list[dict]) -> None:
        with path.open("w", encoding="utf-8") as f:
            for r in runs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    def test_generation_is_labeling(self) -> None:
        """生成即标注：judge 判定直接成为标签；分歧/uncertain 降权"""
        runs = [
            {
                "goal": "g1", "pattern_id": "seed-01", "rounds": 2,
                "target_model": "glm-4-flash", "ran_at": "2026-10-10T00:00:00Z",
                "turns": [
                    {"payload": "p1", "response": "r1", "verdict": "defense_success",
                     "needs_review": False, "defense_signature": "hard_refusal",
                     "tool_calls": [{"tool": "role_play_shell"}]},
                    {"payload": "p2", "response": "r2", "verdict": "attack_success",
                     "needs_review": False, "defense_signature": "compliance",
                     "tool_calls": [{"tool": "base64_wrap"}]},
                ],
            },
            {
                "goal": "g2", "pattern_id": "seed-02", "rounds": 1,
                "target_model": "glm-4-flash", "ran_at": "2026-10-10T00:01:00Z",
                "turns": [
                    {"payload": "p", "response": "r", "verdict": "uncertain",
                     "needs_review": True, "tool_calls": []},
                ],
            },
        ]
        with tempfile.TemporaryDirectory() as td:
            runs_p = Path(td) / "runs.jsonl"
            out_p = Path(td) / "traces.jsonl"
            self._write_runs(runs_p, runs)
            stats = harvest(runs_p, out_p)

            self.assertEqual(stats["harvested"], 2)
            self.assertEqual(stats["high"], 1)
            self.assertEqual(stats["low"], 1)

            traces = [json.loads(l) for l in out_p.open(encoding="utf-8")]
            t0 = traces[0]
            # 生成即标注：标签 = 末轮裁判判定
            self.assertEqual(t0["label"], "success")
            self.assertEqual(t0["confidence"], "high")
            # 手法序列完整保留（策略库数据源）
            self.assertEqual(t0["mutation_chain"], ["role_play_shell", "base64_wrap"])
            self.assertEqual(t0["defense_signature"], "compliance")
            # 低置信度行降权标记
            self.assertEqual(traces[1]["confidence"], "low")
            self.assertTrue(traces[1]["needs_review"])

    def test_error_runs_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            runs_p = Path(td) / "runs.jsonl"
            out_p = Path(td) / "traces.jsonl"
            self._write_runs(runs_p, [{"error": "ReadTimeout", "goal": "g"}])
            stats = harvest(runs_p, out_p)
            self.assertEqual(stats["harvested"], 0)


class TestReportV2(unittest.TestCase):
    def test_technique_label_priority(self) -> None:
        self.assertEqual(_technique({"attack_sub_type": "role_play"}), "role_play")
        self.assertEqual(
            _technique({"mutation_chain": ["base64_wrap:1"]}), "base64_wrap"
        )
        self.assertEqual(_technique({}), "original")

    def test_matrix_counts(self) -> None:
        rows = [
            {"attack_sub_type": "role_play", "model": "m1", "verdict": "attack_success"},
            {"attack_sub_type": "role_play", "model": "m1", "verdict": "defense_success"},
            {"attack_sub_type": "role_play", "model": "m1", "verdict": "uncertain"},
        ]
        m = _matrix(rows, _technique, lambda r: r["model"])
        self.assertEqual(m["role_play"]["m1"], {"success": 1, "total": 2})

    def test_report_has_both_matrices(self) -> None:
        rows = [
            {"attack_sub_type": "role_play", "model": "m1",
             "verdict": "attack_success", "defense_signature": "compliance"},
        ]
        md = build_report(rows)
        self.assertIn("手法 × 靶模型", md)
        self.assertIn("防御签名 × 手法", md)
        self.assertIn("compliance", md)


class TestVersionDataset(unittest.TestCase):
    def test_threshold_gate(self) -> None:
        """新增轨迹低于阈值不出新版本（--force 例外）"""
        from scripts.version_dataset import NEW_TRACES_THRESHOLD

        self.assertEqual(NEW_TRACES_THRESHOLD, 50)


if __name__ == "__main__":
    unittest.main()
