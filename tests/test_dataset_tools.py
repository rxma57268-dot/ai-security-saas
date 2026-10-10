"""Sprint 2 工具单元测试：分层抽样 + ASR 矩阵（纯本地，不调模型）。"""

import unittest

from scripts.asr_matrix import compute_asr_matrix, render_markdown
from scripts.sample_golden import stratified_sample


def _row(model: str, pattern: str, verdict: str, category: str = "jailbreak"):
    return {
        "sample_id": f"{model}-{pattern}-{verdict}",
        "model": model,
        "pattern_id": pattern,
        "verdict": verdict,
        "needs_review": False,
        "attack_category": category,
    }


class TestStratifiedSample(unittest.TestCase):
    def test_covers_three_layers_per_group(self) -> None:
        """每个 (model × pattern) 分组覆盖 success/refusal/boundary 三层"""
        results = []
        for pattern in ("p1", "p2"):
            results += [_row("m1", pattern, "attack_success") for _ in range(10)]
            results += [_row("m1", pattern, "defense_success") for _ in range(10)]
            results += [_row("m1", pattern, "uncertain") for _ in range(10)]
        picked = stratified_sample(results, per_pattern=15, total=100, seed=1)
        self.assertEqual(len(picked), 30)
        for pattern in ("p1", "p2"):
            group = [r for r in picked if r["pattern_id"] == pattern]
            verdicts = {r["verdict"] for r in group}
            self.assertEqual(
                verdicts, {"attack_success", "defense_success", "uncertain"}
            )
            # 每行都带了待标注字段
            for r in group:
                self.assertEqual(r["label"], "")

    def test_error_rows_excluded(self) -> None:
        results = [_row("m1", "p1", "attack_success") for _ in range(5)]
        bad = _row("m1", "p1", "attack_success")
        bad["error"] = "Timeout"
        results.append(bad)
        picked = stratified_sample(results, per_pattern=15, total=100, seed=1)
        self.assertNotIn(bad, picked)

    def test_total_cap(self) -> None:
        results = []
        for pattern in ("p1", "p2", "p3"):
            results += [_row("m1", pattern, "attack_success") for _ in range(20)]
        picked = stratified_sample(results, per_pattern=15, total=10, seed=1)
        self.assertEqual(len(picked), 10)

    def test_deterministic_with_seed(self) -> None:
        results = [_row("m1", "p1", v) for v in
                   ("attack_success", "defense_success", "uncertain") * 5]
        a = stratified_sample(results, 6, 50, seed=7)
        b = stratified_sample(results, 6, 50, seed=7)
        self.assertEqual([r["sample_id"] for r in a], [r["sample_id"] for r in b])


class TestAsrMatrix(unittest.TestCase):
    def test_asr_computation(self) -> None:
        golden = [
            {"model": "m1", "attack_category": "jailbreak", "label": "success"},
            {"model": "m1", "attack_category": "jailbreak", "label": "success"},
            {"model": "m1", "attack_category": "jailbreak", "label": "refusal"},
            {"model": "m1", "attack_category": "jailbreak", "label": "partial"},
            {"model": "m1", "attack_category": "info_leakage", "label": "refusal"},
            {"model": "m2", "attack_category": "jailbreak", "label": "refusal"},
            {"model": "m2", "attack_category": "jailbreak", "label": "refusal"},
        ]
        matrix = compute_asr_matrix(golden)
        self.assertEqual(matrix["m1"]["jailbreak"]["success"], 2)
        self.assertEqual(matrix["m1"]["jailbreak"]["total"], 4)
        self.assertEqual(matrix["m1"]["jailbreak"]["asr"], 0.5)
        self.assertEqual(matrix["m1"]["info_leakage"]["asr"], 0.0)
        self.assertEqual(matrix["m2"]["jailbreak"]["asr"], 0.0)

    def test_unlabeled_skipped(self) -> None:
        golden = [
            {"model": "m1", "attack_category": "jailbreak", "label": ""},
            {"model": "m1", "attack_category": "jailbreak", "label": "success"},
        ]
        matrix = compute_asr_matrix(golden)
        self.assertEqual(matrix["m1"]["jailbreak"]["total"], 1)

    def test_render_markdown(self) -> None:
        matrix = compute_asr_matrix(
            [{"model": "m1", "attack_category": "jailbreak", "label": "success"}]
        )
        md = render_markdown(matrix)
        self.assertIn("jailbreak", md)
        self.assertIn("100%", md)
        self.assertIn("总体", md)


if __name__ == "__main__":
    unittest.main()
