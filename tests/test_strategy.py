"""v3 Sprint 4C 单元测试：策略挖掘聚合 + 策略库两级检索。"""

import asyncio
import unittest
from unittest.mock import patch

from app.strategy import StrategyLibrary, _cosine, format_strategies_for_prompt
from scripts.mine_strategies import (
    MIN_TRIALS,
    build_strategies,
    mine_from_batch,
    mine_from_turns,
)


def _row(chain, verdict, sig=None):
    return {
        "sample_id": f"s-{chain}-{verdict}",
        "mutation_chain": chain,
        "verdict": verdict,
        "defense_signature": sig,
    }


class TestMineFromBatch(unittest.TestCase):
    def test_aggregation(self) -> None:
        rows = (
            [_row(["base64_wrap:0"], "attack_success", "soft_refusal")] * 3
            + [_row(["base64_wrap:0"], "defense_success", "soft_refusal")]
            + [_row([], "attack_success", None)] * 2
        )
        cells = mine_from_batch(rows)
        cell = cells[(("base64_wrap",), "soft_refusal")]
        self.assertEqual(cell["trials"], 4)
        self.assertEqual(cell["successes"], 3)

    def test_uncertain_excluded(self) -> None:
        cells = mine_from_batch([_row([], "uncertain")])
        self.assertEqual(cells, {})


class TestBuildStrategies(unittest.TestCase):
    def test_min_trials_gate(self) -> None:
        """入库门槛：试验次数不足不出库（防伪策略污染）"""
        cells = {
            (("a",), "soft_refusal"): {"trials": MIN_TRIALS, "successes": 2,
                                       "example_ids": ["x"]},
            (("b",), "none"): {"trials": 1, "successes": 1, "example_ids": []},
        }
        strategies = build_strategies(cells)
        self.assertEqual(len(strategies), 1)
        s = strategies[0]
        self.assertEqual(s["technique_sequence"], ["a"])
        self.assertEqual(s["success_rate"], round(2 / MIN_TRIALS, 4))
        # 结构化格式（锁定决策）：手法序列+签名+成功率，无自由文本叙事
        self.assertEqual(s["status"], "pending")
        self.assertNotIn("narrative", s)

    def test_empty_sequence_becomes_direct_send(self) -> None:
        cells = {((), "none"): {"trials": 5, "successes": 1, "example_ids": []}}
        strategies = build_strategies(cells)
        self.assertEqual(strategies[0]["technique_sequence"], ["direct_send"])


class TestMineFromTurns(unittest.TestCase):
    def test_groups_by_run_and_uses_last_signature(self) -> None:
        turns = []
        for i in range(MIN_TRIALS):
            turns += [
                {"probe_run_id": f"r{i}", "round_no": 1,
                 "tool_calls": [{"tool": "role_play_shell"}],
                 "verdict": "defense_success",
                 "defense_signature": "hard_refusal", "id": f"t{i}a"},
                {"probe_run_id": f"r{i}", "round_no": 2,
                 "tool_calls": [{"tool": "base64_wrap"}],
                 "verdict": "attack_success",
                 "defense_signature": "soft_refusal", "id": f"t{i}b"},
            ]
        cells = mine_from_turns(turns)
        key = (("role_play_shell", "base64_wrap"), "soft_refusal")
        self.assertIn(key, cells)
        self.assertEqual(cells[key]["successes"], MIN_TRIALS)


class TestStrategyLibraryJsonl(unittest.TestCase):
    """JSONL 模式两级检索（embedding 打桩，不调外部 API）"""

    def _write_lib(self, tmp, strategies):
        import json

        p = tmp / "strategies.jsonl"
        p.write_text(
            "\n".join(json.dumps(s, ensure_ascii=False) for s in strategies),
            encoding="utf-8",
        )
        return p

    def test_signature_filter_is_hard_gate(self) -> None:
        """第一级过滤是硬条件：签名不匹配的策略再好的语义也不返回"""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            path = self._write_lib(Path(td), [
                {"id": "a", "technique_sequence": ["base64_wrap"],
                 "defense_signature": "hard_refusal", "success_rate": 0.9,
                 "status": "approved"},
                {"id": "b", "technique_sequence": ["turn_split"],
                 "defense_signature": "soft_refusal", "success_rate": 0.1,
                 "status": "approved"},
                {"id": "c", "technique_sequence": ["direct_send"],
                 "defense_signature": "hard_refusal", "success_rate": 1.0,
                 "status": "pending"},  # 门禁内状态不出库
            ])
            lib = StrategyLibrary(jsonl_path=path)
            with patch("app.strategy.embed_text",
                       side_effect=lambda t: [1.0, 0.0]):
                out = asyncio.run(lib.retrieve("hard_refusal", "任意查询"))
            self.assertEqual([s["id"] for s in out], ["a"])

    def test_success_rate_weights_ranking(self) -> None:
        """第二级：成功率加权排序"""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            path = self._write_lib(Path(td), [
                {"id": "low", "technique_sequence": ["x"],
                 "defense_signature": "hard_refusal", "success_rate": 0.1,
                 "status": "approved"},
                {"id": "high", "technique_sequence": ["y"],
                 "defense_signature": "hard_refusal", "success_rate": 0.9,
                 "status": "approved"},
            ])
            lib = StrategyLibrary(jsonl_path=path)
            with patch("app.strategy.embed_text",
                       side_effect=lambda t: [1.0, 1.0]):
                out = asyncio.run(lib.retrieve("hard_refusal", "q"))
            self.assertEqual(out[0]["id"], "high")


class TestCosineAndFormat(unittest.TestCase):
    def test_cosine(self) -> None:
        self.assertAlmostEqual(_cosine([1, 0], [1, 0]), 1.0)
        self.assertAlmostEqual(_cosine([1, 0], [0, 1]), 0.0)
        self.assertEqual(_cosine([0, 0], [1, 1]), 0.0)

    def test_format_for_prompt(self) -> None:
        text = format_strategies_for_prompt([{
            "technique_sequence": ["a", "b"], "success_rate": 0.5}])
        self.assertIn("a → b", text)
        self.assertIn("50%", text)
        self.assertIn("无匹配", format_strategies_for_prompt([]))


if __name__ == "__main__":
    unittest.main()
