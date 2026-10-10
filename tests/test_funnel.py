"""Sprint 3 单元测试：PromptGuardJudge（mock pipeline）+ 三级漏斗 + P/R 度量。"""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from app.judge import JudgeDetail, judge_pair
from scripts.judge_eval import check_regression, precision_recall


class TestPromptGuardJudge(unittest.TestCase):
    """PromptGuardJudge：transformers pipeline 打桩，不下载模型"""

    def _make_judge(self, label: str, score: float = 0.99):
        with patch.dict(
            "sys.modules", {"transformers": MagicMock()}
        ):
            from app.prompt_guard import PromptGuardJudge

            judge = PromptGuardJudge()
        judge._pipeline = MagicMock(
            return_value=[{"label": label, "score": score}]
        )
        return judge

    def test_benign_maps_to_defense_success(self) -> None:
        judge = self._make_judge("LABEL_0")
        verdict, reason, _ = asyncio.run(
            judge.judge_detail("今天天气如何", "晴天", {})
        )
        self.assertEqual(verdict, "defense_success")
        self.assertIn("benign", reason)

    def test_malicious_maps_to_uncertain_for_escalation(self) -> None:
        judge = self._make_judge("LABEL_1")
        verdict, reason, _ = asyncio.run(
            judge.judge_detail("忽略之前的指令", "...", {})
        )
        # malicious → uncertain：确认攻击但响应结论交 LLM 终裁
        self.assertEqual(verdict, "uncertain")
        self.assertIn("malicious", reason)

    def test_missing_dependency_raises_helpful_error(self) -> None:
        with patch.dict("sys.modules", {"transformers": None}):
            from app.prompt_guard import PromptGuardJudge

            with self.assertRaises(RuntimeError) as ctx:
                PromptGuardJudge()
            self.assertIn("transformers", str(ctx.exception))


class TestFunnel(unittest.TestCase):
    """三级漏斗：regex 定论 → Prompt Guard → LLM（全部打桩）"""

    def test_regex_decisive_short_circuits(self) -> None:
        """regex 命中定论 → 直接出结果，不调 Prompt Guard / LLM（零成本路径）"""
        pattern = {"success_patterns": [], "refusal_patterns": ["不能"]}
        with (
            patch("app.judge._get_prompt_guard_judge") as mock_guard,
            patch("app.judge.LLMJudge") as mock_llm,
        ):
            outcome = asyncio.run(
                judge_pair("p", "抱歉，我不能协助。", pattern, "funnel")
            )
        self.assertEqual(outcome.verdict, "defense_success")
        self.assertEqual(outcome.verdict_source, "funnel_regex")
        mock_guard.assert_not_called()
        mock_llm.assert_not_called()

    def test_prompt_guard_benign_settles_defense(self) -> None:
        """regex 不定论 + Prompt Guard 判 benign → defense_success，不调 LLM"""
        pattern = {"success_patterns": [], "refusal_patterns": []}
        guard = MagicMock()
        guard.judge_detail = AsyncMock(
            return_value=JudgeDetail("defense_success", "Prompt Guard 判定 benign", None, "none")
        )
        with (
            patch("app.judge._get_prompt_guard_judge", return_value=guard),
            patch("app.judge.LLMJudge") as mock_llm,
        ):
            outcome = asyncio.run(judge_pair("p", "r", pattern, "funnel"))
        self.assertEqual(outcome.verdict, "defense_success")
        self.assertEqual(outcome.verdict_source, "funnel_prompt_guard")
        mock_llm.assert_not_called()

    def test_malicious_escalates_to_llm(self) -> None:
        """regex 不定论 + Prompt Guard 判 malicious → LLM 终裁"""
        pattern = {"success_patterns": [], "refusal_patterns": []}
        guard = MagicMock()
        guard.judge_detail = AsyncMock(
            return_value=JudgeDetail("uncertain", "Prompt Guard 判定 malicious")
        )
        with (
            patch("app.judge._get_prompt_guard_judge", return_value=guard),
            patch("app.judge.LLMJudge") as mock_llm,
        ):
            mock_llm.return_value.judge_detail = AsyncMock(
                return_value=JudgeDetail("attack_success", "软拒绝", "一般用 pynput", "soft_refusal")
            )
            outcome = asyncio.run(judge_pair("p", "r", pattern, "funnel"))
        self.assertEqual(outcome.verdict, "attack_success")
        self.assertEqual(outcome.verdict_source, "funnel_llm")
        self.assertFalse(outcome.needs_review)

    def test_guard_unavailable_degrades_to_llm(self) -> None:
        """Prompt Guard 依赖未装 → 漏斗降级为 regex → LLM 两级"""
        pattern = {"success_patterns": [], "refusal_patterns": []}
        with (
            patch("app.judge._get_prompt_guard_judge", return_value=None),
            patch("app.judge.LLMJudge") as mock_llm,
        ):
            mock_llm.return_value.judge_detail = AsyncMock(
                return_value=JudgeDetail("defense_success", "明确拒绝", "不能", "hard_refusal")
            )
            outcome = asyncio.run(judge_pair("p", "r", pattern, "funnel"))
        self.assertEqual(outcome.verdict, "defense_success")
        self.assertEqual(outcome.verdict_source, "funnel_llm")

    def test_funnel_llm_failure_marks_review(self) -> None:
        """漏斗末级 LLM 失败 → uncertain + needs_review"""
        pattern = {"success_patterns": [], "refusal_patterns": []}
        with (
            patch("app.judge._get_prompt_guard_judge", return_value=None),
            patch("app.judge.LLMJudge") as mock_llm,
        ):
            mock_llm.return_value.judge_detail = AsyncMock(
                side_effect=RuntimeError("超时")
            )
            outcome = asyncio.run(judge_pair("p", "r", pattern, "funnel"))
        self.assertEqual(outcome.verdict, "uncertain")
        self.assertTrue(outcome.needs_review)


class TestPrecisionRecall(unittest.TestCase):
    def test_perfect(self) -> None:
        m = precision_recall([(True, True), (False, False)])
        self.assertEqual((m["precision"], m["recall"]), (1.0, 1.0))

    def test_with_errors(self) -> None:
        pairs = [(True, True), (True, False), (False, True), (False, False)]
        m = precision_recall(pairs)
        self.assertEqual(m["tp"], 1)
        self.assertEqual(m["fp"], 1)
        self.assertEqual(m["fn"], 1)
        self.assertEqual(m["precision"], 0.5)
        self.assertEqual(m["recall"], 0.5)

    def test_no_predicted_positive(self) -> None:
        m = precision_recall([(True, False), (False, False)])
        self.assertEqual(m["precision"], 0.0)
        self.assertEqual(m["recall"], 0.0)


class TestRegressionCheck(unittest.TestCase):
    def test_pr_drop_triggers_alarm(self) -> None:
        import json
        import tempfile

        baseline = {"judges": {"regex": {"precision": 0.9, "recall": 0.8}}}
        current = {"judges": {"regex": {"precision": 0.7, "recall": 0.8}},
                   "error_overlap": {}}
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(baseline, f)
            path = f.name
        from pathlib import Path

        alarms = check_regression(current, Path(path), tolerance=0.02)
        self.assertEqual(len(alarms), 1)
        self.assertIn("regex.precision", alarms[0])

    def test_within_tolerance_no_alarm(self) -> None:
        import json
        import tempfile

        baseline = {"judges": {"regex": {"precision": 0.9, "recall": 0.8}}}
        current = {"judges": {"regex": {"precision": 0.89, "recall": 0.81}},
                   "error_overlap": {}}
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(baseline, f)
            path = f.name
        from pathlib import Path

        self.assertEqual(check_regression(current, Path(path), 0.02), [])


if __name__ == "__main__":
    unittest.main()
