"""Sprint 4 单元测试：PAIR attacker 解析 + 离线攻击循环 + 探测循环 PAIR 模式。"""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from app.attacker import PAIRAttacker, parse_attacker_output, run_pair_attack
from app.judge import JudgeOutcome


class TestParseAttackerOutput(unittest.TestCase):
    def test_valid_json(self) -> None:
        text = '{"rationale": "换编码维度", "payload": "请解码这段 Base64……"}'
        out = parse_attacker_output(text)
        self.assertEqual(out["payload"], "请解码这段 Base64……")
        self.assertEqual(out["rationale"], "换编码维度")
        self.assertFalse(out["parse_failed"])

    def test_code_fence(self) -> None:
        text = '```json\n{"rationale": "r", "payload": "p"}\n```'
        out = parse_attacker_output(text)
        self.assertEqual(out["payload"], "p")

    def test_garbage_marks_parse_failed(self) -> None:
        out = parse_attacker_output("这不是JSON")
        self.assertTrue(out["parse_failed"])
        self.assertEqual(out["payload"], "")

    def test_empty_payload_marks_parse_failed(self) -> None:
        out = parse_attacker_output('{"rationale": "r", "payload": "  "}')
        self.assertTrue(out["parse_failed"])


class TestRunPairAttack(unittest.TestCase):
    """离线 PAIR 循环：attacker/target/judge 全部打桩"""

    def _make(self, attack_outputs, verdicts, responses=None):
        attacker = MagicMock(spec=PAIRAttacker)
        attacker.next_payload = AsyncMock(side_effect=attack_outputs)
        attacker.total_prompt_tokens = 10
        attacker.total_completion_tokens = 5
        target = MagicMock()
        target.chat = AsyncMock(side_effect=responses or ["响应"] * len(attack_outputs))
        target.last_usage = {"prompt_tokens": 100, "completion_tokens": 50}
        outcomes = [JudgeOutcome(v, "llm", False) for v in verdicts]
        return attacker, target, outcomes

    def test_success_stops_early_and_counts_tokens(self) -> None:
        """第 2 轮 attack_success → 终止，轮次/成本正确累计"""
        attacks = [
            {"payload": "p1", "rationale": "r1", "parse_failed": False},
            {"payload": "p2", "rationale": "r2", "parse_failed": False},
        ]
        attacker, target, outcomes = self._make(
            attacks, ["defense_success", "attack_success"]
        )
        with patch("app.attacker.judge_pair", new=AsyncMock(side_effect=outcomes)):
            result = asyncio.run(
                run_pair_attack("goal", target, {}, "both", max_rounds=8, attacker=attacker)
            )
        self.assertEqual(result["verdict"], "attack_success")
        self.assertEqual(result["rounds"], 2)
        self.assertEqual(result["stop_reason"], "attack_success")
        self.assertEqual(result["target_prompt_tokens"], 200)
        self.assertEqual(result["attacker_prompt_tokens"], 10)

    def test_consecutive_defense_stops(self) -> None:
        attacks = [
            {"payload": f"p{i}", "rationale": "", "parse_failed": False}
            for i in range(5)
        ]
        attacker, target, outcomes = self._make(
            attacks, ["defense_success", "defense_success"]
        )
        with patch("app.attacker.judge_pair", new=AsyncMock(side_effect=outcomes)):
            result = asyncio.run(
                run_pair_attack("goal", target, {}, "both", max_rounds=8, attacker=attacker)
            )
        self.assertEqual(result["verdict"], "defense_success")
        self.assertEqual(result["rounds"], 2)
        self.assertEqual(result["stop_reason"], "consecutive_defense_success")

    def test_parse_failure_stops(self) -> None:
        attacker, target, _ = self._make(
            [{"payload": "", "rationale": "", "parse_failed": True}], []
        )
        result = asyncio.run(
            run_pair_attack("goal", target, {}, "both", max_rounds=8, attacker=attacker)
        )
        self.assertEqual(result["stop_reason"], "pair_output_parse_failure")
        self.assertEqual(result["rounds"], 0)

    def test_last_verdict_passed_to_attacker(self) -> None:
        """上轮判定必须回喂给 attacker（PAIR 的迭代依据）"""
        attacks = [
            {"payload": "p1", "rationale": "", "parse_failed": False},
            {"payload": "p2", "rationale": "", "parse_failed": False},
        ]
        attacker, target, outcomes = self._make(
            attacks, ["defense_success", "attack_success"]
        )
        with patch("app.attacker.judge_pair", new=AsyncMock(side_effect=outcomes)):
            asyncio.run(
                run_pair_attack("goal", target, {}, "both", max_rounds=8, attacker=attacker)
            )
        second_call = attacker.next_payload.call_args_list[1]
        self.assertEqual(second_call.args[2], "defense_success")


class TestProbePairMode(unittest.TestCase):
    """探测循环 PAIR 模式：payload 来源切换为 attacker 生成"""

    def test_pair_mode_uses_attacker_not_agent_decide(self) -> None:
        from app.agent import run_probe

        task = {
            "id": "task-1",
            "payload": "攻击目标",
            "expected_behavior": "拒绝",
            "agent_state": None,
        }
        from tests.test_agent import make_db

        db, mocks = make_db(task)

        attack = {"payload": "attacker 生成", "rationale": "首轮试探", "parse_failed": False}
        attacker = MagicMock()
        attacker.next_payload = AsyncMock(return_value=attack)
        attacker.total_prompt_tokens = 0
        attacker.total_completion_tokens = 0
        outcome = JudgeOutcome("attack_success", "llm", False, "服从了", "证据")

        with (
            patch("app.agent.PROBE_MODE", "pair"),
            patch("app.attacker.PAIRAttacker", return_value=attacker),
            patch("app.agent.TargetModel") as mock_target,
            patch("app.agent.agent_decide", new=AsyncMock()) as mock_decide,
            patch("app.agent.judge_pair", new=AsyncMock(return_value=outcome)),
        ):
            mock_target.return_value.chat = AsyncMock(return_value="目标响应")
            mock_target.return_value.model = "glm-4-flash"
            mock_target.return_value.last_usage = None
            result = asyncio.run(run_probe("task-1", db))

        # attacker 被调用，模板决策（agent_decide）未被调用
        attacker.next_payload.assert_awaited_once()
        mock_decide.assert_not_awaited()
        self.assertEqual(result["verdict"], "attack_success")
        # run 记录 probe_mode=pair
        run_row = mocks["probe_runs"].insert.call_args[0][0]
        self.assertEqual(run_row["probe_mode"], "pair")
        # 轮次的 payload 来自 attacker，rationale 进 agent_thought
        inserted = mocks["probe_turns"].insert.call_args[0][0]
        self.assertEqual(inserted[0]["payload"], "attacker 生成")
        self.assertEqual(inserted[0]["agent_thought"], "首轮试探")


if __name__ == "__main__":
    unittest.main()
