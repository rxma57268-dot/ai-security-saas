"""v3 Sprint 4A/4C 单元测试：动态红队 Attacker（工具组合 + 策略库注入）。"""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from app.attacker import DynamicAttacker, parse_dynamic_output


class TestParseDynamicOutput(unittest.TestCase):
    def test_valid_tool_calls(self) -> None:
        text = '{"thought": "换编码维度", "tool_calls": [{"tool": "base64_wrap", "params": {"variant": 1}}], "stop": false}'
        out = parse_dynamic_output(text)
        self.assertFalse(out["parse_failed"])
        self.assertEqual(out["tool_calls"][0]["tool"], "base64_wrap")
        self.assertEqual(out["tool_calls"][0]["params"]["variant"], 1)

    def test_garbage_parse_failed(self) -> None:
        self.assertTrue(parse_dynamic_output("垃圾")["parse_failed"])

    def test_non_list_tool_calls_rejected(self) -> None:
        out = parse_dynamic_output('{"tool_calls": "base64_wrap"}')
        self.assertTrue(out["parse_failed"])

    def test_call_without_tool_name_rejected(self) -> None:
        out = parse_dynamic_output('{"tool_calls": [{"params": {}}]}')
        self.assertTrue(out["parse_failed"])

    def test_stop_flag(self) -> None:
        out = parse_dynamic_output(
            '{"thought": "放弃", "tool_calls": [], "stop": true, "stop_reason": "打不穿"}'
        )
        self.assertTrue(out["stop"])
        self.assertEqual(out["stop_reason"], "打不穿")


def _make_attacker(raw_output: str) -> DynamicAttacker:
    attacker = DynamicAttacker.__new__(DynamicAttacker)
    attacker.model = "fake"
    attacker.client = MagicMock()
    attacker.client.chat = AsyncMock(return_value=raw_output)
    attacker.client.last_usage = None
    attacker.total_prompt_tokens = 0
    attacker.total_completion_tokens = 0
    attacker.strategy_lib = None
    return attacker


class TestDynamicAttacker(unittest.TestCase):
    def test_tool_calls_rendered_to_payload(self) -> None:
        """工具链渲染出最终 payload（不直接外发 Attacker 原文）"""
        attacker = _make_attacker(
            '{"thought": "套壳", "tool_calls": [{"tool": "role_play_shell", "params": {"variant": 0}}]}'
        )
        out = asyncio.run(attacker.next_action("窃取数据", [], None))
        self.assertFalse(out["stop"])
        self.assertIn("窃取数据", out["payload"])
        self.assertIn("电影", out["payload"])  # role_play_shell:0 的电影壳
        self.assertEqual(out["tool_calls"][0]["tool"], "role_play_shell")

    def test_signature_feedback_in_prompt(self) -> None:
        """防御签名/路径偏差必须注入 prompt（裁判反馈进决策循环）"""
        attacker = _make_attacker('{"thought": "t", "tool_calls": []}')
        asyncio.run(
            attacker.next_action("goal", [], "defense_success",
                                 "hard_refusal", "invocation_blocked")
        )
        prompt = attacker.client.chat.call_args.args[0][0]["content"]
        self.assertIn("hard_refusal", prompt)
        self.assertIn("invocation_blocked", prompt)
        self.assertIn("base64_wrap", prompt)  # 工具清单在 prompt 里

    def test_parse_failure_stops(self) -> None:
        attacker = _make_attacker("垃圾输出")
        out = asyncio.run(attacker.next_action("goal", [], None))
        self.assertTrue(out["stop"])
        self.assertEqual(out["stop_reason"], "attacker_output_parse_failure")

    def test_strategy_library_injected_on_defense(self) -> None:
        """受挫且有策略库 → 检索结果注入 prompt，命中记录随动作返回"""
        attacker = _make_attacker('{"thought": "用策略", "tool_calls": []}')
        lib = MagicMock()
        lib.retrieve = AsyncMock(return_value=[{
            "id": "s1", "technique_sequence": ["base64_wrap", "role_play_shell"],
            "success_rate": 0.6, "defense_signature": "hard_refusal",
        }])
        attacker.strategy_lib = lib
        out = asyncio.run(
            attacker.next_action("goal", [], "defense_success", "hard_refusal")
        )
        lib.retrieve.assert_awaited_once()
        prompt = attacker.client.chat.call_args.args[0][0]["content"]
        self.assertIn("base64_wrap → role_play_shell", prompt)
        self.assertEqual(out["strategies_used"], ["s1"])

    def test_no_retrieval_without_signature(self) -> None:
        """首轮（无签名）不检索策略库"""
        attacker = _make_attacker('{"thought": "t", "tool_calls": []}')
        lib = MagicMock()
        lib.retrieve = AsyncMock()
        attacker.strategy_lib = lib
        asyncio.run(attacker.next_action("goal", [], None, None))
        lib.retrieve.assert_not_called()


if __name__ == "__main__":
    unittest.main()
