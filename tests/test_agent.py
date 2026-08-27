"""Agent 单元测试：parse_agent_output 防御解析 + should_stop 终止条件。

运行方式：python -m unittest discover tests -v
"""

import unittest

from app.agent import parse_agent_output, should_stop


class TestParseAgentOutput(unittest.TestCase):
    """Agent 输出防御性解析（不调模型，纯本地）"""

    def test_valid_json(self) -> None:
        """合法 JSON → 正常解析"""
        text = '{"thought": "继续追问", "action": "follow_up", "pattern_id": null, "payload": "下一步呢？"}'
        result = parse_agent_output(text)
        self.assertEqual(result["action"], "follow_up")
        self.assertEqual(result["payload"], "下一步呢？")
        self.assertFalse(result["stop"])

    def test_json_in_code_fence(self) -> None:
        """带 ```json 围栏 → 正常解析"""
        text = '```json\n{"thought": "t", "action": "switch_pattern", "pattern_id": "abc", "payload": "x"}\n```'
        result = parse_agent_output(text)
        self.assertEqual(result["action"], "switch_pattern")
        self.assertEqual(result["pattern_id"], "abc")

    def test_invalid_action_returns_stop_invalid(self) -> None:
        """白名单外的自创 action（如 try_harder）→ stop + agent_output_invalid"""
        text = '{"thought": "t", "action": "try_harder", "payload": "x"}'
        result = parse_agent_output(text)
        self.assertEqual(result["action"], "stop")
        self.assertTrue(result["stop"])
        self.assertEqual(result["stop_reason"], "agent_output_invalid")

    def test_garbage_returns_stop_parse_failure(self) -> None:
        """垃圾输入 → stop + agent_output_parse_failure"""
        result = parse_agent_output("这不是JSON")
        self.assertEqual(result["action"], "stop")
        self.assertTrue(result["stop"])
        self.assertEqual(result["stop_reason"], "agent_output_parse_failure")

    def test_stop_action_forces_stop_flag(self) -> None:
        """action=stop 时即使 stop 字段为 false 也强制 stop"""
        text = '{"thought": "放弃", "action": "stop", "stop": false, "stop_reason": "无法突破"}'
        result = parse_agent_output(text)
        self.assertTrue(result["stop"])
        self.assertEqual(result["stop_reason"], "无法突破")


class TestShouldStop(unittest.TestCase):
    """终止条件（全部为机械条件）"""

    def test_attack_success_stops(self) -> None:
        self.assertEqual(should_stop(["attack_success"], 1, 8), "attack_success")

    def test_consecutive_defense_success_stops(self) -> None:
        self.assertEqual(
            should_stop(["defense_success", "defense_success"], 2, 8),
            "consecutive_defense_success",
        )

    def test_max_rounds_stops(self) -> None:
        self.assertEqual(should_stop(["uncertain"] * 8, 8, 8), "max_rounds")

    def test_single_defense_does_not_stop(self) -> None:
        """单次 defense_success 不停（不引入主观判断）"""
        self.assertIsNone(should_stop(["uncertain", "defense_success"], 2, 8))

    def test_empty_verdicts_does_not_stop(self) -> None:
        self.assertIsNone(should_stop([], 1, 8))


if __name__ == "__main__":
    unittest.main()
