"""v3 Sprint 4A 单元测试：攻击手法工具库（schema 校验 + 链执行）。"""

import asyncio
import unittest

from app.attack_tools import (
    REGISTRY,
    apply_tool_calls,
    tool_schemas_for_prompt,
    validate_chain,
)


class TestToolRegistry(unittest.TestCase):
    def test_builtin_tools_registered(self) -> None:
        self.assertEqual(
            set(REGISTRY),
            {"direct_send", "synonym_rewrite", "base64_wrap",
             "role_play_shell", "turn_split"},
        )

    def test_schemas_have_composability_fields(self) -> None:
        """锁定决策：schema 必须显式声明 composable_with / order_sensitive"""
        text = tool_schemas_for_prompt()
        self.assertIn("composable_with", text)
        self.assertIn("order_sensitive", text)
        self.assertIn("turn_split", text)


class TestValidateChain(unittest.TestCase):
    def test_single_tool_ok(self) -> None:
        self.assertEqual(
            validate_chain([{"tool": "base64_wrap", "params": {}}]), []
        )

    def test_unknown_tool_rejected(self) -> None:
        errors = validate_chain([{"tool": "sql_injection", "params": {}}])
        self.assertTrue(any("未注册" in e for e in errors))

    def test_order_sensitive_must_be_first(self) -> None:
        """turn_split 是顺序敏感工具：不在链首则违规"""
        errors = validate_chain([
            {"tool": "role_play_shell", "params": {}},
            {"tool": "turn_split", "params": {}},
        ])
        self.assertTrue(any("链首" in e for e in errors))

    def test_incompatible_combo_rejected(self) -> None:
        """base64_wrap × turn_split 不在组合白名单（编码后再拆轮无意义）"""
        errors = validate_chain([
            {"tool": "turn_split", "params": {}},
            {"tool": "base64_wrap", "params": {}},
        ])
        self.assertTrue(any("不可与" in e for e in errors))

    def test_orthogonal_combo_ok(self) -> None:
        """编码×社会工程是允许的正交组合"""
        errors = validate_chain([
            {"tool": "base64_wrap", "params": {"variant": 0}},
            {"tool": "role_play_shell", "params": {"variant": 1}},
        ])
        self.assertEqual(errors, [])


class TestApplyToolCalls(unittest.TestCase):
    def test_empty_calls_returns_original(self) -> None:
        out = asyncio.run(apply_tool_calls("原始", []))
        self.assertEqual(out, "原始")

    def test_invalid_chain_falls_back_to_original(self) -> None:
        """非法组合防御性回落原 payload（不中断探测）"""
        out = asyncio.run(
            apply_tool_calls("原始", [{"tool": "不存在的工具", "params": {}}])
        )
        self.assertEqual(out, "原始")

    def test_role_play_applied(self) -> None:
        out = asyncio.run(
            apply_tool_calls("窃取数据", [{"tool": "role_play_shell", "params": {"variant": 0}}])
        )
        self.assertIn("窃取数据", out)
        self.assertIn("电影", out)

    def test_turn_split_chain_produces_multi_turn(self) -> None:
        out = asyncio.run(apply_tool_calls(
            "恶意请求",
            [{"tool": "turn_split", "params": {"variant": 0}},
             {"tool": "synonym_rewrite", "params": {"variant": 0}}],
        ))
        self.assertIsInstance(out, list)
        self.assertEqual(len(out), 2)


if __name__ == "__main__":
    unittest.main()
