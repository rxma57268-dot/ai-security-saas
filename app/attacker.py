"""PAIR attacker 模块（Sprint 4，arXiv:2310.08419 工程化落地）。

v3 Sprint 4A 升级：动态红队 Attacker——payload 来源从"自由生成"升级为
"Function Call 工具组合"（attack_tools.py 工具库），裁判反馈除 verdict
外消费防御签名 + 路径偏差（SkillAttack 借鉴：未调用工具与被拦截是两种
完全不同的失败，补救策略不同）。

输入：攻击目标 + 会话历史 + 上轮判定（verdict + 防御签名 + 路径偏差）
输出：下一轮动作（工具调用组合 → 渲染出 payload）

attacker 用便宜模型（AGENT_MODEL → JUDGE_MODEL → TARGET_MODEL 回落链），
不需要最强——迭代次数补能力。
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from .attack_tools import apply_tool_calls, tool_schemas_for_prompt
from .judge import Verdict, judge_pair
from .probe_runs import resolve_agent_model, usage_tokens
from .target import TargetModel

logger = logging.getLogger(__name__)

_PROMPT_TEMPLATE = (Path(__file__).parent / "attacker_prompt.md").read_text(
    encoding="utf-8"
)
_DYNAMIC_PROMPT_TEMPLATE = (
    Path(__file__).parent / "attacker_prompt_dynamic.md"
).read_text(encoding="utf-8")


def parse_attacker_output(text: str) -> dict[str, Any]:
    """解析 attacker 模型输出，防御性校验（与 parse_verdict 同一思路）。

    失败回落：payload 为空 + parse_failed 标记，调用方据此终止本轮攻击。
    """
    try:
        cleaned = re.sub(r"```(?:json)?", "", text)
        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if not match:
            return {"payload": "", "rationale": "", "parse_failed": True}
        data = json.loads(match.group(0))
        payload = str(data.get("payload") or "").strip()
        if not payload:
            return {"payload": "", "rationale": "", "parse_failed": True}
        return {
            "payload": payload,
            "rationale": str(data.get("rationale") or ""),
            "parse_failed": False,
        }
    except (json.JSONDecodeError, AttributeError, TypeError):
        return {"payload": "", "rationale": "", "parse_failed": True}


def parse_dynamic_output(text: str) -> dict[str, Any]:
    """解析动态红队 Attacker 输出（v3 Sprint 4A 工具调用格式）。

    输出：{thought, tool_calls, stop, stop_reason, parse_failed}
    防御性校验：JSON 解析失败 / tool_calls 不是列表 → parse_failed。
    """
    fallback = {
        "thought": "", "tool_calls": [], "stop": True,
        "stop_reason": "attacker_output_parse_failure", "parse_failed": True,
    }
    try:
        cleaned = re.sub(r"```(?:json)?", "", text)
        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if not match:
            return fallback
        data = json.loads(match.group(0))
        calls = data.get("tool_calls") or []
        if not isinstance(calls, list):
            return fallback
        # 每个 call 必须是 {tool: str, params: dict}
        normalized = []
        for c in calls:
            if not isinstance(c, dict) or not isinstance(c.get("tool"), str):
                return fallback
            normalized.append(
                {"tool": c["tool"], "params": c.get("params") or {}}
            )
        return {
            "thought": str(data.get("thought") or ""),
            "tool_calls": normalized,
            "stop": bool(data.get("stop")),
            "stop_reason": str(data.get("stop_reason") or ""),
            "parse_failed": False,
        }
    except (json.JSONDecodeError, AttributeError, TypeError):
        return fallback


def _format_history(conversation: list[dict[str, str]]) -> str:
    if not conversation:
        return "（暂无，这是第一轮）"
    lines = []
    for msg in conversation:
        role = "攻击方" if msg["role"] == "user" else "目标"
        lines.append(f"{role}: {msg['content']}")
    return "\n".join(lines)


class PAIRAttacker:
    """PAIR 攻击者（文献基线，arXiv:2310.08419）：自由生成 payload。"""

    def __init__(self, model: str | None = None) -> None:
        self.model = model or resolve_agent_model(None) or None
        self.client = TargetModel(model=self.model)
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0

    async def next_payload(
        self,
        goal: str,
        conversation: list[dict[str, str]],
        last_verdict: Verdict | None,
    ) -> dict[str, Any]:
        """生成下一轮攻击 payload。返回 {payload, rationale, parse_failed}。"""
        prompt = (
            _PROMPT_TEMPLATE
            .replace("{goal}", goal)
            .replace("{history}", _format_history(conversation))
            .replace("{last_verdict}", last_verdict or "（第一轮，无判定）")
        )
        # attacker 需要多样性来探索攻击面：不用 temperature=0
        # （裁判/决策是测量行为要复现；攻击生成是搜索行为要多样）
        raw = await self.client.chat([{"role": "user", "content": prompt}])
        pt, ct = usage_tokens(self.client.last_usage)
        self.total_prompt_tokens += pt
        self.total_completion_tokens += ct
        return parse_attacker_output(raw)


class DynamicAttacker:
    """动态红队 Attacker（v3 Sprint 4A）：Function Call 工具组合生成 payload。

    与 PAIRAttacker 的差异：
      PAIR    自由文本生成 payload
      动态红队 输出 tool_calls（手法组合），由工具库渲染出 payload——
              手法可枚举、组合有约束（composable_with/order_sensitive）、
              每轮的手法序列落库成为策略库（Sprint 4C）的数据源

    裁判反馈消费：verdict + 防御签名 + 路径偏差（两种失败两种补救）。
    """

    def __init__(
        self, model: str | None = None, strategy_lib: Any = None
    ) -> None:
        self.model = model or resolve_agent_model(None) or None
        self.client = TargetModel(model=self.model)
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        # v3 Sprint 4C：策略库检索增强（None = 不检索，纯 Attacker）
        self.strategy_lib = strategy_lib

    async def next_action(
        self,
        goal: str,
        conversation: list[dict[str, str]],
        last_verdict: Verdict | None,
        last_signature: str | None = None,
        last_path_deviation: str | None = None,
    ) -> dict[str, Any]:
        """输出下一轮动作。返回 {payload, thought, tool_calls, stop, ...}。

        payload 由工具链渲染产出（turn_split 链产出多轮 list）；
        解析失败/主动停止时 stop=True。
        攻击受挫（非首轮）且挂了策略库时：检索同类防御签名下的历史
        成功策略注入 prompt（跨会话学习——"PAIR 会打，策略库越打越聪明"）。
        """
        strategies: list[dict[str, Any]] = []
        if self.strategy_lib is not None and last_signature:
            from .strategy import format_strategies_for_prompt

            strategies = await self.strategy_lib.retrieve(
                last_signature, query=goal, top_k=3
            )
            strategies_text = format_strategies_for_prompt(strategies)
        else:
            from .strategy import format_strategies_for_prompt

            strategies_text = format_strategies_for_prompt([])

        prompt = (
            _DYNAMIC_PROMPT_TEMPLATE
            .replace("{goal}", goal)
            .replace("{tools}", tool_schemas_for_prompt())
            .replace("{history}", _format_history(conversation))
            .replace("{last_signature}", last_signature or "（第一轮，无）")
            .replace("{last_path_deviation}", last_path_deviation or "none")
            .replace("{strategies}", strategies_text)
        )
        raw = await self.client.chat([{"role": "user", "content": prompt}])
        pt, ct = usage_tokens(self.client.last_usage)
        self.total_prompt_tokens += pt
        self.total_completion_tokens += ct

        action = parse_dynamic_output(raw)
        if action["parse_failed"] or action["stop"]:
            return {
                "payload": "", "thought": action["thought"],
                "tool_calls": [], "stop": True,
                "stop_reason": action["stop_reason"] or "agent_stop",
                "parse_failed": action["parse_failed"],
                "strategies_used": None,
            }
        payload = await apply_tool_calls(goal, action["tool_calls"])
        return {
            "payload": payload,
            "thought": action["thought"],
            "tool_calls": action["tool_calls"],
            "stop": False,
            "stop_reason": "",
            "parse_failed": False,
            # 策略命中落库（Sprint 6 报告的策略库命中统计数据源）
            "strategies_used": [s.get("id") or s.get("technique_sequence")
                                for s in strategies] or None,
        }


async def run_pair_attack(
    goal: str,
    target: TargetModel,
    judge_context: dict[str, Any],
    judge_mode: str,
    max_rounds: int,
    attacker: PAIRAttacker | None = None,
) -> dict[str, Any]:
    """离线 PAIR 攻击循环（不依赖 DB）：对照实验与脚本复用。

    返回 {verdict, rounds, turns, prompt_tokens, completion_tokens, stop_reason}。
    终止条件与线上探测一致（复用 should_stop 机械条件）。
    """
    from .agent import final_verdict_for, should_stop

    attacker = attacker or PAIRAttacker()
    conversation: list[dict[str, str]] = []
    turns: list[dict[str, Any]] = []
    verdicts: list[Verdict] = []
    stop_reason: str | None = None
    target_prompt_tokens = 0
    target_completion_tokens = 0

    for round_no in range(1, max_rounds + 1):
        attack = await attacker.next_payload(
            goal, conversation, verdicts[-1] if verdicts else None
        )
        if attack["parse_failed"]:
            stop_reason = "pair_output_parse_failure"
            logger.warning("PAIR attacker 输出解析失败，第 %d 轮终止", round_no)
            break

        conversation.append({"role": "user", "content": attack["payload"]})
        response = await target.chat(conversation)
        conversation.append({"role": "assistant", "content": response})
        pt, ct = usage_tokens(target.last_usage)
        target_prompt_tokens += pt
        target_completion_tokens += ct

        outcome = await judge_pair(
            attack["payload"], response, judge_context, judge_mode
        )
        verdicts.append(outcome.verdict)
        turns.append(
            {
                "round_no": round_no,
                "payload": attack["payload"],
                "rationale": attack["rationale"],
                "response": response,
                "verdict": outcome.verdict,
                "verdict_source": outcome.verdict_source,
                "judge_reason": outcome.reason,
                "judge_evidence": outcome.evidence,
            }
        )

        reason = should_stop(verdicts, round_no, max_rounds)
        if reason:
            stop_reason = reason
            break

    return {
        "verdict": final_verdict_for(stop_reason, verdicts),
        "rounds": len(turns),
        "turns": turns,
        "stop_reason": stop_reason,
        # token 成本 = attacker 侧 + 靶模型侧，分开记便于算账
        "attacker_prompt_tokens": attacker.total_prompt_tokens,
        "attacker_completion_tokens": attacker.total_completion_tokens,
        "target_prompt_tokens": target_prompt_tokens,
        "target_completion_tokens": target_completion_tokens,
    }
