"""多轮探测 Agent：ReAct 循环（Thought → Action → Observation）。

设计文档：docs/multi-turn-agent-design.md

终止条件（机械化，无主观判断）：
  1. attack_success 达成
  2. 连续 2 轮 defense_success
  3. 达到 max_rounds（默认 8，MAX_ROUNDS 环境变量）
  4. Agent 输出解析失败/动作非法 → 回落 stop

关键结构：
  - parse_agent_output(text) -> dict   防御性解析，沿用 parse_verdict 思路
  - run_probe(task_id, db) -> dict     主循环
    每轮：渲染 prompt → Agent 模型决策 → payload 发靶模型 → 双裁判判定 → 写 probe_turns
  - 发给靶模型的会话历史独立维护，完整不裁剪
  - Agent 模型配置：AGENT_MODEL env，缺省回落 JUDGE_MODEL
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Literal

from supabase import Client

from .judge import LLMJudge, RegexJudge, Verdict
from .target import TargetModel

TASKS_TABLE = "test_tasks"
TURNS_TABLE = "probe_turns"

AgentActionType = Literal["follow_up", "switch_pattern", "verify_hijack", "stop"]
_VALID_ACTIONS: tuple[str, ...] = (
    "follow_up",
    "switch_pattern",
    "verify_hijack",
    "stop",
)

MAX_ROUNDS = int(os.environ.get("MAX_ROUNDS", "8"))
COMPRESS_AFTER = 8  # Agent 思考上下文超过此轮数开始压缩
RECENT_WINDOW = 6  # 压缩时保留最近 N 轮原文

_PROMPT_TEMPLATE = (Path(__file__).parent / "agent_prompt.md").read_text(
    encoding="utf-8"
)

logger = logging.getLogger(__name__)


# ---------- 终止条件（全部为机械条件，见设计文档第 2 节修订） ----------

def should_stop(verdicts: list[Verdict], round_no: int, max_rounds: int) -> str | None:
    """返回终止原因，None 表示继续。

    - attack_success：目标达成，立即停
    - 连续 2 轮 defense_success：机械条件即停（不引入"有无新信息"主观判断）
    - 达到 max_rounds
    """
    if verdicts and verdicts[-1] == "attack_success":
        return "attack_success"
    if (
        len(verdicts) >= 2
        and verdicts[-1] == "defense_success"
        and verdicts[-2] == "defense_success"
    ):
        return "consecutive_defense_success"
    if round_no >= max_rounds:
        return "max_rounds"
    return None


# ---------- Agent 决策（ReAct 的 Thought + Action） ----------

def parse_agent_output(text: str) -> dict[str, Any]:
    """解析 Agent 模型输出，防御性校验，任何异常回落为 stop。

    与 LLMJudge.parse_verdict 同一思路：提取 JSON → 白名单校验 → 异常回落。
    两类失败区分 stop_reason（与 agent_prompt.md「代码侧防御」约定一致）：
      JSON 解析失败   → agent_output_parse_failure
      action 白名单外 → agent_output_invalid
    """

    def fallback(reason: str) -> dict[str, Any]:
        return {
            "thought": "",
            "action": "stop",
            "pattern_id": None,
            "payload": "",
            "stop": True,
            "stop_reason": reason,
        }

    try:
        cleaned = re.sub(r"```(?:json)?", "", text)
        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if not match:
            return fallback("agent_output_parse_failure")
        data = json.loads(match.group(0))
    except (json.JSONDecodeError, AttributeError, TypeError):
        return fallback("agent_output_parse_failure")

    if data.get("action") not in _VALID_ACTIONS:
        return fallback("agent_output_invalid")

    return {
        "thought": str(data.get("thought") or ""),
        "action": data["action"],
        "pattern_id": data.get("pattern_id"),
        "payload": str(data.get("payload") or ""),
        "stop": bool(data.get("stop")) or data["action"] == "stop",
        "stop_reason": str(data.get("stop_reason") or ""),
    }


async def agent_decide(
    task: dict[str, Any],
    agent_state: dict[str, Any],
    recent_turns: list[dict[str, Any]],
    candidate_patterns: list[dict[str, Any]],
) -> dict[str, Any]:
    """调 Agent 模型做一轮决策。TODO: 实现。

    prompt = _PROMPT_TEMPLATE 渲染 {goal} {agent_state} {round_no} {max_rounds}
             {recent_turns} {patterns}
    client = TargetModel(model=os.environ.get("AGENT_MODEL") or JUDGE_MODEL 缺省)
    raw = await client.chat([...], temperature=0.0)
    return parse_agent_output(raw)
    """
    raise NotImplementedError


# ---------- 上下文压缩（设计文档第 3 节） ----------

async def compress_state(
    agent_state: dict[str, Any], old_turns: list[dict[str, Any]]
) -> dict[str, Any]:
    """把旧轮次压缩进结构化状态摘要。TODO: 实现（调 Agent 模型）。

    输出结构：{goal, tried_strategies, extracted_intel, current_hypothesis,
    refusal_count}——用结构化 JSON 而非自由文本，避免丢策略信息。
    """
    raise NotImplementedError


# ---------- 主循环 ----------

async def run_probe(task_id: str, db: Client) -> dict[str, Any]:
    """对一个任务执行多轮探测，返回最终判定。

    Raises: HTTPException 404 任务不存在。
    """
    # 1. 查任务
    resp = db.table(TASKS_TABLE).select("*").eq("id", task_id).execute()
    if not resp.data:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="任务不存在")
    task = resp.data[0]

    # 2. 初始化：完整会话（发靶模型）、轮次记录、状态摘要
    conversation: list[dict[str, str]] = []  # 发靶模型的完整历史，不裁剪
    turns: list[dict[str, Any]] = []  # 含判定结果，供 Agent 思考上下文
    verdicts: list[Verdict] = []
    agent_state: dict[str, Any] = task.get("agent_state") or {}

    target = TargetModel()
    regex_judge = RegexJudge()
    llm_judge = LLMJudge()

    # 3. ReAct 循环
    for round_no in range(1, MAX_ROUNDS + 1):
        # Thought + Action：Agent 决策
        candidate_patterns: list[dict[str, Any]] = []  # TODO: 按成功率检索模式库
        action = await agent_decide(task, agent_state, turns, candidate_patterns)
        if action["stop"]:
            logger.info("Agent 主动终止: %s", action["stop_reason"])
            break

        # Action 执行：发给靶模型（完整会话历史）
        # 边界钉死：只有 payload 外发给目标模型；thought/action/stop_reason
        # 是内部状态，只进 probe_turns 表，永不进入 conversation。
        conversation.append({"role": "user", "content": action["payload"]})
        response = await target.chat(conversation)
        conversation.append({"role": "assistant", "content": response})

        # Observation：双裁判判定本轮（TODO: 复用 executor 的 both 模式逻辑，
        # 抽到公共函数，避免与 executor.py 重复维护）
        judge_context = {**task}
        regex_verdict = await regex_judge.judge(action["payload"], response, judge_context)
        # TODO: llm_verdict + verdict_source + needs_review 逻辑同 executor
        verdict: Verdict = regex_verdict
        verdicts.append(verdict)

        turns.append(
            {
                "task_id": task_id,
                "round_no": round_no,
                "agent_thought": action["thought"],
                "action": action["action"],
                "pattern_id": action["pattern_id"],
                "payload": action["payload"],
                "response": response,
                "verdict": verdict,
                "verdict_source": "regex",  # TODO: 双裁判后确定
            }
        )

        # 上下文压缩：Agent 思考上下文超窗口时
        if len(turns) > COMPRESS_AFTER:
            agent_state = await compress_state(agent_state, turns[:-RECENT_WINDOW])
            turns[:] = turns[-RECENT_WINDOW:]

        # 终止条件（机械条件）
        reason = should_stop(verdicts, round_no, MAX_ROUNDS)
        if reason:
            logger.info("探测终止: %s（第 %d 轮）", reason, round_no)
            break

    # 4. 落库 + 会话级裁判 + 写回任务（TODO）
    # db.table(TURNS_TABLE).insert(turns).execute()
    # final_verdict = await session_judge(conversation)  # 注意 prompt 注入防御定界符
    # db.table(TASKS_TABLE).update({...}).eq("id", task_id).execute()
    # TODO: 更新 attack_patterns 的 use_count / success_count

    return {
        "task_id": task_id,
        "rounds": len(turns),
        "verdicts": verdicts,
        # TODO: 会话级最终判定
    }
