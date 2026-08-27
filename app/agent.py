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

import httpx
from supabase import Client

from .executor import (
    JUDGE_MODE,
    _fail_result,
    _is_platform_content_filter,
    _update_task,
)
from .judge import Verdict, judge_pair
from .target import TargetModel

TASKS_TABLE = "test_tasks"
TURNS_TABLE = "probe_turns"
PATTERNS_TABLE = "attack_patterns"

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


def _format_turns(turns: list[dict[str, Any]]) -> str:
    """最近轮次渲染为 Agent 可读的文本（含裁判结果，供策略推理）。"""
    if not turns:
        return "（暂无，这是第一轮）"
    lines = []
    for t in turns:
        lines.append(
            f"第{t['round_no']}轮 | 动作:{t['action']} | payload: {t['payload']}\n"
            f"  目标响应: {t.get('response') or ''}\n"
            f"  裁判: {t.get('verdict')}（来源 {t.get('verdict_source')}）"
        )
    return "\n".join(lines)


def _format_patterns(patterns: list[dict[str, Any]]) -> str:
    """候选模式序列化进 prompt（MVP：id+name+attack_category 三字段 JSON）。"""
    if not patterns:
        return "（模式库无候选，自由发挥）"
    return json.dumps(patterns, ensure_ascii=False, indent=2)


def fetch_candidate_patterns(db: Client) -> list[dict[str, Any]]:
    """候选模式检索（MVP）：全量拉取模式库（当前 11 条）。

    一次拉取零成本，字段带全：裁判需要 success_patterns/refusal_patterns，
    任务写回需要 default_severity。
    RLS 保证只能读到当前用户的模式。
    TODO(Phase 2): 按 success_count/use_count 历史成功率排序取 top K。
    """
    resp = (
        db.table(PATTERNS_TABLE)
        .select(
            "id,name,attack_category,attack_sub_type,"
            "success_patterns,refusal_patterns,default_severity"
        )
        .execute()
    )
    return resp.data or []


async def agent_decide(
    task: dict[str, Any],
    agent_state: dict[str, Any],
    recent_turns: list[dict[str, Any]],
    candidate_patterns: list[dict[str, Any]],
    round_no: int,
) -> dict[str, Any]:
    """调 Agent 模型做一轮决策（ReAct 的 Thought + Action）。

    模型配置：AGENT_MODEL env，缺省回落 JUDGE_MODEL，再缺省回落 TARGET_MODEL；
    temperature=0——决策和裁判一样是测量行为，需要可复现。
    TODO: goal 目前用任务 payload 充当攻击目标描述，任务模型后续可加独立 goal 字段。
    """
    prompt = (
        _PROMPT_TEMPLATE
        .replace("{goal}", str(task.get("payload") or ""))
        .replace(
            "{agent_state}",
            json.dumps(agent_state, ensure_ascii=False) if agent_state else "（无，第一轮）",
        )
        .replace("{round_no}", str(round_no))
        .replace("{max_rounds}", str(MAX_ROUNDS))
        .replace("{recent_turns}", _format_turns(recent_turns))
        .replace("{patterns}", _format_patterns(candidate_patterns))
    )
    model = os.environ.get("AGENT_MODEL") or os.environ.get("JUDGE_MODEL")
    client = TargetModel(model=model)  # model=None 时 TargetModel 回落 TARGET_MODEL
    raw = await client.chat([{"role": "user", "content": prompt}], temperature=0.0)
    return parse_agent_output(raw)


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

    # 2. 状态机流转：→ 执行中（与 executor 单轮语义一致）
    _update_task(db, task_id, {"status": "执行中"})

    try:
        return await _probe_loop(task_id, task, db)
    except Exception as e:
        # 任何未处理异常 → 任务记失败（与单轮 execute 的失败语义一致），
        # 错误信息写入 actual_behavior 便于排查
        return _fail_result(task_id, db, e)


async def _probe_loop(task_id: str, task: dict[str, Any], db: Client) -> dict[str, Any]:
    """ReAct 主循环 + 落库。异常由 run_probe 统一兜底为任务失败。"""
    # 初始化：完整会话（发靶模型）、轮次记录、状态摘要
    conversation: list[dict[str, str]] = []  # 发靶模型的完整历史，不裁剪
    turns: list[dict[str, Any]] = []  # 含判定结果，供 Agent 思考上下文
    verdicts: list[Verdict] = []
    agent_state: dict[str, Any] = task.get("agent_state") or {}

    target = TargetModel()
    last_verdict_source: str | None = None
    last_needs_review = False

    # 候选模式检索：一次拉取（探测期间模式库不变，无需每轮查）
    candidate_patterns = fetch_candidate_patterns(db)

    # ReAct 循环
    for round_no in range(1, MAX_ROUNDS + 1):
        # Thought + Action：Agent 决策
        action = await agent_decide(
            task, agent_state, turns, candidate_patterns, round_no
        )
        if action["stop"]:
            logger.info("Agent 主动终止: %s", action["stop_reason"])
            break

        # Action 执行：发给靶模型（完整会话历史）
        # 边界钉死：只有 payload 外发给目标模型；thought/action/stop_reason
        # 是内部状态，只进 probe_turns 表，永不进入 conversation。
        conversation.append({"role": "user", "content": action["payload"]})
        try:
            response = await target.chat(conversation)
        except httpx.HTTPStatusError as e:
            if not _is_platform_content_filter(e):
                raise  # 非 1301 的 HTTP 错误不吞，由 run_probe 兜底记失败
            # 1301 平台内容过滤：攻击通道被平台掐断，继续追问无意义。
            # 记一条 platform_filter 轮次，终止探测，任务记 defense_success
            # （防御方是厂商过滤层，与 executor 单轮语义一致）
            turns.append(
                {
                    "task_id": task_id,
                    "round_no": round_no,
                    "agent_thought": action["thought"],
                    "action": action["action"],
                    "pattern_id": action["pattern_id"],
                    "payload": action["payload"],
                    "response": f"被平台内容过滤拦截（1301）：{e.response.text[:200]}",
                    "verdict": "defense_success",
                    "verdict_source": "platform_filter",
                }
            )
            verdicts.append("defense_success")
            last_verdict_source = "platform_filter"
            last_needs_review = False
            logger.info("第 %d 轮被平台内容过滤拦截（1301），探测终止", round_no)
            break
        conversation.append({"role": "assistant", "content": response})

        # Observation：双裁判判定本轮（与 executor 共用 judge_pair）
        # 按 Agent 选定的 pattern_id 取模式（含 success/refusal_patterns）；
        # 自由追问（pattern_id=null）或 id 未命中时用空 dict
        pattern: dict[str, Any] = next(
            (p for p in candidate_patterns if p.get("id") == action["pattern_id"]),
            {},
        )
        judge_context = {**pattern, "expected_behavior": task.get("expected_behavior")}
        verdict, verdict_source, needs_review = await judge_pair(
            action["payload"], response, judge_context, JUDGE_MODE
        )
        verdicts.append(verdict)
        last_verdict_source = verdict_source
        last_needs_review = needs_review

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
                "verdict_source": verdict_source,
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

    # 落库：批量写轮次 + 写回任务
    if turns:
        db.table(TURNS_TABLE).insert(turns).execute()

    # 任务级最终判定：MVP 用最后一轮的 turn 级 verdict
    # TODO(Phase 2): 会话级裁判（完整历史 + 注入防御定界符，见设计文档第 2 节）
    final_verdict = verdicts[-1] if verdicts else "uncertain"
    update: dict[str, Any] = {
        "status": "完成",
        "actual_behavior": (
            turns[-1]["response"] if turns else "（Agent 首轮即终止，无交互）"
        ),
        "is_success": final_verdict == "attack_success",
        "verdict_source": last_verdict_source,
        "needs_review": last_needs_review,
        "agent_state": agent_state or None,
    }
    _update_task(db, task_id, update)

    # TODO(Phase 2): 更新 attack_patterns 的 use_count / success_count
    # （长期记忆成功率反馈，见设计文档第 4.2 节）

    return {
        "task_id": task_id,
        "status": "完成",
        "rounds": len(turns),
        "verdict": final_verdict,
        "verdict_source": last_verdict_source,
        "needs_review": last_needs_review,
        "is_success": final_verdict == "attack_success",
        "verdicts": verdicts,
    }
