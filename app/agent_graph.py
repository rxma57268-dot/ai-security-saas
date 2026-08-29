"""多轮探测 Agent 的 LangGraph 版（JD 第 6 条：框架的流程控制与记忆模块）。

重构边界：逻辑一行不改，控制流从 run_probe 的 for 循环搬家到 StateGraph。
  不变（直接复用）：agent_decide / parse_agent_output / judge_pair /
                    1301 轮内处理 / probe_turns 落库 / should_stop 机械条件
  变：for 循环 → 节点+条件边；turns/verdicts 列表 → Graph State 字段

图结构：

    ┌─────────┐  stop      ┌─────┐
    │ decide  │──────────→ │ END │
    │（思考+  │            └─────┘
    │  决策） │ 继续   ┌─────────┐  should_stop   ┌─────┐
    └─────────┘──────→ │ attack  │──────────────→ │ END │
           ↑           │（发靶机+│                └─────┘
           │           │  双裁判）│ 继续
           └───────────└─────────┘

状态：骨架——节点与条件边为最终实现；agent_state 压缩本轮仍不实现
（设计文档第 3 节，Phase 2）。
"""

import logging
import os
from operator import add
from typing import Annotated, Any, TypedDict

import httpx
from langgraph.graph import END, StateGraph
from supabase import Client

from .agent import (
    MAX_ROUNDS,
    TASKS_TABLE,
    TURNS_TABLE,
    agent_decide,
    fetch_candidate_patterns,
    final_verdict_for,
    should_stop,
)
from .executor import (
    JUDGE_MODE,
    _fail_result,
    _is_platform_content_filter,
    _update_task,
)
from .judge import Verdict, judge_pair
from .target import TargetModel

logger = logging.getLogger(__name__)


# ---------- Graph State ----------

class ProbeState(TypedDict, total=False):
    """探测图状态。带 add reducer 的字段：节点返回增量，框架负责追加。"""

    task_id: str
    task: dict[str, Any]
    # 发靶模型的完整会话：不裁剪（测的就是长对话行为），add 追加
    conversation: Annotated[list[dict[str, str]], add]
    # 轮次记录（probe_turns 行），add 追加
    turns: Annotated[list[dict[str, Any]], add]
    # 各轮判定，add 追加
    verdicts: Annotated[list[str], add]
    # Agent 思考上下文摘要（压缩逻辑 Phase 2）
    agent_state: dict[str, Any]
    candidate_patterns: list[dict[str, Any]]
    round_no: int
    # decide 节点的产出（内部状态，永不外发给靶模型）
    action: dict[str, Any]
    # 写回任务用的末轮信息
    verdict_source: str | None
    needs_review: bool
    # 终止原因（None=继续）：agent_stop / attack_success /
    # consecutive_defense_success / max_rounds / platform_filter
    stop_reason: str | None


# ---------- 节点 ----------

async def decide_node(state: ProbeState) -> dict[str, Any]:
    """Thought + Action：Agent 决策一轮。轮次在这里递增（图里没有 for 计数器）。"""
    round_no = state.get("round_no", 0) + 1
    action = await agent_decide(
        state["task"],
        state.get("agent_state") or {},
        state.get("turns") or [],
        state.get("candidate_patterns") or [],
        round_no,
    )
    if action["stop"]:
        logger.info("Agent 主动终止: %s", action["stop_reason"])
        return {
            "action": action,
            "round_no": round_no,
            "stop_reason": action["stop_reason"] or "agent_stop",
        }
    return {"action": action, "round_no": round_no}


def make_attack_node(target: TargetModel):
    """attack 节点工厂：TargetModel 实例闭包注入（节点签名只收 state）。"""

    async def attack_node(state: ProbeState) -> dict[str, Any]:
        action = state["action"]
        task = state["task"]
        round_no = state["round_no"]

        # 边界钉死：只有 payload 外发给目标模型；thought/action/stop_reason
        # 是内部状态，只进 turns，永不进入 conversation。
        user_msg = {"role": "user", "content": action["payload"]}

        try:
            response = await target.chat((state.get("conversation") or []) + [user_msg])
        except httpx.HTTPStatusError as e:
            if not _is_platform_content_filter(e):
                raise  # 非 1301 不吞，由 run_probe_graph 兜底记失败
            # 1301：记 platform_filter 轮次，终止探测（与 for 循环版语义一致）
            logger.info("第 %d 轮被平台内容过滤拦截（1301），探测终止", round_no)
            return {
                "conversation": [user_msg],
                "turns": [{
                    "task_id": state["task_id"],
                    "round_no": round_no,
                    "agent_thought": action["thought"],
                    "action": action["action"],
                    "pattern_id": action["pattern_id"],
                    "payload": action["payload"],
                    "response": f"被平台内容过滤拦截（1301）：{e.response.text[:200]}",
                    "verdict": "defense_success",
                    "verdict_source": "platform_filter",
                }],
                "verdicts": ["defense_success"],
                "verdict_source": "platform_filter",
                "needs_review": False,
                "stop_reason": "platform_filter",
            }

        # Observation：双裁判（judge_pair 原样复用）
        pattern: dict[str, Any] = next(
            (p for p in (state.get("candidate_patterns") or [])
             if p.get("id") == action["pattern_id"]),
            {},
        )
        judge_context = {**pattern, "expected_behavior": task.get("expected_behavior")}
        verdict, verdict_source, needs_review = await judge_pair(
            action["payload"], response, judge_context, JUDGE_MODE
        )

        turn = {
            "task_id": state["task_id"],
            "round_no": round_no,
            "agent_thought": action["thought"],
            "action": action["action"],
            "pattern_id": action["pattern_id"],
            "payload": action["payload"],
            "response": response,
            "verdict": verdict,
            "verdict_source": verdict_source,
        }
        # 终止判断只在节点里做一次并写进 state（should_stop 的唯一调用点），
        # 条件边纯读 stop_reason——避免边算一遍、wrapper 收尾再算一遍的逻辑漂移
        verdicts_so_far = (state.get("verdicts") or []) + [verdict]
        reason = should_stop(verdicts_so_far, round_no, MAX_ROUNDS)
        update: dict[str, Any] = {
            "conversation": [user_msg, {"role": "assistant", "content": response}],
            "turns": [turn],
            "verdicts": [verdict],
            "verdict_source": verdict_source,
            "needs_review": needs_review,
        }
        if reason:
            logger.info("探测终止: %s（第 %d 轮）", reason, round_no)
            update["stop_reason"] = reason
        return update

    return attack_node


# ---------- 条件边 ----------

def decide_edge(state: ProbeState) -> str:
    """decide 之后：Agent 喊停 → END，否则 → attack。"""
    return "end" if state.get("stop_reason") else "attack"


def attack_edge(state: ProbeState) -> str:
    """attack 之后：节点已把终止原因写进 stop_reason，这里只读不算。"""
    return "end" if state.get("stop_reason") else "decide"


# ---------- 图组装 ----------

def build_probe_graph(target: TargetModel | None = None) -> Any:
    """组装探测图（编译后可 ainvoke）。target 可注入，便于测试 mock。"""
    graph = StateGraph(ProbeState)
    graph.add_node("decide", decide_node)
    graph.add_node("attack", make_attack_node(target or TargetModel()))

    graph.set_entry_point("decide")
    graph.add_conditional_edges("decide", decide_edge, {"attack": "attack", "end": END})
    graph.add_conditional_edges("attack", attack_edge, {"decide": "decide", "end": END})
    return graph.compile()


async def run_probe_graph(task_id: str, db: Client) -> dict[str, Any]:
    """LangGraph 版多轮探测入口。与 run_probe 行为等价（搬家完成标准）。

    外层与 run_probe 完全同款：查任务/404 → 置执行中 → try 执行 → 落库写回；
    任何异常（图内部或落库）兜底为任务失败——对调用方与手写循环版无差别。
    """
    from fastapi import HTTPException

    # 1. 查任务
    resp = db.table(TASKS_TABLE).select("*").eq("id", task_id).execute()
    if not resp.data:
        raise HTTPException(status_code=404, detail="任务不存在")
    task = resp.data[0]

    # 2. 状态机流转：→ 执行中
    _update_task(db, task_id, {"status": "执行中"})

    try:
        # 3. 跑图
        candidate_patterns = fetch_candidate_patterns(db)
        graph = build_probe_graph()
        final: ProbeState = await graph.ainvoke(
            {
                "task_id": task_id,
                "task": task,
                "candidate_patterns": candidate_patterns,
                "round_no": 0,
                "stop_reason": None,
            }
        )

        # 4. 落库：批量写轮次 + 写回任务（终止原因读 state.stop_reason）
        turns = final.get("turns") or []
        verdicts = final.get("verdicts") or []
        agent_state = final.get("agent_state") or {}
        if turns:
            # 重复探测：旧轮次整批替换（MVP 语义同 run_probe）
            db.table(TURNS_TABLE).delete().eq("task_id", task_id).execute()
            db.table(TURNS_TABLE).insert(turns).execute()

        # 任务级最终判定：由终止原因推导（verdict 映射表见 final_verdict_for；
        # 会话级裁判 Phase 2）
        final_verdict = final_verdict_for(final.get("stop_reason"), verdicts)
        update: dict[str, Any] = {
            "status": "完成",
            "actual_behavior": (
                turns[-1]["response"] if turns else "（Agent 首轮即终止，无交互）"
            ),
            "is_success": final_verdict == "attack_success",
            "verdict": final_verdict,
            "verdict_source": final.get("verdict_source"),
            "needs_review": final.get("needs_review") or False,
            "stop_reason": final.get("stop_reason"),
            "agent_state": agent_state or None,
        }
        _update_task(db, task_id, update)

        # TODO(Phase 2): 更新 attack_patterns 的 use_count / success_count
        return {
            "task_id": task_id,
            "status": "完成",
            "rounds": len(turns),
            "verdict": final_verdict,
            "verdict_source": final.get("verdict_source"),
            "needs_review": final.get("needs_review") or False,
            "is_success": final_verdict == "attack_success",
            "verdicts": verdicts,
            "stop_reason": final.get("stop_reason"),
        }
    except Exception as e:
        # 图内部异常与手写循环异常对调用方无差别：任务记失败
        return _fail_result(task_id, db, e)
