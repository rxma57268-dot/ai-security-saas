"""probe_runs 历史账本（Sprint 0）：判定写入 append-only。

每次执行（execute 单轮 / probe 多轮）都新建一行 probe_runs，
轮次写入 probe_turns 时携带 probe_run_id，不再整批删除旧轮次。
verdict 绑定靶模型/裁判模型/Agent 模型的版本快照（先存模型名字符串）。

设计原则：历史账本写入失败绝不阻塞任务——所有函数吞异常、记日志、
返回 None。缺表（迁移未执行）时业务流不受影响，只是没有历史。
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any

from supabase import Client

logger = logging.getLogger(__name__)

RUNS_TABLE = "probe_runs"


def resolve_judge_model() -> str:
    """裁判模型版本快照（与 LLMJudge 的解析规则一致）。"""
    return os.environ.get("JUDGE_MODEL") or "glm-4-flash"

def resolve_agent_model(fallback_target_model: str | None = None) -> str:
    """Agent/attacker 模型版本快照（与 agent_decide 的解析规则一致）。"""
    return (
        os.environ.get("AGENT_MODEL")
        or os.environ.get("JUDGE_MODEL")
        or fallback_target_model
        or ""
    )


def create_probe_run(
    db: Client,
    task_id: str,
    entrypoint: str,
    probe_mode: str,
    target_model: str | None,
    judge_model: str | None = None,
    agent_model: str | None = None,
) -> str | None:
    """新建一行 probe_run，返回 run id；失败返回 None（不阻塞任务）。

    Args:
        entrypoint: execute（单轮）/ probe（多轮）/ batch（离线跑批）。
        probe_mode: single / template / pair。
    """
    try:
        resp = (
            db.table(RUNS_TABLE)
            .insert(
                {
                    "task_id": task_id,
                    "entrypoint": entrypoint,
                    "probe_mode": probe_mode,
                    "target_model": target_model,
                    "judge_model": judge_model or resolve_judge_model(),
                    "agent_model": agent_model,
                    "started_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            .execute()
        )
        return resp.data[0]["id"] if resp.data else None
    except Exception as e:
        logger.warning(
            "probe_run 创建失败（历史缺失但任务继续）: %s: %s", type(e).__name__, e
        )
        return None


def finalize_probe_run(
    db: Client,
    run_id: str | None,
    *,
    rounds: int,
    final_verdict: str,
    verdict_source: str | None,
    needs_review: bool,
    stop_reason: str | None = None,
    judge_reason: str | None = None,
    judge_evidence: str | None = None,
    defense_signature: str | None = None,
    path_deviation: str | None = None,
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
) -> None:
    """收尾写回 probe_run：最终判定 + 轮次 + 防御签名 + token 成本。
    失败只记日志。"""
    if not run_id:
        return
    try:
        db.table(RUNS_TABLE).update(
            {
                "rounds": rounds,
                "final_verdict": final_verdict,
                "verdict_source": verdict_source,
                "needs_review": needs_review,
                "stop_reason": stop_reason,
                "judge_reason": judge_reason,
                "judge_evidence": judge_evidence,
                "defense_signature": defense_signature,
                "path_deviation": path_deviation,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "finished_at": datetime.now(timezone.utc).isoformat(),
            }
        ).eq("id", run_id).execute()
    except Exception as e:
        logger.warning(
            "probe_run 收尾失败（历史不完整但任务继续）: %s: %s",
            type(e).__name__, e,
        )


def usage_tokens(usage: dict[str, Any] | None) -> tuple[int, int]:
    """从 OpenAI 兼容 usage 字段提取 (prompt_tokens, completion_tokens)。"""
    if not usage:
        return 0, 0
    try:
        return int(usage.get("prompt_tokens") or 0), int(
            usage.get("completion_tokens") or 0
        )
    except (TypeError, ValueError):
        return 0, 0
