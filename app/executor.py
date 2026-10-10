"""任务执行引擎：渲染 payload → 调用靶模型 → 判定 → 结果写库。

状态机：待执行 → 执行中 → 完成 / 失败
判定模式（JUDGE_MODE 环境变量）：
  regex  只用规则裁判
  llm    只用 LLM 裁判（裁判失败回落到规则裁判）
  both   两个裁判都跑（默认）：LLM 结果为准，两判不一致时 needs_review=true
  funnel 三级漏斗（Sprint 3）：regex → Prompt Guard → LLM
裁判模型调用失败（含被平台 1301 过滤）回落 regex 时，needs_review 置 true。
LLMJudge 固定 temperature=0（测量工具需要可复现）；靶模型保持厂商默认
（被测对象的随机性本身是真实信号）。
特殊分支：靶模型被平台内容过滤拦截（智谱 1301）→ defense_success /
  verdict_source=platform_filter，状态记为"完成"而非"失败"。

Sprint 0：判定写入 append-only——每次执行新建 probe_runs 行（带靶模型/
裁判模型版本快照），轮次带 probe_run_id 落库，judge reason/evidence 随
verdict 一起写入 probe_runs / probe_turns / test_tasks，不再丢弃。
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import HTTPException
from supabase import Client

from .judge import judge_pair
from .probe_runs import create_probe_run, finalize_probe_run, resolve_judge_model
from .target import TargetModel

logger = logging.getLogger(__name__)

PATTERNS_TABLE = "attack_patterns"
TASKS_TABLE = "test_tasks"
TURNS_TABLE = "probe_turns"

JUDGE_MODE = os.environ.get("JUDGE_MODE", "both")


def render_payload(template: str, task: dict[str, Any]) -> str:
    """用任务字段替换模板中的 {{var}} 占位符（如 {{target_name}}）。"""
    result = template
    for key in ("target_name", "target_url"):
        result = result.replace("{{" + key + "}}", str(task.get(key) or ""))
    return result


def _update_task(db: Client, task_id: str, data: dict[str, Any]) -> None:
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    db.table(TASKS_TABLE).update(data).eq("id", task_id).execute()


def _fail_result(task_id: str, db: Client, e: Exception) -> dict[str, Any]:
    """异常 → 状态 → 失败，错误信息写入 actual_behavior 便于排查。

    verdict 写 uncertain（无法判定），并同步刷 is_success=False——
    防止历史成功残留与本次失败矛盾（verdict/is_success 语义一致约束）。
    """
    _update_task(
        db,
        task_id,
        {
            "status": "失败",
            "actual_behavior": f"执行异常：{type(e).__name__}: {e}",
            "verdict": "uncertain",
            "is_success": False,
        },
    )
    return {
        "task_id": task_id,
        "status": "失败",
        "verdict": None,
        "error": f"{type(e).__name__}: {e}",
    }


def _is_platform_content_filter(e: httpx.HTTPStatusError) -> bool:
    """厂商平台内容过滤拦截（非模型自身拒答，请求未真正完成）。

    已识别的平台过滤信号：
      - 智谱：HTTP 400 且 error.code == '1301'
      - 阿里云百炼（通义）：HTTP 400 且 error.code == 'data_inspection_failed'
        （"Input data may contain inappropriate content"）
    """
    try:
        body = e.response.json()
    except Exception:
        return False
    code = str(body.get("error", {}).get("code"))
    return code in ("1301", "data_inspection_failed")


def _record_single_turn_run(
    db: Client,
    task_id: str,
    *,
    target_model: str | None,
    payload: str,
    response_text: str,
    verdict: str,
    verdict_source: str,
    needs_review: bool,
    judge_reason: str | None,
    judge_evidence: str | None,
    defense_signature: str | None = None,
    path_deviation: str | None = None,
) -> str | None:
    """Sprint 0：单轮执行的 append-only 账本——probe_run + 一条 probe_turn。

    v3 Sprint 0：防御签名/路径偏差随判定落库（策略库两级检索依赖）。
    历史写入失败不阻塞任务（probe_runs 内部已吞异常）。
    """
    run_id = create_probe_run(
        db,
        task_id,
        entrypoint="execute",
        probe_mode="single",
        target_model=target_model,
        judge_model=resolve_judge_model(),
    )
    finalize_probe_run(
        db,
        run_id,
        rounds=1,
        final_verdict=verdict,
        verdict_source=verdict_source,
        needs_review=needs_review,
        judge_reason=judge_reason,
        judge_evidence=judge_evidence,
        defense_signature=defense_signature,
        path_deviation=path_deviation,
    )
    if run_id:
        try:
            db.table(TURNS_TABLE).insert(
                {
                    "task_id": task_id,
                    "probe_run_id": run_id,
                    "round_no": 1,
                    "action": "follow_up",
                    "payload": payload,
                    "response": response_text,
                    "verdict": verdict,
                    "verdict_source": verdict_source,
                    "judge_reason": judge_reason,
                    "judge_evidence": judge_evidence,
                    "defense_signature": defense_signature,
                    "path_deviation": path_deviation,
                }
            ).execute()
        except Exception as e:
            logger.warning(
                "单轮 probe_turn 写入失败（历史缺失但任务继续）: %s: %s",
                type(e).__name__, e,
            )
    return run_id


async def execute_task(task_id: str, db: Client) -> dict[str, Any]:
    """执行一个测试任务，返回判定结果。

    Raises:
        HTTPException: 任务不存在(404) / 关联攻击模式不存在(404)。
    """
    # 1. 查任务（RLS 保证只能查到自己的；查不到即 404）
    resp = db.table(TASKS_TABLE).select("*").eq("id", task_id).execute()
    if not resp.data:
        raise HTTPException(status_code=404, detail="任务不存在")
    task = resp.data[0]

    # 2. 按任务关联的 attack_pattern_id 查攻击模式（payload 模板 + 判定规则）
    pattern_id = str(task["attack_pattern_id"])
    resp = db.table(PATTERNS_TABLE).select("*").eq("id", pattern_id).execute()
    if not resp.data:
        raise HTTPException(status_code=404, detail="关联的攻击模式不存在")
    pattern = resp.data[0]

    # 3. 渲染 payload：任务里已填写的 payload 优先，否则用模式模板
    template = task.get("payload") or pattern.get("payload_template") or ""
    payload = render_payload(template, task)

    # 4. 状态机流转：待执行 → 执行中
    _update_task(db, task_id, {"status": "执行中"})

    try:
        # 5. 调靶模型
        target = TargetModel()
        response = await target.chat([{"role": "user", "content": payload}])

        # 6. 判定：regex / llm / both / funnel（公共判定管线，agent.py 同款）
        # 把任务的 expected_behavior 合入判定上下文（LLM 裁判模板需要）
        judge_context = {**pattern, "expected_behavior": task.get("expected_behavior")}
        outcome = await judge_pair(payload, response, judge_context, JUDGE_MODE)

        # Sprint 0：append-only 账本（probe_run + probe_turn，带模型版本快照）
        run_id = _record_single_turn_run(
            db,
            task_id,
            target_model=target.model,
            payload=payload,
            response_text=response,
            verdict=outcome.verdict,
            verdict_source=outcome.verdict_source,
            needs_review=outcome.needs_review,
            judge_reason=outcome.reason,
            judge_evidence=outcome.evidence,
            defense_signature=outcome.defense_signature,
            path_deviation=outcome.path_deviation,
        )

        # 7. 写回结果：响应文本、是否成功、模式自带危险等级、判定来源、
        # 裁判理由/证据、防御签名、靶模型版本快照、最新 run 指针、状态 → 完成
        update: dict[str, Any] = {
            "status": "完成",
            "actual_behavior": response,
            "is_success": outcome.verdict == "attack_success",
            "verdict": outcome.verdict,
            "verdict_source": outcome.verdict_source,
            "needs_review": outcome.needs_review,
            "judge_reason": outcome.reason,
            "judge_evidence": outcome.evidence,
            "defense_signature": outcome.defense_signature,
            "target_model": target.model,
            "latest_probe_run_id": run_id,
        }
        if pattern.get("default_severity"):
            update["severity"] = pattern["default_severity"]
        _update_task(db, task_id, update)

        return {
            "task_id": task_id,
            "status": "完成",
            "verdict": outcome.verdict,
            "verdict_source": outcome.verdict_source,
            "needs_review": outcome.needs_review,
            "judge_reason": outcome.reason,
            "judge_evidence": outcome.evidence,
            "is_success": update["is_success"],
            "severity": update.get("severity"),
            "probe_run_id": run_id,
        }
    except httpx.HTTPStatusError as e:
        if _is_platform_content_filter(e):
            # 平台内容过滤拦截（1301）：攻击未成功，本质是厂商过滤层防御，
            # 记为 defense_success，不进入"失败"分支
            filter_text = f"被平台内容过滤拦截（1301）：{e.response.text[:200]}"
            run_id = _record_single_turn_run(
                db,
                task_id,
                target_model=target.model,
                payload=payload,
                response_text=filter_text,
                verdict="defense_success",
                verdict_source="platform_filter",
                needs_review=False,
                judge_reason="平台内容过滤拦截（1301）",
                judge_evidence=e.response.text[:200],
                defense_signature="platform_block",
            )
            update: dict[str, Any] = {
                "status": "完成",
                "actual_behavior": filter_text,
                "is_success": False,
                "verdict": "defense_success",
                "verdict_source": "platform_filter",
                "needs_review": False,
                "judge_reason": "平台内容过滤拦截（1301）",
                "judge_evidence": e.response.text[:200],
                "defense_signature": "platform_block",
                "target_model": target.model,
                "latest_probe_run_id": run_id,
            }
            if pattern.get("default_severity"):
                update["severity"] = pattern["default_severity"]
            _update_task(db, task_id, update)
            return {
                "task_id": task_id,
                "status": "完成",
                "verdict": "defense_success",
                "verdict_source": "platform_filter",
                "needs_review": False,
                "is_success": False,
                "severity": update.get("severity"),
                "probe_run_id": run_id,
            }
        # 其他 HTTP 错误维持原样：进入失败分支
        return _fail_result(task_id, db, e)
    except Exception as e:
        return _fail_result(task_id, db, e)
