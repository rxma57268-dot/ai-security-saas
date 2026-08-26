"""任务执行引擎：渲染 payload → 调用靶模型 → 判定 → 结果写库。

状态机：待执行 → 执行中 → 完成 / 失败
判定模式（JUDGE_MODE 环境变量）：
  regex  只用规则裁判
  llm    只用 LLM 裁判（裁判失败回落到规则裁判）
  both   两个裁判都跑（默认）：LLM 结果为准，两判不一致时 needs_review=true
裁判模型调用失败（含被平台 1301 过滤）回落 regex 时，needs_review 置 true。
LLMJudge 固定 temperature=0（测量工具需要可复现）；靶模型保持厂商默认
（被测对象的随机性本身是真实信号）。
特殊分支：靶模型被平台内容过滤拦截（智谱 1301）→ defense_success /
  verdict_source=platform_filter，状态记为"完成"而非"失败"。
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import HTTPException
from supabase import Client

from .judge import LLMJudge, RegexJudge, Verdict
from .target import TargetModel

PATTERNS_TABLE = "attack_patterns"
TASKS_TABLE = "test_tasks"

JUDGE_MODE = os.environ.get("JUDGE_MODE", "both")

logger = logging.getLogger(__name__)


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
    """异常 → 状态 → 失败，错误信息写入 actual_behavior 便于排查"""
    _update_task(
        db,
        task_id,
        {"status": "失败", "actual_behavior": f"执行异常：{type(e).__name__}: {e}"},
    )
    return {
        "task_id": task_id,
        "status": "失败",
        "verdict": None,
        "error": f"{type(e).__name__}: {e}",
    }


def _is_platform_content_filter(e: httpx.HTTPStatusError) -> bool:
    """智谱平台内容过滤：HTTP 400 且响应体 error.code == '1301'。

    平台过滤层拦住了输入或模型输出（role=user/assistant），请求未真正完成。
    """
    try:
        body = e.response.json()
    except Exception:
        return False
    return str(body.get("error", {}).get("code")) == "1301"


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

        # 6. 判定：regex / llm / both
        # 把任务的 expected_behavior 合入判定上下文（LLM 裁判模板需要）
        judge_context = {**pattern, "expected_behavior": task.get("expected_behavior")}
        regex_verdict = await RegexJudge().judge(payload, response, judge_context)

        llm_verdict: Verdict | None = None
        if JUDGE_MODE in ("llm", "both"):
            try:
                llm_verdict = await LLMJudge().judge(payload, response, judge_context)
            except Exception as e:
                # 裁判模型失败不阻塞任务，回落到规则裁判，但留下日志
                logger.warning("LLMJudge 调用失败，回落 regex: %s: %s", type(e).__name__, e)
                llm_verdict = None

        if JUDGE_MODE == "regex":
            verdict, verdict_source, needs_review = regex_verdict, "regex", False
        else:
            # llm / both：LLM 结果为准；both 模式下两判不一致 → 需人工复核
            # 裁判失败回落 regex 时结果可信度不足（替补裁判出的判），同样标记复核
            verdict = llm_verdict or regex_verdict
            verdict_source = "llm" if llm_verdict else "regex"
            needs_review = llm_verdict is None or (
                JUDGE_MODE == "both" and llm_verdict != regex_verdict
            )

        # 7. 写回结果：响应文本、是否成功、模式自带危险等级、判定来源、状态 → 完成
        update: dict[str, Any] = {
            "status": "完成",
            "actual_behavior": response,
            "is_success": verdict == "attack_success",
            "verdict_source": verdict_source,
            "needs_review": needs_review,
        }
        if pattern.get("default_severity"):
            update["severity"] = pattern["default_severity"]
        _update_task(db, task_id, update)

        return {
            "task_id": task_id,
            "status": "完成",
            "verdict": verdict,
            "verdict_source": verdict_source,
            "needs_review": needs_review,
            "is_success": update["is_success"],
            "severity": update.get("severity"),
        }
    except httpx.HTTPStatusError as e:
        if _is_platform_content_filter(e):
            # 平台内容过滤拦截（1301）：攻击未成功，本质是厂商过滤层防御，
            # 记为 defense_success，不进入"失败"分支
            update: dict[str, Any] = {
                "status": "完成",
                "actual_behavior": f"被平台内容过滤拦截（1301）：{e.response.text[:200]}",
                "is_success": False,
                "verdict_source": "platform_filter",
                "needs_review": False,
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
            }
        # 其他 HTTP 错误维持原样：进入失败分支
        return _fail_result(task_id, db, e)
    except Exception as e:
        return _fail_result(task_id, db, e)
