"""任务执行引擎：渲染 payload → 调用靶模型 → RegexJudge 判定 → 结果写库。

状态机：待执行 → 执行中 → 完成 / 失败
"""

from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from supabase import Client

from .judge import RegexJudge
from .target import TargetModel

PATTERNS_TABLE = "attack_patterns"
TASKS_TABLE = "test_tasks"


def render_payload(template: str, task: dict[str, Any]) -> str:
    """用任务字段替换模板中的 {{var}} 占位符（如 {{target_name}}）。"""
    result = template
    for key in ("target_name", "target_url"):
        result = result.replace("{{" + key + "}}", str(task.get(key) or ""))
    return result


def _update_task(db: Client, task_id: str, data: dict[str, Any]) -> None:
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    db.table(TASKS_TABLE).update(data).eq("id", task_id).execute()


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

        # 6. 规则判定
        verdict = RegexJudge().judge(payload, response, pattern)

        # 7. 写回结果：响应文本、是否成功、模式自带危险等级、状态 → 完成
        update: dict[str, Any] = {
            "status": "完成",
            "actual_behavior": response,
            "is_success": verdict == "attack_success",
        }
        if pattern.get("default_severity"):
            update["severity"] = pattern["default_severity"]
        _update_task(db, task_id, update)

        return {
            "task_id": task_id,
            "status": "完成",
            "verdict": verdict,
            "is_success": update["is_success"],
            "severity": update.get("severity"),
        }
    except Exception as e:
        # 异常 → 状态 → 失败，错误信息写入 actual_behavior 便于排查
        _update_task(
            db,
            task_id,
            {
                "status": "失败",
                "actual_behavior": f"执行异常：{type(e).__name__}: {e}",
            },
        )
        return {
            "task_id": task_id,
            "status": "失败",
            "verdict": None,
            "error": f"{type(e).__name__}: {e}",
        }
