from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

import httpx
import logging
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse
from postgrest.exceptions import APIError
from supabase import Client

# uvicorn 只配置自己的 logger，应用 logger（app.agent 等）的 INFO 默认被
# root 的 WARNING 级别吞掉；显式提到 INFO，探测过程日志才会出现在 Render Logs
logging.basicConfig(level=logging.INFO)

from .auth import CurrentUser, get_current_user
from .database import get_user_client
from .agent import run_probe
from .executor import execute_task
from .schemas import (
    AttackPatternCreate,
    AttackPatternOut,
    ProbeTurnOut,
    TaskStatus,
    TestTaskCreate,
    TestTaskOut,
    TestTaskUpdate,
)

app = FastAPI(
    title="Agent 安全测试平台 API",
    description="攻击模式与测试任务管理服务",
    version="1.0.0",
)

PATTERNS_TABLE = "attack_patterns"
TASKS_TABLE = "test_tasks"
TURNS_TABLE = "probe_turns"


@app.exception_handler(httpx.TransportError)
async def upstream_error_handler(request: Request, exc: httpx.TransportError):
    """Supabase 网络错误（重试后仍失败）兜底：返回 503 而不是裸 500"""
    return JSONResponse(
        status_code=503,
        content={"detail": "数据库连接暂时不可用，请稍后重试"},
    )


def get_db(user: CurrentUser = Depends(get_current_user)) -> Client:
    """每个请求创建带用户 token 的 Supabase client。

    RLS 策略据此按用户隔离数据；同时使所有挂载了 db 依赖的接口
    自动要求登录（get_current_user 校验失败即 401）。
    """
    return get_user_client(user.token)


def handle_db_error(e: APIError):
    """将 Supabase/PostgREST 错误转换为合适的 HTTP 响应"""
    if e.code == "23503":  # 外键约束
        raise HTTPException(status_code=400, detail="关联的 attack_pattern_id 不存在")
    raise HTTPException(status_code=500, detail=f"数据库错误: {e.message}")


# ---------- 攻击模式 ----------

@app.post(
    "/patterns",
    response_model=AttackPatternOut,
    status_code=201,
    summary="新建攻击模式",
)
def create_pattern(
    body: AttackPatternCreate,
    db: Client = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    data = body.model_dump()
    data["user_id"] = user.user_id
    try:
        resp = db.table(PATTERNS_TABLE).insert(data).execute()
    except APIError as e:
        handle_db_error(e)
    return resp.data[0]


@app.get(
    "/patterns",
    response_model=List[AttackPatternOut],
    summary="查模式列表",
)
def list_patterns(
    attack_category: Optional[str] = Query(default=None, description="按攻击大类过滤"),
    target_component: Optional[str] = Query(default=None, description="按目标组件过滤"),
    keyword: Optional[str] = Query(default=None, description="按名称模糊搜索"),
    offset: int = Query(default=0, ge=0, description="偏移量"),
    limit: int = Query(default=20, ge=1, le=100, description="每页数量"),
    db: Client = Depends(get_db),
):
    query = db.table(PATTERNS_TABLE).select("*")
    if attack_category:
        query = query.eq("attack_category", attack_category)
    if target_component:
        query = query.eq("target_component", target_component)
    if keyword:
        query = query.ilike("name", f"%{keyword}%")
    try:
        resp = query.order("created_at", desc=True).range(offset, offset + limit - 1).execute()
    except APIError as e:
        handle_db_error(e)
    return resp.data


# ---------- 测试任务 ----------

@app.post(
    "/tasks",
    response_model=TestTaskOut,
    status_code=201,
    summary="新建测试任务",
)
def create_task(
    body: TestTaskCreate,
    db: Client = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    # 显式校验外键，给出更友好的错误信息
    pattern = (
        db.table(PATTERNS_TABLE)
        .select("id")
        .eq("id", str(body.attack_pattern_id))
        .execute()
    )
    if not pattern.data:
        raise HTTPException(status_code=400, detail="关联的 attack_pattern_id 不存在")

    data = body.model_dump(mode="json")
    data["user_id"] = user.user_id
    try:
        resp = db.table(TASKS_TABLE).insert(data).execute()
    except APIError as e:
        handle_db_error(e)
    return resp.data[0]


@app.get(
    "/tasks",
    response_model=List[TestTaskOut],
    summary="查任务列表",
)
def list_tasks(
    status: Optional[TaskStatus] = Query(default=None, description="按任务状态过滤"),
    attack_pattern_id: Optional[UUID] = Query(default=None, description="按攻击模式过滤"),
    is_success: Optional[bool] = Query(default=None, description="按攻击是否成功过滤"),
    offset: int = Query(default=0, ge=0, description="偏移量"),
    limit: int = Query(default=20, ge=1, le=100, description="每页数量"),
    db: Client = Depends(get_db),
):
    query = db.table(TASKS_TABLE).select("*")
    if status:
        query = query.eq("status", status)
    if attack_pattern_id:
        query = query.eq("attack_pattern_id", str(attack_pattern_id))
    if is_success is not None:
        query = query.eq("is_success", is_success)
    try:
        resp = query.order("created_at", desc=True).range(offset, offset + limit - 1).execute()
    except APIError as e:
        handle_db_error(e)
    return resp.data


@app.get(
    "/tasks/{task_id}",
    response_model=TestTaskOut,
    summary="查单个任务",
)
def get_task(
    task_id: UUID = Path(..., description="任务 ID"),
    db: Client = Depends(get_db),
):
    try:
        resp = db.table(TASKS_TABLE).select("*").eq("id", str(task_id)).execute()
    except APIError as e:
        handle_db_error(e)
    if not resp.data:
        raise HTTPException(status_code=404, detail="任务不存在")
    return resp.data[0]


@app.post(
    "/tasks/{task_id}/execute",
    summary="执行任务（调靶模型 + 判定 + 写回结果）",
)
async def execute(
    task_id: UUID = Path(..., description="任务 ID"),
    db: Client = Depends(get_db),
):
    return await execute_task(str(task_id), db)


@app.get(
    "/tasks/{task_id}/turns",
    response_model=List[ProbeTurnOut],
    summary="查任务的多轮探测轮次（probe_turns 时间线）",
)
def list_turns(
    task_id: UUID = Path(..., description="任务 ID"),
    db: Client = Depends(get_db),
):
    # 先确认任务存在（404 语义与各 task 端点一致；RLS 保证只能查自己的）
    task = db.table(TASKS_TABLE).select("id").eq("id", str(task_id)).execute()
    if not task.data:
        raise HTTPException(status_code=404, detail="任务不存在")
    try:
        resp = (
            db.table(TURNS_TABLE)
            .select("*")
            .eq("task_id", str(task_id))
            .order("round_no")
            .execute()
        )
    except APIError as e:
        handle_db_error(e)
    return resp.data


@app.post(
    "/tasks/{task_id}/probe",
    status_code=202,
    summary="多轮探测（Agent ReAct 循环：多轮攻击 + 逐轮判定 + 写回）",
)
async def probe(
    background_tasks: BackgroundTasks,
    task_id: UUID = Path(..., description="任务 ID"),
    user: CurrentUser = Depends(get_current_user),
):
    # 多轮探测耗时长（每轮 = Agent 决策 + 靶模型 + 双裁判三次 LLM 调用），
    # 后台执行、立即返回 202；前端按任务状态轮询结果（详情页已有 5s 轮询）。
    db = get_user_client(user.token)
    # 预检任务存在性，保持与 execute 一致的 404 语义
    resp = db.table(TASKS_TABLE).select("id").eq("id", str(task_id)).execute()
    if not resp.data:
        raise HTTPException(status_code=404, detail="任务不存在")

    background_tasks.add_task(_run_probe_background, str(task_id), user.token)
    return {"task_id": str(task_id), "status": "执行中"}


async def _run_probe_background(task_id: str, token: str) -> None:
    """后台执行多轮探测：用用户 token 重建 client，与请求生命周期解耦。

    已知边界（MVP 接受，见设计文档）：
    - Supabase JWT 默认 1 小时有效，探测通常 5-10 分钟，过期风险有界
    - Render 实例重启/重新部署会丢后台任务，任务停在"执行中"（Phase 2 加超时清扫）
    """
    db = get_user_client(token)
    await run_probe(task_id, db)


@app.patch(
    "/tasks/{task_id}",
    response_model=TestTaskOut,
    summary="更新任务状态/结果",
)
def update_task(
    body: TestTaskUpdate,
    task_id: UUID = Path(..., description="任务 ID"),
    db: Client = Depends(get_db),
):
    update_data = body.model_dump(exclude_unset=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="请求体为空，至少提供一个待更新字段")

    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()

    try:
        resp = (
            db.table(TASKS_TABLE)
            .update(update_data)
            .eq("id", str(task_id))
            .execute()
        )
    except APIError as e:
        handle_db_error(e)
    if not resp.data:
        raise HTTPException(status_code=404, detail="任务不存在")
    return resp.data[0]
