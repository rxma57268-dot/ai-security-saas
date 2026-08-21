from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Path, Query
from postgrest.exceptions import APIError
from supabase import Client

from .auth import get_current_user
from .database import supabase
from .schemas import (
    AttackPatternCreate,
    AttackPatternOut,
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


def get_db() -> Client:
    return supabase


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
    _user_id: str = Depends(get_current_user),
):
    try:
        resp = db.table(PATTERNS_TABLE).insert(body.model_dump()).execute()
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
    _user_id: str = Depends(get_current_user),
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

    try:
        resp = db.table(TASKS_TABLE).insert(body.model_dump(mode="json")).execute()
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


@app.patch(
    "/tasks/{task_id}",
    response_model=TestTaskOut,
    summary="更新任务状态/结果",
)
def update_task(
    body: TestTaskUpdate,
    task_id: UUID = Path(..., description="任务 ID"),
    db: Client = Depends(get_db),
    _user_id: str = Depends(get_current_user),
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
