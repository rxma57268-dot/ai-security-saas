from datetime import datetime
from typing import Literal, Optional
from uuid import UUID

from pydantic import BaseModel, Field

# ---------- 枚举定义 ----------

AttackCategory = Literal[
    "prompt_injection",
    "data_poisoning",
    "tool_abuse",
    "memory_tampering",
    "privilege_escalation",
    "info_leakage",
    "jailbreak",
]

TargetComponent = Literal[
    "llm_core",
    "tool_chain",
    "skill_system",
    "mcp_server",
    "memory",
    "state_manager",
    "rag_pipeline",
]

AttackVector = Literal[
    "user_input",
    "external_doc",
    "api_call",
    "upload_file",
    "third_party_skill",
    "mcp_response",
    "memory_rw",
]

PayloadEncoding = Literal[
    "plain",
    "base64",
    "unicode",
    "emoji_substitution",
    "multilingual",
]

Severity = Literal["critical", "high", "medium", "low", "info"]

TaskStatus = Literal["待执行", "执行中", "完成", "失败"]

ExecutionMethod = Literal["手动", "自动脚本", "fuzz"]

ImpactScope = Literal["单用户", "全部用户", "系统级", "数据级"]


# ---------- 攻击模式 ----------

class AttackPatternCreate(BaseModel):
    """新建攻击模式请求体"""

    name: str = Field(..., min_length=1, max_length=200, description="攻击模式名称")
    attack_category: AttackCategory = Field(..., description="攻击大类")
    attack_sub_type: str = Field(..., min_length=1, max_length=100, description="攻击子类")
    target_component: TargetComponent = Field(..., description="目标 Agent 组件")
    attack_vector: AttackVector = Field(..., description="攻击入口")
    payload_template: str = Field(..., min_length=1, description="载荷模板，支持 {{变量}} 占位符")
    payload_encoding: PayloadEncoding = Field(default="plain", description="编码方式")
    precondition: Optional[str] = Field(default=None, description="前置条件")
    default_severity: Severity = Field(default="medium", description="默认严重等级")
    cwe_id: Optional[str] = Field(default=None, max_length=20, description="关联 CWE 编号，如 CWE-77")
    mitigation: Optional[str] = Field(default=None, description="修复建议")
    success_patterns: list[str] = Field(default_factory=list, description="命中规则：响应含任一即疑似攻击成功")
    refusal_patterns: list[str] = Field(default_factory=list, description="拒绝规则：响应含任一即判定防御成功（优先于命中规则）")


class AttackPatternOut(BaseModel):
    """攻击模式返回体（字段均可空，兼容库中历史数据）"""

    id: UUID
    name: Optional[str] = None
    attack_category: Optional[AttackCategory] = None
    attack_sub_type: Optional[str] = None
    target_component: Optional[TargetComponent] = None
    attack_vector: Optional[AttackVector] = None
    payload_template: Optional[str] = None
    payload_encoding: Optional[PayloadEncoding] = None
    precondition: Optional[str] = None
    default_severity: Optional[Severity] = None
    cwe_id: Optional[str] = None
    mitigation: Optional[str] = None
    success_patterns: Optional[list[str]] = None
    refusal_patterns: Optional[list[str]] = None
    created_at: Optional[datetime] = None


# ---------- 测试任务 ----------

class TestTaskCreate(BaseModel):
    """新建测试任务请求体"""

    attack_pattern_id: UUID = Field(..., description="关联的攻击模式 ID")
    target_name: str = Field(..., min_length=1, max_length=200, description="被测目标名称")
    target_url: Optional[str] = Field(default=None, max_length=500, description="被测目标地址")
    payload: str = Field(..., min_length=1, description="实际使用的载荷（模板渲染后内容）")
    execution_method: ExecutionMethod = Field(default="手动", description="执行方式")
    tool_used: Optional[str] = Field(default=None, max_length=200, description="使用工具")
    status: TaskStatus = Field(default="待执行", description="任务状态")
    is_success: Optional[bool] = Field(default=None, description="攻击是否成功")
    severity: Optional[Severity] = Field(default=None, description="实际严重等级")
    impact_scope: Optional[ImpactScope] = Field(default=None, description="影响范围")
    actual_behavior: Optional[str] = Field(default=None, description="实际观测行为")
    expected_behavior: Optional[str] = Field(default=None, description="预期安全行为")
    evidence: Optional[str] = Field(default=None, description="证据（截图/日志/抓包路径）")
    regression_tested: bool = Field(default=False, description="是否已回归验证")


class TestTaskUpdate(BaseModel):
    """更新测试任务请求体（所有字段可选，仅更新传入字段）"""

    target_name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    target_url: Optional[str] = Field(default=None, max_length=500)
    payload: Optional[str] = Field(default=None, min_length=1)
    execution_method: Optional[ExecutionMethod] = None
    tool_used: Optional[str] = Field(default=None, max_length=200)
    status: Optional[TaskStatus] = None
    is_success: Optional[bool] = None
    severity: Optional[Severity] = None
    impact_scope: Optional[ImpactScope] = None
    actual_behavior: Optional[str] = None
    expected_behavior: Optional[str] = None
    evidence: Optional[str] = None
    regression_tested: Optional[bool] = None


class TestTaskOut(BaseModel):
    """测试任务返回体（字段均可空，兼容库中历史数据）"""

    id: UUID
    attack_pattern_id: Optional[UUID] = None
    target_name: Optional[str] = None
    target_url: Optional[str] = None
    payload: Optional[str] = None
    execution_method: Optional[ExecutionMethod] = None
    tool_used: Optional[str] = None
    status: Optional[TaskStatus] = None
    is_success: Optional[bool] = None
    severity: Optional[Severity] = None
    impact_scope: Optional[ImpactScope] = None
    actual_behavior: Optional[str] = None
    expected_behavior: Optional[str] = None
    evidence: Optional[str] = None
    regression_tested: Optional[bool] = None
    verdict_source: Optional[str] = None
    needs_review: Optional[bool] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
