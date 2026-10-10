# ai-security-saas

AI 安全测试 SaaS：场景化安全检测 + PoC 动态验证 + 红队基准评测

## 这是什么（30 秒版）

给 AI 应用做安全体检的平台：内置场景化攻击模式库（越狱/注入/信息泄露/角色扮演等），
一键对目标大模型发起自动化攻击测试，由**三级判定漏斗**（regex → Prompt Guard → LLM 裁判）
给出结论，分歧自动进人工复核。支持单轮执行、多轮探测 Agent（ReAct 循环，LangGraph 图实现）
和 **PAIR 算法驱动攻击**（attacker 模型逐轮生成 payload）。
用真实攻击行为回答一个问题：**你的模型防线，到底有多厚？**

## 快速开始

```bash
# 本地（Python 3.12+）
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows PowerShell
pip install -r requirements.txt
uvicorn app.main:app --port 8000

# Docker 一键起
docker-compose up --build
```

数据库为 Supabase（GoTrue 认证 + PostgREST RLS）：
- 云端：建一个免费 Supabase 项目，把 URL/anon key 填进 `.env`
- 本地：`supabase start` 起本地栈，`.env` 指向 `http://localhost:54321`

**数据库迁移**：依次在 Supabase SQL Editor 执行
`docs/schema.sql`（基础表，全新项目从这开始）→ `docs/attack_patterns_v2.sql` → `docs/multi_turn_agent.sql` → `docs/sprint0_probe_runs.sql` → `docs/v3_dynamic_redteam.sql`

环境变量（`.env`，完整注释见 `.env.example`）：

| 变量 | 说明 |
|---|---|
| `SUPABASE_URL` / `SUPABASE_KEY` | Supabase 项目配置（数据库 + 认证，anon key） |
| `TARGET_BASE_URL` / `TARGET_API_KEY` / `TARGET_MODEL` | 靶模型（OpenAI 兼容端点，默认智谱 glm-4-flash） |
| `JUDGE_MODE` | 判定模式：`regex` / `llm` / `both`（默认）/ `funnel`（三级漏斗） |
| `JUDGE_MODEL` / `JUDGE_BASE_URL` / `JUDGE_API_KEY` | 裁判模型（可独立端点，跨厂商裁判避免自我裁判偏差） |
| `AGENT_MODEL` | 多轮探测 Agent / Attacker 模型（缺省回落 JUDGE_MODEL） |
| `EMBEDDING_*` | 策略库语义检索的 embedding 端点（默认智谱 embedding-3） |
| `MAX_ROUNDS` | 多轮探测轮次上限（默认 8） |
| `PROBE_MODE` | `template`（默认）/ `pair`（PAIR 基线）/ `dynamic`（动态红队） |

## 架构（v3 · 动态红队）

```mermaid
flowchart TB
    subgraph 生成侧
        DS[数据集管线<br/>种子×变异算子] --> QG[质量评估门<br/>黄金集 P/R + 回归门禁]
        MINE[手法挖掘<br/>黑盒 autoresearch] --> QG
    end
    QG --> LIB[攻击模式库<br/>+ 工具库 Function Call]
    LIB --> ATT[动态红队 Attacker<br/>工具组合生成 payload]
    STRAT[攻击策略库<br/>pgvector 两级检索] -->|失败时注入 Top-K 策略| ATT
    ATT -->|多轮攻击| TARGET[靶模型]
    TARGET --> JUDGE[判定管线<br/>regex → Prompt Guard → LLM]
    JUDGE -->|verdict + 防御签名 + 路径偏差| ATT
    JUDGE -->|probe_turns 落库| MEM[历史账本<br/>append-only]
    MEM -->|自动总结：手法序列×防御签名→成功率| STRAT
```

核心组件：

- **执行引擎**（`executor.py`）：单轮执行 + 状态机（待执行 → 执行中 → 完成/失败）
- **多轮探测 Agent**（`agent.py` / `agent_graph.py`）：ReAct 循环，手写与 LangGraph 图双实现
- **动态红队 Attacker**（`attacker.py` + `attack_tools.py`）：三种 payload 来源——
  `template` 模板渲染 / `pair` PAIR 文献基线 / `dynamic` Function Call 工具组合
  （工具 schema 显式声明 composable_with / order_sensitive）
- **攻击策略库**（`strategy.py` + `scripts/mine_strategies.py`）：历史探测自动总结为
  结构化策略（手法序列×防御签名→成功率），pgvector 两级检索（签名过滤→语义排序），
  攻击受挫时注入 Top-K 策略——跨会话学习
- **手法挖掘**（`scripts/mine_operators.py` + `operator_gate.py`）：黑盒 autoresearch 循环，
  新算子过质量门（dev 集固定 token 预算，held-out 复验）才入库
- **判定管线**（`judge.py`）：RegexJudge + LLMJudge + PromptGuardJudge，
  输出 verdict + reason/evidence + **防御签名** + **路径偏差**；
  Agent 场景支持轨迹证据判定（幻觉执行单独一类签名）
- **历史账本**（`probe_runs.py`）：append-only，每次执行一行带模型版本快照
- **平台过滤识别**：智谱 1301 / 百炼 data_inspection_failed → `platform_filter`

## 三大能力

### 1. 数据集（dataset/，活基准）

三层构成（零人工标注）：

- **静态种子**：11 种子 × 4 变异算子 + JailbreakBench → 531 条带谱系样本（回归基线）
- **开源集**：SafeDialBench 中文多轮 198 条 + CoSafe 200 条（官方标签 +
  语义漂移自动检测）+ MHJ（授权受限，脚本就绪待 HF token）
- **dynamic 轨迹**：动态红队产出自动入库（生成即标注），增量超 50 条
  自动打包新版本（`version_dataset.py`）

置信度口径：高置信（多票一致）/ 预标采信 / 低置信降权（不占 ASR 分母）。

```bash
python -m scripts.build_dataset            # 构建静态种子数据集
python -m scripts.safedial_convert         # SafeDialBench 中文子集
python -m scripts.cosafe_convert           # CoSafe（含漂移检测）
python -m scripts.mhj_convert              # MHJ（需 HF_TOKEN，授权受限）
python -m scripts.rejudge_multiturn        # 多轮样本三票自动重判
python -m scripts.run_dynamic --n 10       # 动态红队跑数
python -m scripts.harvest_dynamic_traces   # 轨迹入库（生成即标注）
python -m scripts.version_dataset          # 活基准版本化
```

### 2. 判官（judge）

- 三级漏斗：regex 定论零成本直出 → Prompt Guard 86M（CPU，毫秒级）筛查 → LLM 终裁
- 黄金集驱动的 P/R 度量与回归门禁：P/R 跌了就报警
- 异构裁判：三个判官错误模式不重合（判官评估报告里的 error_overlap 就是证据）

```bash
# 黄金集评估（RegexJudge 单独 / LLMJudge 单独 / 双通道 / Prompt Guard / 漏斗）
python -m scripts.judge_eval --golden dataset/v1.0/golden.jsonl
# 保存基线 / 回归对比
python -m scripts.judge_eval --golden golden.jsonl --save-baseline
python -m scripts.judge_eval --golden golden.jsonl --baseline dataset/v1.0/judge_baseline.json
```

### 3. 报告（report）

- 跑批结束自动生成 Markdown 报告：ASR 矩阵、翻转告警（历史对比 verdict 变化标红）、
  成本统计、典型 case
- 在线报表 API：`GET /reports/summary`（probe_runs 账本聚合）

```bash
python -m scripts.run_batch --targets targets.json --limit 20   # 先冒烟！
python -m scripts.run_batch --targets targets.json              # 全量
python -m scripts.sample_golden                                 # 分层抽样出黄金集
python -m scripts.asr_matrix --golden dataset/v1.0/golden.jsonl # ASR 矩阵
python -m scripts.generate_report --compare <上一版结果.jsonl>   # 完整报告
python -m scripts.report_v2                                     # 机制级分析（手法×模型 / 防御签名×手法）
python -m scripts.pair_compare --targets targets.json           # 模板 vs PAIR 对照
```

## 多轮探测：从手写循环到 LangGraph 图

多轮探测 Agent 有两个完全等价的实现：`run_probe`（手写 for 循环）与
`run_probe_graph`（LangGraph StateGraph）。控制流搬家，业务逻辑零改动。

```mermaid
flowchart LR
    Start([开始]) --> Decide[decide 节点<br/>Agent 决策 / PAIR attacker]
    Decide -->|action = stop| End([结束])
    Decide -->|继续| Attack[attack 节点<br/>发靶模型 + 判定]
    Attack -->|should_stop 命中<br/>节点写 stop_reason| End
    Attack -->|stop_reason 为空<br/>边只读不写| Decide
```

设计文档（含判定哲学、记忆系统、注入防御）：[docs/multi-turn-agent-design.md](docs/multi-turn-agent-design.md)

### 两版对照

| 维度 | 手写循环 `run_probe` | LangGraph 图 `run_probe_graph` |
|---|---|---|
| 控制流 | for 循环 + if 终止 | StateGraph + 条件边 |
| 状态载体 | 函数局部变量 | `ProbeState` TypedDict（显式 schema） |
| 轮次递增 | 循环体首行 | `decide_node` 唯一递增点 |
| 终止判断 | `should_stop()` 调用点 | `attack_node` 写 `stop_reason`，边纯读 |
| 外部依赖 | 函数参数直接传 | 工厂闭包注入（db 不进 State） |
| 可观测性 | 日志 | 日志 + 图结构可视化 + State 快照 |

### 边界设计原则

- **进 State**：`conversation` / `turns` / `verdicts` / `round_no` / `stop_reason` ——图内流转的数据，用 `Annotated[list, add]` reducer 声明式合并
- **不进 State**：db client / `TargetModel` / env 配置——client 不可 JSON 序列化，进 State 将来接 checkpointer 直接炸；依赖用工厂闭包注入节点
- **单一写入口**：`stop_reason` 只在 `attack_node` 写，条件边只读不写——消除双份逻辑漂移

## 截图

| 任务列表 | 任务详情 + 探测时间线 | 攻击模式库 |
|---|---|---|
| ![任务列表](docs/screenshots/task-list.png) | ![探测时间线](docs/screenshots/task-detail-timeline.png) | ![模式库](docs/screenshots/patterns.png) |

## 工程化

- `Dockerfile` + `docker-compose.yml`：`docker-compose up` 一键起
- GitHub Actions（`.github/workflows/ci.yml`）：PR 触发单测 + 数据集构建回归 +
  判官回归冒烟（20 条黄金集，需 secrets，单次 API 成本 < 1 美元）
- 测试：`python -m unittest discover tests -v`（100+ 单测，LLM/DB 全 mock）

## 已知局限（诚实清单）

- ~~重跑覆盖式（DELETE + INSERT）~~ **已修（Sprint 0）**：probe_runs append-only，历史完整保留
- `agent_state` 压缩未实现（MAX_ROUNDS=8 默认触不到压缩线）
- 后台探测持用户 JWT（1 小时过期）；实例重启丢后台任务，任务停在"执行中"（待加超时清扫）
- `agent_graph.py` 暂不支持 PAIR 模式（PAIR 走手写循环 `run_probe`，即 `/probe` 端点所用实现）
- Agent 场景基准（AgentDojo）需单独 `pip install agentdojo`，见 `scripts/agentdojo_run.py`
