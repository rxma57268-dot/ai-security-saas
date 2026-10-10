# 数据集 CHANGELOG

## 开源集接入（2026-10-10）

- **SafeDialBench 中文子集 198 条**（`safedialbench.jsonl`）：多轮安全对话，
  官方任务设计即标签（生成即标注）。手法分布：场景构造 50 / 参考攻击 40 /
  目的反转 38 / 探针提问 26 / 角色扮演 25 / 谬误攻击 13 / 话题转移 6
- **CoSafe 200 条**（`cosafe.jsonl`）：官方类别标签 + 语义漂移自动检测
  （embedding 优先；GLM embedding 额度耗尽时词面 Jaccard 兜底，
  分位数口径打标 drift_suspect 47 条降权）
- **MHJ 未接入**：ScaleAI/mhj 与镜像均为 HF 授权受限仓库（401），
  `mhj_convert.py` 已就绪，配 HF_TOKEN 后一键转换
- 两个开源集已对 glm-4-flash 全量跑批（`batch_results_ext.jsonl` 398 行，
  欠费期间仅 GLM 可用）

## 活基准机制（living benchmark，2026-10-10 起）
数据集不再冻结，随使用自动生长：

- **三层构成**：静态种子（`attacks.jsonl`，回归用）+ 开源集
  （JailbreakBench/SafeDialBench/CoSafe，广度用）+ dynamic 轨迹
  （`dynamic_traces.jsonl`，差异化用——动态红队的产出自动入库）
- **生成即标注**：dynamic 轨迹的 judge 判定结果就是标签，不人工标注；
  裁判分歧/uncertain 的行标 `needs_review=true` + 低置信降权
- **版本化**：`python -m scripts.version_dataset`，dynamic 轨迹新增
  ≥50 条自动打包新版本（v1.1、v1.2…），旧版本目录保留保证可复现
- **置信度口径**：confidence ∈ high / prelabel / low；
  low 行不占 ASR 分母（asr_matrix / judge_eval 均实现）

## v1.0（2026-09-14）

首个版本化数据集。

- **种子**：11 个自建攻击模式（`dataset/seeds.jsonl`），覆盖 prompt_injection /
  jailbreak / info_leakage / privilege_escalation 四大类。
- **变异算子**：4 个，覆盖语义（synonym_rewrite）、编码（base64_wrap）、
  社会工程（role_play_shell）、时序（turn_split）四个正交维度。
- **变异链**：种子 21 条链（单算子 + 两两组合），公开基准 3 条代表链
  （成本约束，见 scripts/build_dataset.py 注释）。
- **规模**：231 条带谱系样本（种子部分）+ 300 条 JailbreakBench
  （100 behaviors × 3 链），合计 **531 条**（已构建入库）。
- **谱系字段**：每条含 `pattern_id` / `mutation_chain` / `difficulty` /
  `expected_verdict` / `source` / `owasp`。
- **多轮样本**：66 条（turn_split 产出，存 `turns` 数组）。
- **OWASP 映射**：见 `docs/owasp_llm_top10_mapping.md`。
- **JailbreakBench 获取**：`scripts/jbb_convert.py` 双路径（pip 包优先，
  HF 数据集 CSV 直读兜底——jailbreakbench 钉死 litellm~=1.20.0 装不上时
  用兜底路径，已实测可用）。

### 首次全量跑批（2026-09-15）

- 靶模型：glm-4-flash（518/531 有效，13 条 GLM 端挂起超时放弃）+
  qwen-flash（531/531 全有效）
- 裁判：glm-4-air（JUDGE_MODE=both）
- 平台过滤归类：智谱 1301 与百炼 data_inspection_failed 均记
  defense_success / platform_filter，不算执行错误
- 报告：`report/latest.md`（自动生成）

### 多轮管线修复 + 重跑（2026-09-16）

- **bug1**：多轮样本曾把多条 user 消息塞进单次调用（模型复读铺垫轮）。
  修复为逐轮真实对话，判定末轮响应，中间轮存入 `turn_responses`
- **bug2**：中间轮失败时拿残留回复判定（`completed` 标志修复——
  全部轮次完成才进判定）
- **bug3**：跑批结果不落 `payload` 字段（预标看不到攻击内容）。
  修复后 payload/turns 随结果落盘
- 受影响 132 行全部重跑；glm 侧 6 条多轮 + 13 条 JBB 持续挂起超时放弃，
  最终 glm 512/531（96.4%）、qwen 531/531
- 预标：glm-4-air 余额中途耗尽（1113），79 条失败行用 glm-4-flash 补标
  63 条；剩余 16 条裁判提示词本身被 1301 过滤，只能纯人工标注
- 黄金集重抽样 + 重预标 + 审阅表 `golden_review.csv` 重新导出

### 零人工标注转型（2026-10-10）

220 条黄金集全部完成自动化判定，零人工标注：

- **176 条单轮**：采信预标（confidence=prelabel）
- **44 条多轮**：`scripts/rejudge_multiturn.py` funnel 三票制自动重判
  （regex + LLM + Prompt Guard 矛盾检测；regex 的 uncertain 视为弃权）。
  34 条三票一致 → 高置信；10 条 LLM uncertain → 低置信降权
- **10 条预标失败**（裁判提示词被平台 1301 过滤）→ 低置信降权
- 低置信度共 20 条：`needs_review=true` 但不人工审核，报告单独列出，
  **不占 ASR 分母**（asr_matrix / judge_eval 均已实现该口径）
- Prompt Guard 未参与本轮：meta-llama/Prompt-Guard-86M 是 HF 受限仓库，
  需 HF token（待补）；本轮漏斗降级为 regex+LLM 两票
- 验证：`python -m scripts.import_review --status` → 220/220 已处理
  （高置信 34 / 预标采信 166 / 低置信降权 20）

### 判官基线（2026-09-16，临时版）
- `judge_baseline.json`：regex + both 双模式，dev 集 153 条，
  裁判临时用 glm-4-flash（百炼欠费期间）；**百炼充值 + 人工标注完成后，
  须用生产裁判（deepseek-v4.1-flash）重新生成**：
  `python -m scripts.judge_eval --golden dataset/v1.0/golden.jsonl --judges regex both --save-baseline`
- 基线含 meta 溯源字段（judge_model / split / 样本数）
- 当前数字（预标口径）：regex P/R=0/0（地板基线，规则裁判字面匹配的
  固有盲区）、both P=94.7% R=20.2%（R 偏低是预标噪声，待人工标注校准）

### 构建方式

```bash
# 离线（规则改写，可复现）
python -m scripts.build_dataset
# LLM 同义改写（glm-4-flash 级，成本 < 2 美元）
python -m scripts.build_dataset --use-llm
# 先接入公开基准
pip install jailbreakbench && python -m scripts.jbb_convert
python -m scripts.build_dataset
```

### 版本规则

- 目录即版本：`dataset/v{major}.{minor}/`
- major：种子/算子/字段结构的破坏性变更；minor：样本增补、规则修正
- 每次变更必须更新本 CHANGELOG 并随 Git 提交

## v1.1（2026-10-10）

- 自 v1.0 以来新增 dynamic 轨迹 9 条
- 打包文件：attacks.jsonl, jailbreakbench.jsonl, golden.jsonl, golden_review.csv, judge_baseline.json, dynamic_traces.jsonl, safedialbench.jsonl, cosafe.jsonl
- 主要发现：首次动态红队轨迹入库（9 条，dynamic 模式首跑验证）
