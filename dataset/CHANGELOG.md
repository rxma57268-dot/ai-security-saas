# 数据集 CHANGELOG

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
