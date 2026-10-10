# OWASP LLM Top 10（2025）覆盖映射表

11 类种子模式 + 变体 与 OWASP LLM Top 10 的逐条对照。
"变体增强"指变异算子提升了该条目下的覆盖深度（如 base64_wrap 增强 LLM01 的编码绕过子类）。

| OWASP 条目 | 覆盖的种子模式 | 变体增强 | 覆盖度 |
|---|---|---|---|
| LLM01 Prompt Injection | seed-01 角色扮演 / seed-02 忽略指令 / seed-03 模拟执行 / seed-04 DAN / seed-05 目标劫持 / seed-07 表情包绕过 / seed-08 直接有害 / seed-09 权威伪装 / seed-10 间接注入 | 全部 4 算子（语义改写、Base64、角色壳、轮次拆分均作用于注入载荷） | ★★★ 深 |
| LLM02 Sensitive Information Disclosure | seed-10 间接注入 / seed-11 敏感信息套取 | synonym_rewrite | ★★ 中 |
| LLM03 Supply Chain | — | — | ✗ 未覆盖（见下） |
| LLM04 Data and Model Poisoning | — | — | ✗ 未覆盖（见下） |
| LLM05 Improper Output Handling | — | — | ✗ 未覆盖（见下） |
| LLM06 Excessive Agency | seed-05 目标劫持 / seed-08 直接有害 / seed-11 敏感套取 | role_play_shell | ★ 浅（黑盒无工具调用面） |
| LLM07 System Prompt Leakage | seed-02 忽略指令 / seed-06 提示词泄露 / seed-09 权威伪装 | base64_wrap、turn_split | ★★★ 深 |
| LLM08 Vector and Embedding Weaknesses | seed-10 间接注入（检索内容带毒场景） | — | ★ 浅 |
| LLM09 Misinformation | seed-09 权威伪装（冒充来源） | — | ★ 浅 |
| LLM10 Unbounded Consumption | — | — | ✗ 未覆盖（见下） |

## 未覆盖条目与原因（写清楚，不回避）

- **LLM03 Supply Chain**：针对模型/插件/依赖供应链（恶意微调模型、投毒插件）。
  本平台测的是"已部署模型的对话面"，没有模型供应链的测试面。属平台级尽职调查，非黑盒对抗样本。
- **LLM04 Data and Model Poisoning**：投毒发生在训练/微调阶段，黑盒 API 无法注入训练数据。
  需要白盒或训练管线权限，超出本平台范围。
- **LLM05 Improper Output Handling**：测的是"下游系统如何处理模型输出"（XSS、SQL 注入经由 LLM 输出）。
  需要一个真实的下游消费系统作靶，本平台只到模型响应为止。Sprint 5 的 AgentDojo 间接注入场景部分触及（工具消费输出）。
- **LLM10 Unbounded Consumption**：拒绝服务/资源耗尽（长上下文轰炸、高频请求）。
  属于容量与限流测试，与"判定攻击是否成功"的语义判定管线不兼容，且有真实成本与合规风险，主动不做。

## 浅覆盖条目的补强路径

- **LLM06 Excessive Agency**：Sprint 5 接入 AgentDojo 后加深（工具调用面的越权）。
- **LLM08**：需要 RAG 靶场，列入 Phase 3 候选（自建检索管道 + 投毒文档）。
