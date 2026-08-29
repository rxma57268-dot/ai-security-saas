-- 多轮探测 Agent 的存储迁移
-- 设计依据：docs/multi-turn-agent-design.md 第 3、4 节

-- 1. 探测轮次表：Agent 每轮的 thought / action / payload / response / 判定
create table if not exists probe_turns (
  id uuid primary key default gen_random_uuid(),
  task_id uuid not null references test_tasks(id) on delete cascade,
  round_no int not null,
  agent_thought text,          -- Agent 的推理（ReAct 的 Thought）
  action text,                 -- follow_up / switch_pattern / verify_hijack / stop
  pattern_id uuid,             -- 本轮选用的攻击模式（可空：自由追问时没有）
  payload text not null,       -- 发给靶模型的内容
  response text,               -- 靶模型响应
  verdict text,                -- 本轮裁判结果：attack_success / defense_success / uncertain
  verdict_source text,         -- regex / llm / platform_filter
  created_at timestamptz default now(),
  unique (task_id, round_no)
);

create index if not exists probe_turns_task_id_idx on probe_turns(task_id);

-- RLS：与 test_tasks 一致的隔离粒度——只能访问自己任务的轮次
alter table probe_turns enable row level security;

create policy "probe_turns_select_own" on probe_turns for select
  using (exists (
    select 1 from test_tasks
    where test_tasks.id = probe_turns.task_id
      and test_tasks.user_id = auth.uid()
  ));

create policy "probe_turns_insert_own" on probe_turns for insert
  with check (exists (
    select 1 from test_tasks
    where test_tasks.id = probe_turns.task_id
      and test_tasks.user_id = auth.uid()
  ));

-- 2. test_tasks 加 Agent 状态列：压缩后的结构化摘要（长期记忆之短期部分）
alter table test_tasks
  add column if not exists agent_state jsonb;

-- 2.5 test_tasks 加终止原因列：探测为什么停（attack_success / consecutive_defense_success /
--     max_rounds / platform_filter / agent_stop / agent_output_*），此前只在返回值和日志里
alter table test_tasks
  add column if not exists stop_reason text;

-- 3. attack_patterns 加成功率统计：长期记忆的"学习"闭环
alter table attack_patterns
  add column if not exists use_count int not null default 0,
  add column if not exists success_count int not null default 0;
