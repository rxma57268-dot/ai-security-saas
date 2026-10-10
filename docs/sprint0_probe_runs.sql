-- Sprint 0：修账本（append-only 探测历史 + verdict 绑定模型版本 + reason/evidence 落库）
-- 在 Supabase SQL Editor 执行。幂等：重复执行不报错。

-- ============================================================
-- 1. probe_runs：每次执行（单轮/多轮/跑批）一行历史，永不覆盖
-- ============================================================
create table if not exists probe_runs (
    id uuid primary key default gen_random_uuid(),
    task_id uuid not null references test_tasks(id) on delete cascade,
    entrypoint text,            -- execute（单轮）/ probe（多轮）/ batch（离线跑批）
    probe_mode text,            -- single / template / pair
    target_model text,          -- 靶模型版本快照（先存模型名字符串）
    judge_model text,           -- 裁判模型版本快照
    agent_model text,           -- Agent/attacker 模型版本快照
    rounds int,                 -- 实际执行的轮次
    final_verdict text,         -- attack_success / defense_success / uncertain
    verdict_source text,        -- regex / llm / prompt_guard / funnel_* / platform_filter
    needs_review boolean,
    stop_reason text,
    judge_reason text,          -- 裁判判定理由（Sprint 0 起落库）
    judge_evidence text,        -- 裁判证据原文片段
    prompt_tokens int,          -- 靶模型侧 token 成本
    completion_tokens int,
    started_at timestamptz,
    finished_at timestamptz,
    created_at timestamptz not null default now()
);

create index if not exists probe_runs_task_id_idx on probe_runs(task_id, created_at desc);

alter table probe_runs enable row level security;

-- RLS：与 probe_turns 同一思路——只能读写自己任务的 run
drop policy if exists "probe_runs_select_own" on probe_runs;
create policy "probe_runs_select_own" on probe_runs for select
    using (exists (
        select 1 from test_tasks
        where test_tasks.id = probe_runs.task_id
          and test_tasks.user_id = auth.uid()
    ));

drop policy if exists "probe_runs_insert_own" on probe_runs;
create policy "probe_runs_insert_own" on probe_runs for insert
    with check (exists (
        select 1 from test_tasks
        where test_tasks.id = probe_runs.task_id
          and test_tasks.user_id = auth.uid()
    ));

drop policy if exists "probe_runs_update_own" on probe_runs;
create policy "probe_runs_update_own" on probe_runs for update
    using (exists (
        select 1 from test_tasks
        where test_tasks.id = probe_runs.task_id
          and test_tasks.user_id = auth.uid()
    ));

-- ============================================================
-- 2. probe_turns：挂 run + 裁判理由/证据；唯一约束改为 (probe_run_id, round_no)
--    （append-only 后同一 task 的多个 run 都从 round_no=1 开始）
-- ============================================================
alter table probe_turns add column if not exists probe_run_id uuid references probe_runs(id);
alter table probe_turns add column if not exists judge_reason text;
alter table probe_turns add column if not exists judge_evidence text;

alter table probe_turns drop constraint if exists probe_turns_task_id_round_no_key;

-- 部分唯一索引：run 内轮次唯一；迁移前无归属（probe_run_id is null）的
-- 历史轮次不受约束，保持可查
drop index if exists probe_turns_run_round_uidx;
create unique index probe_turns_run_round_uidx
    on probe_turns(probe_run_id, round_no)
    where probe_run_id is not null;

create index if not exists probe_turns_run_id_idx on probe_turns(probe_run_id);

-- ============================================================
-- 3. test_tasks：裁判理由/证据 + 靶模型版本快照 + 最新 run 指针
--    （任务行仍是"最新一次结果的视图"，历史在 probe_runs）
-- ============================================================
alter table test_tasks add column if not exists judge_reason text;
alter table test_tasks add column if not exists judge_evidence text;
alter table test_tasks add column if not exists target_model text;
alter table test_tasks add column if not exists latest_probe_run_id uuid references probe_runs(id);
