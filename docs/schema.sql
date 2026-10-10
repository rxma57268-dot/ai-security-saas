-- 基础表 schema（全新 Supabase 项目的第 0 步，先于其余迁移执行）
-- 重建自 schemas.py + 代码用法；幂等。执行顺序：
--   schema.sql → attack_patterns_v2.sql → multi_turn_agent.sql
--   → sprint0_probe_runs.sql → v3_dynamic_redteam.sql

-- ============================================================
-- attack_patterns：攻击模式库
-- ============================================================
create table if not exists attack_patterns (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null default auth.uid(),
    name text not null,
    attack_category text,          -- prompt_injection/data_poisoning/tool_abuse/
                                   -- memory_tampering/privilege_escalation/
                                   -- info_leakage/jailbreak
    attack_sub_type text,
    target_component text,         -- llm_core/tool_chain/skill_system/mcp_server/
                                   -- memory/state_manager/rag_pipeline
    attack_vector text,            -- user_input/external_doc/api_call/upload_file/
                                   -- third_party_skill/mcp_response/memory_rw
    payload_template text,         -- 支持 {{var}} 占位符
    payload_encoding text default 'plain',
    precondition text,
    default_severity text default 'medium',  -- critical/high/medium/low/info
    cwe_id text,
    mitigation text,
    -- success_patterns / refusal_patterns 由 attack_patterns_v2.sql 添加（jsonb）
    created_at timestamptz not null default now()
);

alter table attack_patterns enable row level security;

drop policy if exists "patterns_select_own" on attack_patterns;
create policy "patterns_select_own" on attack_patterns for select
    using (user_id = auth.uid());
drop policy if exists "patterns_insert_own" on attack_patterns;
create policy "patterns_insert_own" on attack_patterns for insert
    with check (user_id = auth.uid());
drop policy if exists "patterns_update_own" on attack_patterns;
create policy "patterns_update_own" on attack_patterns for update
    using (user_id = auth.uid());
drop policy if exists "patterns_delete_own" on attack_patterns;
create policy "patterns_delete_own" on attack_patterns for delete
    using (user_id = auth.uid());

-- ============================================================
-- test_tasks：测试任务
-- ============================================================
create table if not exists test_tasks (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null default auth.uid(),
    attack_pattern_id uuid references attack_patterns(id),
    target_name text not null,
    target_url text,
    payload text not null,
    execution_method text default '手动',   -- 手动/自动脚本/fuzz
    tool_used text,
    status text not null default '待执行',  -- 待执行/执行中/完成/失败
    is_success boolean,
    severity text,
    impact_scope text,             -- 单用户/全部用户/系统级/数据级
    actual_behavior text,
    expected_behavior text,
    evidence text,
    regression_tested boolean not null default false,
    -- 判定结果字段直接放基础表（历史上 verdict 由 multi_turn_agent.sql 添加、
    -- verdict_source/needs_review 只存在于线上库——全新部署不再有这个坑）
    verdict text,                  -- attack_success/defense_success/uncertain
    verdict_source text,           -- regex/llm/prompt_guard/funnel_*/platform_filter
    needs_review boolean,
    -- judge_reason / judge_evidence / target_model / latest_probe_run_id
    -- 由 sprint0_probe_runs.sql 添加；defense_signature 由
    -- v3_dynamic_redteam.sql 添加；agent_state / stop_reason 由
    -- multi_turn_agent.sql 添加（幂等，重复执行不冲突）
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists test_tasks_user_idx on test_tasks(user_id, created_at desc);

alter table test_tasks enable row level security;

drop policy if exists "tasks_select_own" on test_tasks;
create policy "tasks_select_own" on test_tasks for select
    using (user_id = auth.uid());
drop policy if exists "tasks_insert_own" on test_tasks;
create policy "tasks_insert_own" on test_tasks for insert
    with check (user_id = auth.uid());
drop policy if exists "tasks_update_own" on test_tasks;
create policy "tasks_update_own" on test_tasks for update
    using (user_id = auth.uid());
drop policy if exists "tasks_delete_own" on test_tasks;
create policy "tasks_delete_own" on test_tasks for delete
    using (user_id = auth.uid());
