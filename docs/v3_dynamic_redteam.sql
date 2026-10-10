-- v3 动态红队架构迁移：防御签名落库 + 攻击策略库（pgvector）
-- 在 Supabase SQL Editor 执行（须在 sprint0_probe_runs.sql 之后）。幂等。

-- ============================================================
-- 1. 防御签名 / 路径偏差字段（v3 Sprint 0：策略库两级检索依赖）
-- ============================================================
alter table probe_turns add column if not exists defense_signature text;
alter table probe_turns add column if not exists path_deviation text;
-- v3 Sprint 4A：手法序列（Attacker 工具调用链）落库——策略库挖掘的数据源
alter table probe_turns add column if not exists tool_calls jsonb;
-- v3 Sprint 4C：策略库命中记录（报告的策略命中统计用）
alter table probe_turns add column if not exists strategies_used jsonb;
alter table probe_runs add column if not exists defense_signature text;
alter table probe_runs add column if not exists path_deviation text;
alter table test_tasks add column if not exists defense_signature text;

create index if not exists probe_turns_signature_idx on probe_turns(defense_signature);

-- ============================================================
-- 2. 攻击策略库（v3 Sprint 4C）：结构化策略 + pgvector 语义检索
--    策略记录格式（锁定决策）：手法序列 + 防御签名 + 成功率，
--    不存自由文本叙事（无法加权排序，伪策略会污染库）
-- ============================================================
create extension if not exists vector;

create table if not exists attack_strategies (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null default auth.uid(),
    -- 手法序列：如 ["role_play_shell", "synonym_rewrite"]（有序，顺序敏感）
    technique_sequence jsonb not null,
    -- 该策略针对的防御签名（两级检索的第一级过滤条件）
    defense_signature text not null,
    -- 统计字段：成功率 = successes / trials（挖掘管线聚合自 probe_turns）
    trials int not null default 0,
    successes int not null default 0,
    success_rate float generated always as (
        case when trials > 0 then successes::float / trials else null end
    ) stored,
    -- 典型会话引用（probe_turns id 列表）+ 谱系（从哪些策略/挖掘演化而来）
    example_turn_ids jsonb,
    lineage jsonb,
    -- 语义检索向量（embedding-3，2048 维；内容为手法序列+目标场景的描述文本）
    embedding vector(2048),
    -- 入库门禁（防 reward hacking）：pending → approved / rejected
    -- 裁判初筛 + needs_review 抽检 + 黄金集复核后才转 approved
    status text not null default 'pending',
    created_at timestamptz not null default now()
);

create index if not exists attack_strategies_signature_idx
    on attack_strategies(defense_signature, status);

-- pgvector 余弦相似度索引（数据量小，用 ivfflat 足够）
create index if not exists attack_strategies_embedding_idx
    on attack_strategies using ivfflat (embedding vector_cosine_ops)
    with (lists = 10);

alter table attack_strategies enable row level security;

drop policy if exists "strategies_select_own" on attack_strategies;
create policy "strategies_select_own" on attack_strategies for select
    using (user_id = auth.uid());

drop policy if exists "strategies_insert_own" on attack_strategies;
create policy "strategies_insert_own" on attack_strategies for insert
    with check (user_id = auth.uid());

drop policy if exists "strategies_update_own" on attack_strategies;
create policy "strategies_update_own" on attack_strategies for update
    using (user_id = auth.uid());

-- ============================================================
-- 3. 两级检索 RPC：防御签名过滤 → 语义相似度排序（成功率加权）
--    PostgREST 对 vector 类型的过滤支持有限，用 SQL 函数收口
-- ============================================================
create or replace function match_strategies(
    query_embedding vector(2048),
    filter_signature text,
    match_count int default 3
)
returns table (
    id uuid,
    technique_sequence jsonb,
    defense_signature text,
    trials int,
    successes int,
    success_rate float,
    example_turn_ids jsonb,
    similarity float,
    score float
)
language sql stable
as $$
    select
        s.id,
        s.technique_sequence,
        s.defense_signature,
        s.trials,
        s.successes,
        s.success_rate,
        s.example_turn_ids,
        1 - (s.embedding <=> query_embedding) as similarity,
        -- 成功率加权：语义相似度 × (0.5 + 成功率)，低成功率策略沉底
        (1 - (s.embedding <=> query_embedding)) * (0.5 + coalesce(s.success_rate, 0)) as score
    from attack_strategies s
    where s.status = 'approved'
      and s.user_id = auth.uid()
      and s.defense_signature = filter_signature
      and s.embedding is not null
    order by score desc
    limit match_count;
$$;
