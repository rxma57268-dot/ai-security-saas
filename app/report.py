"""在线报表聚合（Sprint 6）：从 probe_runs 历史账本算 ASR 矩阵 + 翻转告警。

数据源是 Sprint 0 的 append-only 账本——同一任务多次执行的 verdict 变化
（翻转）正是这个报表要暴露的信号。

GET /reports/summary 返回：
  asr_matrix   {model: {category: {success, refusal, partial, total, asr}}}
  flips        同一任务最新 run 与前一 run final_verdict 不一致的列表
  cost         按靶模型汇总的 token 用量
  runs         run 总数
"""

from collections import defaultdict
from typing import Any

from supabase import Client

RUNS_TABLE = "probe_runs"
TASKS_TABLE = "test_tasks"
PATTERNS_TABLE = "attack_patterns"


def _asr_cell() -> dict[str, Any]:
    return {"success": 0, "refusal": 0, "partial": 0, "total": 0, "asr": None}


def build_summary(db: Client) -> dict[str, Any]:
    """汇总当前用户的探测历史（RLS 限定）为报表。"""
    runs = (
        db.table(RUNS_TABLE)
        .select("id,task_id,target_model,final_verdict,rounds,"
                "prompt_tokens,completion_tokens,created_at,probe_mode")
        .order("created_at")
        .execute()
    ).data or []
    if not runs:
        return {"asr_matrix": {}, "flips": [], "cost": {}, "runs": 0}

    # task → pattern → attack_category（三次查询内存 join，MVP 规模够用）
    task_ids = list({r["task_id"] for r in runs})
    tasks = (
        db.table(TASKS_TABLE)
        .select("id,attack_pattern_id,target_name")
        .in_("id", task_ids)
        .execute()
    ).data or []
    pattern_ids = list({t["attack_pattern_id"] for t in tasks if t.get("attack_pattern_id")})
    patterns = (
        db.table(PATTERNS_TABLE)
        .select("id,attack_category")
        .in_("id", pattern_ids)
        .execute()
    ).data or [] if pattern_ids else []

    task_map = {t["id"]: t for t in tasks}
    pattern_map = {p["id"]: p for p in patterns}

    def category_of(run: dict[str, Any]) -> str:
        task = task_map.get(run["task_id"]) or {}
        pattern = pattern_map.get(task.get("attack_pattern_id")) or {}
        return pattern.get("attack_category") or "unknown"

    # 1. ASR 矩阵：target_model × attack_category
    matrix: dict[str, dict[str, dict[str, Any]]] = defaultdict(
        lambda: defaultdict(_asr_cell)
    )
    for run in runs:
        verdict = run.get("final_verdict")
        if verdict not in ("attack_success", "defense_success", "uncertain"):
            continue
        cell = matrix[run.get("target_model") or "unknown"][category_of(run)]
        key = {"attack_success": "success", "defense_success": "refusal"}[verdict] \
            if verdict != "uncertain" else "partial"
        cell[key] += 1
        cell["total"] += 1
    for cats in matrix.values():
        for cell in cats.values():
            if cell["total"]:
                cell["asr"] = round(cell["success"] / cell["total"], 4)

    # 2. 翻转告警：同一任务最新 run 与前一 run 的 final_verdict 不一致
    by_task: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for run in runs:
        if run.get("final_verdict"):
            by_task[run["task_id"]].append(run)
    flips = []
    for task_id, task_runs in by_task.items():
        if len(task_runs) < 2:
            continue
        prev, latest = task_runs[-2], task_runs[-1]
        if prev["final_verdict"] != latest["final_verdict"]:
            flips.append(
                {
                    "task_id": task_id,
                    "target_name": (task_map.get(task_id) or {}).get("target_name"),
                    "target_model": latest.get("target_model"),
                    "before": prev["final_verdict"],
                    "after": latest["final_verdict"],
                    "before_run_id": prev["id"],
                    "after_run_id": latest["id"],
                    "at": latest.get("created_at"),
                }
            )

    # 3. 成本：按靶模型汇总 token
    cost: dict[str, dict[str, int]] = defaultdict(
        lambda: {"runs": 0, "prompt_tokens": 0, "completion_tokens": 0}
    )
    for run in runs:
        c = cost[run.get("target_model") or "unknown"]
        c["runs"] += 1
        c["prompt_tokens"] += int(run.get("prompt_tokens") or 0)
        c["completion_tokens"] += int(run.get("completion_tokens") or 0)

    # 4. v3 Sprint 6：策略库命中统计——注入策略的轮次数、覆盖 run 数、
    #    以及这些 run 的 ASR（策略库价值的直接度量）
    strategy_stats: dict[str, Any] = {
        "injected_turns": 0, "runs_with_strategy": 0, "asr_when_used": None
    }
    if run_ids := [r["id"] for r in runs]:
        try:
            strat_turns = (
                db.table("probe_turns")
                .select("probe_run_id")
                .in_("probe_run_id", run_ids)
                .not_.is_("strategies_used", "null")
                .execute()
            ).data or []
        except Exception:
            strat_turns = []  # 迁移未执行时不阻塞报表
        strategy_stats["injected_turns"] = len(strat_turns)
        used_run_ids = {t["probe_run_id"] for t in strat_turns}
        strategy_stats["runs_with_strategy"] = len(used_run_ids)
        used_runs = [r for r in runs if r["id"] in used_run_ids]
        if used_runs:
            wins = sum(
                1 for r in used_runs if r.get("final_verdict") == "attack_success"
            )
            strategy_stats["asr_when_used"] = round(wins / len(used_runs), 4)

    return {
        "asr_matrix": {m: dict(cats) for m, cats in matrix.items()},
        "flips": flips,
        "cost": dict(cost),
        "strategy_stats": strategy_stats,
        "runs": len(runs),
    }
