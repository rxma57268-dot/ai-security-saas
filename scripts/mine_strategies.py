"""策略挖掘管线（v3 Sprint 4C）：历史探测数据 → 结构化策略库。

从跑批/探测历史按（手法序列 × 防御签名）聚合成功率，产出结构化策略
（锁定决策：不存自由文本叙事——无法加权排序，伪策略会污染库）。

输入优先级：probe_turns 导出（含 tool_calls + defense_signature 的最完整
数据源）> batch_results.jsonl（mutation_chain 充当手法序列，防御签名
可能缺失→按 none 聚合）。

产出：dataset/strategies.jsonl（status=pending，门禁：needs_review 抽检 +
黄金集复核后人工把 status 改 approved；或跑 scripts/strategy_review.py）。

用法：
  python -m scripts.mine_strategies --results dataset/v1.0/batch_results.jsonl
  python -m scripts.mine_strategies --turns probe_turns_export.jsonl
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

STRATEGIES_PATH = ROOT / "dataset" / "strategies.jsonl"

# 入库门槛：试验次数太少成功率无统计意义（防伪策略污染）
MIN_TRIALS = 3


def _technique_sequence_from_turns(turns: list[dict[str, Any]]) -> list[str]:
    """从一个 run 的轮次序列提取手法序列（dynamic 模式的 tool_calls）。"""
    seq: list[str] = []
    for t in turns:
        for c in t.get("tool_calls") or []:
            seq.append(c["tool"])
    return seq


def mine_from_batch(results: list[dict[str, Any]]) -> dict[tuple, dict[str, Any]]:
    """跑批数据聚合：（手法序列 × 防御签名）→ 试验/成功计数。"""
    cells: dict[tuple, dict[str, Any]] = defaultdict(
        lambda: {"trials": 0, "successes": 0, "example_ids": []}
    )
    for r in results:
        if r.get("verdict") not in ("attack_success", "defense_success"):
            continue
        seq = tuple(c.split(":")[0] for c in (r.get("mutation_chain") or []))
        key = (seq, r.get("defense_signature") or "none")
        cell = cells[key]
        cell["trials"] += 1
        if r["verdict"] == "attack_success":
            cell["successes"] += 1
            cell["example_ids"].append(r.get("sample_id"))
    return cells


def mine_from_turns(turns: list[dict[str, Any]]) -> dict[tuple, dict[str, Any]]:
    """probe_turns 聚合：按 probe_run_id 分组取手法序列与最终防御签名。"""
    by_run: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for t in turns:
        if t.get("probe_run_id"):
            by_run[t["probe_run_id"]].append(t)

    cells: dict[tuple, dict[str, Any]] = defaultdict(
        lambda: {"trials": 0, "successes": 0, "example_ids": []}
    )
    for run_id, run_turns in by_run.items():
        run_turns.sort(key=lambda t: t.get("round_no") or 0)
        seq = tuple(_technique_sequence_from_turns(run_turns))
        last = run_turns[-1]
        sig = last.get("defense_signature") or "none"
        key = (seq, sig)
        cells[key]["trials"] += 1
        if last.get("verdict") == "attack_success":
            cells[key]["successes"] += 1
            cells[key]["example_ids"].append(run_turns[-1].get("id"))
    return cells


def build_strategies(cells: dict[tuple, dict[str, Any]]) -> list[dict[str, Any]]:
    """聚合结果 → 结构化策略记录（过入库门槛 MIN_TRIALS）。"""
    strategies = []
    for (seq, sig), cell in sorted(
        cells.items(), key=lambda x: -(x[1]["successes"] / max(x[1]["trials"], 1))
    ):
        if cell["trials"] < MIN_TRIALS:
            continue
        strategies.append(
            {
                "technique_sequence": list(seq) or ["direct_send"],
                "defense_signature": sig,
                "trials": cell["trials"],
                "successes": cell["successes"],
                "success_rate": round(cell["successes"] / cell["trials"], 4),
                "example_turn_ids": cell["example_ids"][:5],
                "lineage": {"source": "mine_strategies", "parents": []},
                # 入库门禁：pending——裁判初筛 + 抽检 + 黄金集复核后转 approved
                "status": "pending",
            }
        )
    return strategies


def main() -> None:
    parser = argparse.ArgumentParser(description="策略挖掘管线")
    parser.add_argument("--results", default=None, help="batch_results.jsonl")
    parser.add_argument("--turns", default=None, help="probe_turns 导出 JSONL")
    parser.add_argument("--out", default=str(STRATEGIES_PATH))
    args = parser.parse_args()

    if not args.results and not args.turns:
        args.results = str(ROOT / "dataset" / "v1.0" / "batch_results.jsonl")

    if args.turns:
        rows = [
            json.loads(l)
            for l in Path(args.turns).read_text(encoding="utf-8").splitlines()
            if l.strip()
        ]
        cells = mine_from_turns(rows)
    else:
        rows = [
            json.loads(l)
            for l in Path(args.results).read_text(encoding="utf-8").splitlines()
            if l.strip()
        ]
        cells = mine_from_batch(rows)

    strategies = build_strategies(cells)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with Path(args.out).open("w", encoding="utf-8") as f:
        for s in strategies:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    print(f"聚合组合 {len(cells)} 个，过门槛（≥{MIN_TRIALS} 次试验）策略 {len(strategies)} 条")
    print(f"→ {args.out}（status=pending，门禁复核后改 approved 才会被 Attacker 检索到）")


if __name__ == "__main__":
    main()
