"""机制级分析报告（Day 5，学 JBF）：在 ASR 矩阵之外加两个机制矩阵。

1. attack_sub_type × 靶模型：细粒度手法（指代/场景构造/目的反转/角色扮演…）
   对哪个模型最有效——手法级攻击面画像
2. defense_signature × 手法：模型的防御姿态（硬拒绝/软拒绝/平台拦截…）
   在面对哪类手法时出现——防御机制画像（本平台独有维度）

数据源：batch_results*.jsonl（含 v3 字段）+ dynamic_traces.jsonl。
旧数据无 defense_signature 的行归入"unknown"。

用法：
  python -m scripts.report_v2 --out report/mechanism.md
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _load(paths: list[Path]) -> list[dict[str, Any]]:
    rows = []
    for p in paths:
        if p.exists():
            rows.extend(
                json.loads(l)
                for l in p.read_text(encoding="utf-8").splitlines()
                if l.strip()
            )
    return rows


def _technique(row: dict[str, Any]) -> str:
    """手法标签：优先 attack_sub_type，其次变异链首算子，否则原始。"""
    if row.get("attack_sub_type"):
        return row["attack_sub_type"]
    chain = row.get("mutation_chain") or []
    return chain[0].split(":")[0] if chain else "original"


def _matrix(
    rows: list[dict[str, Any]], row_key, col_key
) -> dict[str, dict[str, dict[str, int]]]:
    m: dict[str, dict[str, dict[str, int]]] = defaultdict(
        lambda: defaultdict(lambda: {"success": 0, "total": 0})
    )
    for r in rows:
        if r.get("verdict") not in ("attack_success", "defense_success"):
            continue
        cell = m[row_key(r)][col_key(r)]
        cell["total"] += 1
        if r["verdict"] == "attack_success":
            cell["success"] += 1
    return m


def _render(title: str, m: dict, col_label: str) -> list[str]:
    lines = [f"## {title}", ""]
    cols = sorted({c for row in m.values() for c in row})
    lines.append(f"| {col_label} | " + " | ".join(cols) + " |")
    lines.append("|" + "---|" * (len(cols) + 1))
    for rk in sorted(m):
        cells = []
        for c in cols:
            cell = m[rk].get(c)
            if not cell or not cell["total"]:
                cells.append("—")
            else:
                asr = cell["success"] / cell["total"]
                cells.append(f"{asr:.0%} ({cell['success']}/{cell['total']})")
        lines.append(f"| {rk} | " + " | ".join(cells) + " |")
    lines.append("")
    return lines


def build_report(rows: list[dict[str, Any]]) -> str:
    lines = ["# 机制级红队分析", ""]
    lines += _render(
        "手法 × 靶模型 ASR 矩阵",
        _matrix(rows, _technique, lambda r: r.get("model") or "unknown"),
        "手法（attack_sub_type / 变异链首算子）",
    )
    lines += _render(
        "防御签名 × 手法分布（本平台独有维度）",
        _matrix(
            rows,
            _technique,
            lambda r: r.get("defense_signature") or "unknown",
        ),
        "手法",
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="机制级分析报告")
    parser.add_argument("--out", default=str(ROOT / "report" / "mechanism.md"))
    args = parser.parse_args()

    base = ROOT / "dataset" / "v1.0"
    rows = _load([
        base / "batch_results.jsonl",
        base / "batch_results_ext.jsonl",
        base / "dynamic_traces.jsonl",
    ])
    md = build_report(rows)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(md + "\n", encoding="utf-8")
    print(f"机制报告 → {args.out}")
    print(md[:800])


if __name__ == "__main__":
    main()
