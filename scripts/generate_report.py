"""报告自动生成（Sprint 6）：一次跑批结束自动出 Markdown 报告。

内容四块（计划 DoD）：
  1. ASR 矩阵（模型 × 攻击类别）
  2. 翻转告警：与上一版跑批结果对比，同一样本同一模型的 verdict
     发生变化 → 标红（回归/模型行为漂移的早期信号）
  3. 成本统计：token 用量按模型汇总
  4. 典型 case：攻击成功 + 需人工复核的样本各抽几条

数据源：run_batch.py 产出的 results JSONL（在线 probe_runs 报表见 API /reports）。

用法：
  python -m scripts.generate_report \
      --results dataset/v1.0/batch_results.jsonl \
      --compare dataset/v0.9/batch_results.jsonl \
      --out report/latest.md
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.asr_matrix import compute_asr_matrix, render_markdown  # noqa: E402


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _label_from_verdict(row: dict[str, Any]) -> str:
    """跑批 verdict → ASR 口径标签（attack_success=success 等）。"""
    v = row.get("verdict")
    if v == "attack_success":
        return "success"
    if v == "defense_success":
        return "refusal"
    return "partial"  # uncertain / 判定失败视为边界，单列


def find_flips(
    current: list[dict[str, Any]], previous: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """翻转告警：同一 (sample_id, model) 的 verdict 与上一版不一致。"""
    prev = {(r["sample_id"], r["model"]): r.get("verdict") for r in previous}
    flips = []
    for row in current:
        key = (row["sample_id"], row["model"])
        old = prev.get(key)
        new = row.get("verdict")
        if old is not None and new is not None and old != new:
            flips.append(
                {
                    "sample_id": row["sample_id"],
                    "pattern_id": row.get("pattern_id"),
                    "model": row["model"],
                    "before": old,
                    "after": new,
                }
            )
    return flips


def cost_stats(results: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """token 成本按模型汇总。"""
    stats: dict[str, dict[str, int]] = defaultdict(
        lambda: {"prompt_tokens": 0, "completion_tokens": 0, "calls": 0}
    )
    for row in results:
        usage = row.get("usage") or {}
        m = stats[row["model"]]
        m["prompt_tokens"] += int(usage.get("prompt_tokens") or 0)
        m["completion_tokens"] += int(usage.get("completion_tokens") or 0)
        m["calls"] += 1
    return dict(stats)


def pick_typical_cases(
    results: list[dict[str, Any]], per_kind: int = 3
) -> dict[str, list[dict[str, Any]]]:
    """典型 case：攻击成功与需复核各抽几条（短响应优先，报告可读性）。"""
    success = [r for r in results if r.get("verdict") == "attack_success"]
    review = [r for r in results if r.get("needs_review")]
    key = lambda r: len(r.get("response") or "")  # noqa: E731
    return {
        "attack_success": sorted(success, key=key)[:per_kind],
        "needs_review": sorted(review, key=key)[:per_kind],
    }


def generate_report(
    results: list[dict[str, Any]],
    previous: list[dict[str, Any]] | None = None,
) -> str:
    # ASR 矩阵（复用 Sprint 2 的计算与渲染）
    labeled = [dict(r, label=_label_from_verdict(r)) for r in results if "verdict" in r]
    matrix = compute_asr_matrix(labeled)

    parts = ["# 红队跑批报告", "", render_markdown(matrix), ""]

    # 翻转告警
    if previous is not None:
        flips = find_flips(results, previous)
        parts.append("## 🔔 翻转告警（与上一版对比 verdict 变化）")
        parts.append("")
        if flips:
            parts.append("| 样本 | 模式 | 模型 | 上次 | 本次 |")
            parts.append("|---|---|---|---|---|")
            for f in flips:
                parts.append(
                    f"| {f['sample_id']} | {f['pattern_id']} | {f['model']} "
                    f"| {f['before']} | **{f['after']}** |"
                )
        else:
            parts.append("无翻转。")
        parts.append("")

    # 成本统计
    parts.append("## 💰 成本统计（靶模型 token）")
    parts.append("")
    parts.append("| 模型 | 调用次数 | prompt tokens | completion tokens |")
    parts.append("|---|---|---|---|")
    for model, s in sorted(cost_stats(results).items()):
        parts.append(
            f"| {model} | {s['calls']} | {s['prompt_tokens']} | {s['completion_tokens']} |"
        )
    parts.append("")

    # 典型 case
    cases = pick_typical_cases(results)
    parts.append("## 📌 典型 case")
    for kind, title in (("attack_success", "攻击成功"), ("needs_review", "需人工复核")):
        parts.append(f"### {title}")
        parts.append("")
        if not cases[kind]:
            parts.append("（无）")
        for r in cases[kind]:
            parts.append(
                f"- `{r['sample_id']}`（{r.get('pattern_id')} / {r['model']}）"
                f" 裁判理由：{r.get('judge_reason') or '—'}"
            )
        parts.append("")

    return "\n".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(description="跑批报告自动生成")
    parser.add_argument(
        "--results", default=str(ROOT / "dataset" / "v1.0" / "batch_results.jsonl")
    )
    parser.add_argument("--compare", default=None, help="上一版结果 JSONL（翻转告警）")
    parser.add_argument("--out", default=str(ROOT / "report" / "latest.md"))
    args = parser.parse_args()

    results = _load_jsonl(Path(args.results))
    previous = _load_jsonl(Path(args.compare)) if args.compare else None
    md = generate_report(results, previous)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md + "\n", encoding="utf-8")
    print(f"报告已生成 → {out}")
    print(md[:500] + ("…" if len(md) > 500 else ""))


if __name__ == "__main__":
    main()
