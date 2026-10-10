"""动态轨迹自动入库（Day 3 核心）：生成即标注。

学 ARMs：标签是判定的副产品，不是人工的后补。dynamic 模式跑完后，
judge 的逐轮判定直接成为轨迹标签：
  - 三票一致 / 裁判有定论 → 高置信，直接入库
  - 裁判分歧或 uncertain → needs_review=true、低置信降权（不人工审核）

输入：dynamic_runs.jsonl（scripts/run_dynamic.py 产出）
输出：dynamic_traces.jsonl（黄金集同构格式，可直接并入评估管线）

用法：
  python -m scripts.harvest_dynamic_traces [--runs dataset/v1.0/dynamic_runs.jsonl]
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_VERDICT_TO_LABEL = {
    "attack_success": "success",
    "defense_success": "refusal",
    "uncertain": "partial",
}


def harvest(runs_path: Path, out_path: Path) -> dict[str, int]:
    runs = [
        json.loads(l)
        for l in runs_path.read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]
    out: list[dict[str, Any]] = []
    for run in runs:
        if "error" in run:
            continue
        turns = run.get("turns") or []
        if not turns:
            continue
        last = turns[-1]
        # 手法序列（策略库数据源格式一致）
        technique_sequence = [
            c["tool"] for t in turns for c in (t.get("tool_calls") or [])
        ]
        # 生成即标注：末轮裁判结果就是标签
        label = _VERDICT_TO_LABEL.get(last.get("verdict"), "partial")
        # 置信度：裁判有定论且来源非回落 → 高；uncertain/分歧 → 低
        confident = (
            last.get("verdict") in ("attack_success", "defense_success")
            and not last.get("needs_review")
        )
        sample_key = f"dyn-{run.get('pattern_id')}-{run.get('ran_at')}"
        out.append({
            "id": hashlib.sha1(sample_key.encode()).hexdigest()[:12],
            "sample_id": sample_key,
            "pattern_id": run.get("pattern_id"),
            "source": "dynamic_trace",
            "attack_category": "jailbreak",
            "mutation_chain": technique_sequence,
            "model": run.get("target_model"),
            "payload": last.get("payload"),
            "turns": [t.get("payload") for t in turns],
            "turn_responses": [t.get("response") for t in turns[:-1]],
            "response": last.get("response"),
            "verdict": last.get("verdict"),
            "verdict_source": last.get("verdict_source"),
            "defense_signature": last.get("defense_signature"),
            "path_deviation": last.get("path_deviation"),
            "label": label,
            "label_note": "[生成即标注] dynamic 轨迹，judge 判定直接入库",
            "judge_reason": last.get("judge_reason"),
            "confidence": "high" if confident else "low",
            "needs_review": not confident,
            "rounds": run.get("rounds"),
            "stop_reason": run.get("stop_reason"),
        })

    out_path.parent.mkdir(parents=True, exist_ok=True)
    # 追加模式：活基准——每次 dynamic 运行后新轨迹自动追加
    with out_path.open("a", encoding="utf-8") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    from collections import Counter

    return {
        "harvested": len(out),
        **dict(Counter(r["confidence"] for r in out)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="dynamic 轨迹自动入库（生成即标注）")
    parser.add_argument(
        "--runs", default=str(ROOT / "dataset" / "v1.0" / "dynamic_runs.jsonl")
    )
    parser.add_argument(
        "--out", default=str(ROOT / "dataset" / "v1.0" / "dynamic_traces.jsonl")
    )
    args = parser.parse_args()
    stats = harvest(Path(args.runs), Path(args.out))
    print(f"轨迹入库: {stats} → {args.out}（追加模式，活基准）")


if __name__ == "__main__":
    main()
