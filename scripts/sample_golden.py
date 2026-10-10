"""黄金集分层抽样（Sprint 2）：从跑批结果抽 200-250 条待标注语料。

抽样规则（分层）：
  - 每个 (model × pattern_id) 分组内，按 verdict 分三层：
    success（attack_success）/ refusal（defense_success）/ 边界（uncertain 或
    needs_review 或 judge_error）三层都要覆盖
  - 每个分组至少抽 --per-pattern 条（默认 15），层内随机
  - 总量用 --total 封顶（默认 220）

输出 golden_candidates.jsonl：跑批行 + 空的 "label" 字段（等待人工标注
success / refusal / partial）。标注纪律：可用 LLM 预标再人工校对，
但最终 ground truth 必须人眼过一遍。

用法：
  python -m scripts.sample_golden --results dataset/v1.0/batch_results.jsonl
"""

import argparse
import json
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _layer(row: dict[str, Any]) -> str | None:
    """分层：success / refusal / boundary；执行出错的行不入黄金集。

    注意：needs_review（双裁判分歧）不单独分层——它只是人工复核标记，
    行里的 verdict 仍是有效判定；否则 JBB 这类无 regex 规则的样本
    会全部挤进 boundary 层，破坏层间平衡。
    """
    if "error" in row:
        return None
    if row.get("judge_error"):
        return "boundary"
    verdict = row.get("verdict")
    if verdict == "attack_success":
        return "success"
    if verdict == "defense_success":
        return "refusal"
    return "boundary"


def _round_robin(
    groups: dict[str, list[dict[str, Any]]],
    quota: int,
    rng: random.Random,
) -> list[dict[str, Any]]:
    """三层轮转抽样：success/refusal/boundary 都要覆盖。"""
    picked: list[dict[str, Any]] = []
    layer_names = ["success", "refusal", "boundary"]
    idx = 0
    while quota > 0 and any(groups.values()):
        layer = layer_names[idx % 3]
        idx += 1
        if groups[layer]:
            picked.append(groups[layer].pop(rng.randrange(len(groups[layer]))))
            quota -= 1
    return picked


def stratified_sample(
    results: list[dict[str, Any]],
    per_pattern: int,
    total: int,
    seed: int,
    heldout_ratio: float = 0.3,
) -> list[dict[str, Any]]:
    """分层抽样：自建模式每模式 per_pattern 条（跨模型合并）；JBB 按块抽剩余额度。

    v3 Sprint 2：黄金集拆 dev / held-out 两份（70/30，按模式分层）。
    调参（手法挖掘质量门、判官阈值）只用 dev 集；held-out 集只在最终
    验证时开封——防止"在测试集上调参"的过拟合。
    """
    rng = random.Random(seed)
    seed_groups: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    jbb_layers: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in results:
        layer = _layer(row)
        if not layer:
            continue
        if row.get("source") == "jailbreakbench":
            jbb_layers[layer].append(row)
        else:
            seed_groups[row["pattern_id"]][layer].append(row)

    picked: list[dict[str, Any]] = []
    for key in sorted(seed_groups):
        picked.extend(_round_robin(seed_groups[key], per_pattern, rng))

    picked.extend(_round_robin(jbb_layers, max(0, total - len(picked)), rng))

    rng.shuffle(picked)
    picked = picked[:total]

    # dev / held-out 拆分：按模式分层 70/30（同模式两边都有覆盖）
    by_pattern: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in picked:
        by_pattern[row["pattern_id"]].append(row)
    for group in by_pattern.values():
        rng.shuffle(group)
        cut = max(1, round(len(group) * (1 - heldout_ratio)))
        for i, row in enumerate(group):
            row["split"] = "dev" if i < cut else "heldout"

    out = []
    for row in picked:
        golden = dict(row)
        golden["label"] = ""  # 人工标注：success / refusal / partial
        golden["label_note"] = ""  # 标注备注（可选）
        out.append(golden)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="黄金集分层抽样")
    parser.add_argument(
        "--results", default=str(ROOT / "dataset" / "v1.0" / "batch_results.jsonl")
    )
    parser.add_argument(
        "--out", default=str(ROOT / "dataset" / "v1.0" / "golden_candidates.jsonl")
    )
    parser.add_argument("--per-pattern", type=int, default=15)
    parser.add_argument("--total", type=int, default=220)
    parser.add_argument("--seed", type=int, default=42, help="随机种子（可复现）")
    args = parser.parse_args()

    results = [
        json.loads(line)
        for line in Path(args.results).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    golden = stratified_sample(results, args.per_pattern, args.total, args.seed)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with Path(args.out).open("w", encoding="utf-8") as f:
        for row in golden:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    from collections import Counter

    layers = Counter(_layer(r) for r in golden)
    splits = Counter(r.get("split") for r in golden)
    print(f"抽样完成: {len(golden)} 条 → {args.out}")
    print(f"层分布: {dict(layers)}")
    print(f"拆分: {dict(splits)}（heldout 集只在最终验证时开封）")
    print("下一步：人工标注每行的 label 字段（success/refusal/partial），"
          "每天 50 条，标完存为 golden.jsonl")


if __name__ == "__main__":
    main()
