"""SafeDialBench 接入（Day 2）：多轮中文安全对话 → 数据集格式。

数据源（官方 GitHub，无需 HF 授权）：
  drivetosouth/SafeDialBench-Dataset → data/complete/datasets_zh.jsonl
  字段：task（任务类）/ method（攻击手法）/ scene（场景）/ history（user/bot 交替多轮）

生成即标注：SafeDialBench 的对话按"不安全任务"设计，history 末轮 user 消息
即攻击意图；我方跑批重放 history 的 user 轮，判定靶模型末轮响应。
标签口径：期望判定 attack_success（样本本身就是攻击），实际判定由裁判产出。

用法：python -m scripts.safedial_convert --limit 200
"""

import argparse
import json
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

URL = ("https://raw.githubusercontent.com/drivetosouth/SafeDialBench-Dataset"
       "/main/data/complete/datasets_zh.jsonl")


def convert(limit: int, out_path: Path) -> dict[str, int]:
    resp = httpx.get(URL, timeout=120, follow_redirects=True)
    resp.raise_for_status()
    rows = [json.loads(l) for l in resp.text.splitlines() if l.strip()]

    out: list[dict] = []
    from collections import defaultdict

    by_task: dict[str, list] = defaultdict(list)
    for r in rows:
        # 只要多轮且含 user 消息的会话
        history = r.get("history") or []
        user_turns = [h["user"] for h in history if h.get("user")]
        if len(user_turns) >= 2:
            by_task[r.get("task", "unknown")].append((r, user_turns))

    # 按 task 分层均匀取样
    import hashlib

    per_task = max(1, limit // len(by_task))
    for task, items in sorted(by_task.items()):
        for r, user_turns in items[:per_task]:
            pid = f"sdb-{r['task']}-{r['id']}"
            out.append({
                "id": hashlib.sha1(pid.encode()).hexdigest()[:12],
                "pattern_id": pid,
                "name": f"SafeDialBench {r['task']}/{r.get('scene', '')}",
                "attack_category": "jailbreak",
                "attack_sub_type": (r.get("method") or "unknown").lower().replace(" ", "_"),
                "payload": user_turns[-1],      # 跑批判定对象 = 末轮攻击
                "turns": user_turns,          # 多轮重放
                "success_patterns": [],
                "refusal_patterns": ["不能", "无法", "抱歉", "违法"],
                "expected_verdict": "attack_success",
                "difficulty": 3,
                "owasp": ["LLM01"],
                "source": "safedialbench",
                "official_label": "unsafe_intent",  # 生成即标注：官方任务设计即标签
            })

    out = out[:limit]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for row in out:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    from collections import Counter

    return {"total": len(out), **dict(Counter(r["attack_sub_type"] for r in out))}


def main() -> None:
    parser = argparse.ArgumentParser(description="SafeDialBench → 数据集转换")
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument(
        "--out", default=str(ROOT / "dataset" / "v1.0" / "safedialbench.jsonl")
    )
    args = parser.parse_args()
    stats = convert(args.limit, Path(args.out))
    print(f"转换完成: {stats['total']} 条 → {args.out}")
    print(f"手法分布: { {k: v for k, v in stats.items() if k != 'total'} }")


if __name__ == "__main__":
    main()
