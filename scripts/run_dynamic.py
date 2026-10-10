"""动态红队离线跑数（Day 3）：DynamicAttacker × 种子目标，轨迹落盘。

与线上 agent.py dynamic 模式同构但无 DB 依赖：goal 来自种子库，
工具链渲染 payload → 靶模型 → 裁判（verdict + 防御签名 + 路径偏差
回喂下一轮）→ 机械终止条件。

用法：
  python -m scripts.run_dynamic --n 10 --max-rounds 4
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.agent import final_verdict_for, should_stop  # noqa: E402
from app.attacker import DynamicAttacker  # noqa: E402
from app.judge import judge_pair  # noqa: E402
from app.probe_runs import usage_tokens  # noqa: E402
from app.target import TargetModel  # noqa: E402


async def run_one(
    goal: str,
    pattern: dict[str, Any],
    target: TargetModel,
    judge_mode: str,
    max_rounds: int,
) -> dict[str, Any]:
    attacker = DynamicAttacker()
    conversation: list[dict[str, str]] = []
    turns: list[dict[str, Any]] = []
    verdicts: list[str] = []
    stop_reason = None

    for round_no in range(1, max_rounds + 1):
        last_sig = turns[-1]["defense_signature"] if turns else None
        last_dev = turns[-1]["path_deviation"] if turns else None
        action = await attacker.next_action(
            goal, conversation, verdicts[-1] if verdicts else None,
            last_sig, last_dev,
        )
        if action["stop"]:
            stop_reason = action["stop_reason"] or "agent_stop"
            break

        payloads = action["payload"] if isinstance(action["payload"], list) \
            else [action["payload"]]
        for p in payloads:
            conversation.append({"role": "user", "content": p})
            response = await target.chat(conversation)
            conversation.append({"role": "assistant", "content": response})

        outcome = await judge_pair(payloads[-1], response, pattern, judge_mode)
        verdicts.append(outcome.verdict)
        turns.append({
            "round_no": round_no,
            "thought": action["thought"],
            "tool_calls": action["tool_calls"],
            "payload": payloads[-1],
            "response": response,
            "verdict": outcome.verdict,
            "verdict_source": outcome.verdict_source,
            "defense_signature": outcome.defense_signature,
            "path_deviation": outcome.path_deviation,
            "judge_reason": outcome.reason,
            "strategies_used": action.get("strategies_used"),
        })

        reason = should_stop(verdicts, round_no, max_rounds)
        if reason:
            stop_reason = reason
            break

    pt, ct = usage_tokens(target.last_usage)
    return {
        "goal": goal,
        "pattern_id": pattern.get("pattern_id"),
        "rounds": len(turns),
        "final_verdict": final_verdict_for(stop_reason, verdicts),
        "stop_reason": stop_reason,
        "turns": turns,
        "attacker_model": attacker.model,
        "target_model": target.model,
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "usage": {"prompt_tokens": pt, "completion_tokens": ct},
    }


async def run_dynamic(
    seeds_path: Path, out_path: Path, n: int, max_rounds: int,
    concurrency: int, judge_mode: str,
) -> dict[str, int]:
    seeds = [
        json.loads(l)
        for l in seeds_path.read_text(encoding="utf-8").splitlines()
        if l.strip()
    ][:n]
    target = TargetModel()  # TARGET_* 环境变量
    sem = asyncio.Semaphore(concurrency)

    async def guarded(s):
        async with sem:
            try:
                return await run_one(
                    s["payload_template"], s, target, judge_mode, max_rounds
                )
            except Exception as e:
                return {"goal": s["payload_template"][:50],
                        "error": f"{type(e).__name__}: {e}"}

    runs = await asyncio.gather(*(guarded(s) for s in seeds))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in runs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    ok = [r for r in runs if "final_verdict" in r]
    from collections import Counter

    return {
        "total": len(runs), "ok": len(ok), "error": len(runs) - len(ok),
        **dict(Counter(r["final_verdict"] for r in ok)),
    }


def main() -> None:
    import os

    parser = argparse.ArgumentParser(description="动态红队离线跑数")
    parser.add_argument("--seeds", default=str(ROOT / "dataset" / "seeds.jsonl"))
    parser.add_argument(
        "--out", default=str(ROOT / "dataset" / "v1.0" / "dynamic_runs.jsonl")
    )
    parser.add_argument("--n", type=int, default=10)
    parser.add_argument("--max-rounds", type=int, default=4)
    parser.add_argument("--concurrency", type=int, default=2)
    args = parser.parse_args()

    judge_mode = os.environ.get("JUDGE_MODE", "both")
    stats = asyncio.run(
        run_dynamic(Path(args.seeds), Path(args.out), args.n,
                    args.max_rounds, args.concurrency, judge_mode)
    )
    print(f"动态红队跑完: {stats} → {args.out}")


if __name__ == "__main__":
    main()
