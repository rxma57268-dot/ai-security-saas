"""MHJ（Multi-turn Human Jailbreaks，Scale AI）接入。

⚠️ 当前状态：MHJ 在 HuggingFace 是**授权受限仓库**（ScaleAI/mhj 与镜像
lvogel123/m2s-mhj 均 401），需先在 HF 申请权限并在环境变量配置 HF_TOKEN。

用法：
  export HF_TOKEN=hf_xxx   # 或 .env 里配置
  python -m scripts.mhj_convert --limit 100

MHJ 是真人红队多轮越狱数据，标签自带（攻击手法分类）——生成即标注。
"""

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MHJ_PARQUET = ("https://huggingface.co/datasets/lvogel123/m2s-mhj"
               "/resolve/main/data/numberize-00000-of-00001.parquet")


def convert(limit: int, out_path: Path) -> int:
    token = os.environ.get("HF_TOKEN")
    if not token:
        print(
            "未配置 HF_TOKEN。MHJ 是授权受限数据集：\n"
            "1. huggingface.co 注册账号\n"
            "2. 打开 https://huggingface.co/datasets/ScaleAI/mhj 点 Agree and access\n"
            "3. Settings → Access Tokens 创建 token，写进 .env 的 HF_TOKEN",
            file=sys.stderr,
        )
        sys.exit(2)

    import io

    import httpx
    import pandas as pd

    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")

    resp = httpx.get(
        MHJ_PARQUET,
        headers={"Authorization": f"Bearer {token}"},
        timeout=120,
        follow_redirects=True,
    )
    resp.raise_for_status()
    df = pd.read_parquet(io.BytesIO(resp.content))

    # m2s 格式：conversation 列（user/assistant 交替），取 user 轮
    out = []
    for i, (_, row) in enumerate(df.head(limit).iterrows()):
        conv = row.get("conversation") or row.get("messages") or []
        user_turns = [m["content"] for m in conv if m.get("role") == "user"]
        if not user_turns:
            continue
        out.append({
            "id": f"mhj-{i:04d}",
            "pattern_id": f"mhj-{i:04d}",
            "name": f"MHJ 真人红队 #{i}",
            "attack_category": "jailbreak",
            "attack_sub_type": "human_multi_turn",
            "payload": user_turns[-1],
            "turns": user_turns,
            "success_patterns": [],
            "refusal_patterns": ["I'm sorry", "I cannot", "I can't",
                                 "不能", "无法", "抱歉"],
            "expected_verdict": "attack_success",
            "difficulty": 4,  # 真人红队手法，难度最高档
            "owasp": ["LLM01"],
            "source": "mhj",
            "official_label": "human_jailbreak",
        })

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for row in out:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return len(out)


def main() -> None:
    parser = argparse.ArgumentParser(description="MHJ → 数据集转换（需 HF_TOKEN）")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument(
        "--out", default=str(ROOT / "dataset" / "v1.0" / "mhj.jsonl")
    )
    args = parser.parse_args()
    n = convert(args.limit, Path(args.out))
    print(f"转换完成: {n} 条 → {args.out}")


if __name__ == "__main__":
    main()
