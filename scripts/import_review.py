"""把人工标注从审阅表格合并回 golden.jsonl（见 export_review.py 的流程说明）。

用法：
  python -m scripts.import_review            # 合并
  python -m scripts.import_review --status   # 只看标注进度（不写回）
"""

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.export_review import GOLDEN, REVIEW_CSV, import_csv  # noqa: E402


def show_status(csv_path: Path, golden_path: Path | None = None) -> None:
    """处理进度（零人工标注计划口径）：
    - CSV 人工确认数（可选，非必须）
    - golden.jsonl 自动化判定覆盖率（高置信/预标签/低置信降权）
    """
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    total = len(rows)
    filled = [r for r in rows if r["你的标注"].strip()]
    valid = [r for r in filled if r["你的标注"].strip() in ("success", "refusal", "partial")]
    disagree_total = [r for r in rows if r["分歧"].strip()]
    disagree_done = [r for r in disagree_total if r["你的标注"].strip()]
    print(f"人工确认（可选）：{len(valid)}/{total}；分歧裁决：{len(disagree_done)}/{len(disagree_total)}")
    if len(filled) != len(valid):
        print(f"⚠️ {len(filled) - len(valid)} 行填了非法标签（应为 success/refusal/partial）")

    if golden_path and golden_path.exists():
        from collections import Counter

        golden = [
            json.loads(l)
            for l in golden_path.read_text(encoding="utf-8").splitlines()
            if l.strip()
        ]
        conf = Counter(r.get("confidence", "prelabel") for r in golden)
        labeled = sum(1 for r in golden if (r.get("label") or "").strip())
        print(f"自动化判定覆盖：{labeled}/{len(golden)} 已有标签 "
              f"（高置信 {conf.get('high', 0)} / 预标采信 {conf.get('prelabel', 0)} "
              f"/ 低置信降权 {conf.get('low', 0)}）")


if __name__ == "__main__":
    if "--status" in sys.argv:
        show_status(Path(REVIEW_CSV), Path(GOLDEN))
    else:
        import_csv(Path(REVIEW_CSV), Path(GOLDEN))
