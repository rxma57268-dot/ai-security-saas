"""把人工标注从审阅表格合并回 golden.jsonl（见 export_review.py 的流程说明）。

用法：
  python -m scripts.import_review            # 合并
  python -m scripts.import_review --status   # 只看标注进度（不写回）
"""

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.export_review import GOLDEN, REVIEW_CSV, import_csv  # noqa: E402


def show_status(csv_path: Path) -> None:
    """标注进度：已标/总数/分歧已裁决数（每天 50 条的进度条）。"""
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    total = len(rows)
    filled = [r for r in rows if r["你的标注"].strip()]
    valid = [r for r in filled if r["你的标注"].strip() in ("success", "refusal", "partial")]
    disagree_total = [r for r in rows if r["分歧"].strip()]
    disagree_done = [r for r in disagree_total if r["你的标注"].strip()]
    print(f"标注进度：{len(valid)}/{total}（合法标签）")
    if len(filled) != len(valid):
        print(f"⚠️ {len(filled) - len(valid)} 行填了非法标签（应为 success/refusal/partial）")
    print(f"分歧裁决：{len(disagree_done)}/{len(disagree_total)}")
    if valid:
        from collections import Counter

        print("人工标签分布:", dict(Counter(r["你的标注"].strip() for r in valid)))


if __name__ == "__main__":
    if "--status" in sys.argv:
        show_status(Path(REVIEW_CSV))
    else:
        import_csv(Path(REVIEW_CSV), Path(GOLDEN))
