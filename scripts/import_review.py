"""把人工标注从审阅表格合并回 golden.jsonl（见 export_review.py 的流程说明）。

用法：python -m scripts.import_review
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.export_review import GOLDEN, REVIEW_CSV, import_csv  # noqa: E402

if __name__ == "__main__":
    import_csv(Path(REVIEW_CSV), Path(GOLDEN))
