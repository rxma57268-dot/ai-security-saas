"""数据集活基准版本化（Day 4，学 JBF living benchmark）。

数据集不再冻结：dynamic 轨迹持续增长，每周（或增量超阈值时）打包新版本。

规则：
  1. 统计 dynamic_traces.jsonl 自上一版本以来的新增条数
  2. 新增 ≥ 阈值（默认 50 条）→ 打包当前 dataset/ 为 dataset/v1.x/
     （拷贝种子/黄金集/轨迹/CHANGELOG，不含跑批大文件）
  3. 更新 CHANGELOG：版本号、新增条数、主要发现
  4. 旧版本目录保留，保证可复现

用法：
  python -m scripts.version_dataset           # 增量够就出新版本
  python -m scripts.version_dataset --force   # 强制出新版本
"""

import argparse
import json
import re
import shutil
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DATASET = ROOT / "dataset"
CHANGELOG = DATASET / "CHANGELOG.md"
# 纳入版本化的文件（跑批大文件 batch_results* 不打包，属产物非资产）
VERSIONED_PATTERNS = [
    "seeds.jsonl", "CHANGELOG.md", "attacks.jsonl", "jailbreakbench.jsonl",
    "golden.jsonl", "golden_review.csv", "judge_baseline.json",
    "dynamic_traces.jsonl", "safedialbench.jsonl", "cosafe.jsonl", "mhj.jsonl",
]

NEW_TRACES_THRESHOLD = 50


def current_version() -> tuple[int, int]:
    """从目录名找最新版本号。"""
    versions = []
    for d in DATASET.iterdir():
        m = re.fullmatch(r"v(\d+)\.(\d+)", d.name)
        if m and d.is_dir():
            versions.append((int(m.group(1)), int(m.group(2))))
    return max(versions) if versions else (1, 0)


def count_traces() -> int:
    path = DATASET / f"v{'.'.join(map(str, current_version()))}" / "dynamic_traces.jsonl"
    if not path.exists():
        return 0
    return sum(1 for l in path.open(encoding="utf-8") if l.strip())


def main() -> None:
    parser = argparse.ArgumentParser(description="活基准版本化")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--note", default="", help="本版本主要发现（写入 CHANGELOG）")
    args = parser.parse_args()

    major, minor = current_version()
    cur_dir = DATASET / f"v{major}.{minor}"
    new_traces = count_traces()

    if new_traces < NEW_TRACES_THRESHOLD and not args.force:
        print(f"当前 v{major}.{minor}，dynamic 轨迹 {new_traces} 条 "
              f"< 阈值 {NEW_TRACES_THRESHOLD}，不出新版本")
        return

    new_ver = (major, minor + 1)
    new_dir = DATASET / f"v{new_ver[0]}.{new_ver[1]}"
    new_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    for name in VERSIONED_PATTERNS:
        src = cur_dir / name
        if src.exists():
            shutil.copy2(src, new_dir / name)
            copied.append(name)

    entry = (
        f"\n## v{new_ver[0]}.{new_ver[1]}（{date.today().isoformat()}）\n\n"
        f"- 自 v{major}.{minor} 以来新增 dynamic 轨迹 {new_traces} 条\n"
        f"- 打包文件：{', '.join(copied)}\n"
    )
    if args.note:
        entry += f"- 主要发现：{args.note}\n"
    CHANGELOG.write_text(
        CHANGELOG.read_text(encoding="utf-8") + entry, encoding="utf-8"
    )
    print(f"新版本 v{new_ver[0]}.{new_ver[1]} 已打包 → {new_dir}")


if __name__ == "__main__":
    main()
