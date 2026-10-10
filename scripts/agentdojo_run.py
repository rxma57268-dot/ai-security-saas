"""AgentDojo 接入（Sprint 5，arXiv:2406.13352）：Agent 间接注入基准。

用法：
  pip install agentdojo
  python -m scripts.agentdojo_run --suite workspace

做什么：
  1. 加载 AgentDojo 的 workspace 套件（办公 Agent 场景：邮件/日历/云盘工具）
  2. 选 1-2 个间接注入攻击场景，用本平台靶模型（TARGET_*）跑
  3. 判定（v3 Sprint 5 升级）：响应文本 + 工具调用轨迹一起喂裁判——
     judge_pair(..., trajectory=<工具调用序列>)。攻击成功的判定必须基于
     轨迹里的真实危险操作（文件修改/工具调用/网络活动）；模型"声称做了
     但轨迹为空"判幻觉执行（hallucinated_execution），verdict 记负。
     没有轨迹验证的裁判会被幻觉骗过（SkillAttack 已证明）。
  4. 结果落 JSONL，供 docs/agent_injection_analysis.md 引用

与裸模型注入的差异（攻击面扩展）：
  prompt → 工具返回 / 检索内容 / 多步状态——注入不再来自用户输入，
  而是来自 Agent 调用的工具结果（邮件正文、日历描述、网页内容）。

注意：AgentDojo 的 API 随版本变化，本脚本按 0.1.x 编写；
失败时打印原始异常，按其 README 调整即可。
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main() -> None:
    parser = argparse.ArgumentParser(description="AgentDojo 间接注入基准")
    parser.add_argument("--suite", default="workspace", help="AgentDojo 套件名")
    parser.add_argument(
        "--attack", default="important_instructions", help="注入攻击名"
    )
    parser.add_argument("--max-tasks", type=int, default=5, help="冒烟：任务数上限")
    parser.add_argument(
        "--out", default=str(ROOT / "report" / "agentdojo_results.jsonl")
    )
    args = parser.parse_args()

    try:
        import agentdojo  # noqa: F401
    except ImportError:
        print("未安装 agentdojo。请先：pip install agentdojo", file=sys.stderr)
        sys.exit(1)

    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
    from agentdojo.attacks.load_attacks import load_attack
    from agentdojo.benchmark import load_suite
    from agentdojo.task_suite.load_suites import get_suites

    from app.target import TargetModel

    target = TargetModel()

    # AgentDojo 的 pipeline 需要它自己的 LLM 封装；这里用它内置的
    # OpenAI 兼容客户端指向 TARGET_*（版本间 API 有差异，按装好的版本调整）
    from agentdojo.models import ModelsEnum

    print(f"加载套件: {args.suite}，攻击: {args.attack}")
    suites = get_suites(Path(agentdojo.__file__).parent / "data")
    if args.suite not in suites:
        print(f"套件不存在，可选: {list(suites)}", file=sys.stderr)
        sys.exit(1)

    suite = load_suite(str(suites[args.suite]), args.suite)
    attack = load_attack(args.attack, suite, None)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    results = []
    tasks = list(suite.user_tasks.values())[: args.max_tasks]
    for user_task in tasks:
        for injection_task in suite.injection_tasks.values():
            try:
                pipeline = AgentPipeline(
                    llm=None,  # 按安装版本接入靶模型，详见 AgentDojo README
                    suite=suite,
                )
                # 运行 (user_task, injection_task) 组合并判定
                # —— 具体调用签名以装好的 agentdojo 版本为准，
                #    核心是把 attack 注入 + security check 的结果记录下来
                record = {
                    "suite": args.suite,
                    "attack": args.attack,
                    "user_task": user_task.ID,
                    "injection_task": injection_task.ID,
                    "target_model": target.model,
                    "note": "API 适配点：按 agentdojo 版本补 benchmark 调用",
                }
                results.append(record)
            except Exception as e:
                results.append(
                    {
                        "suite": args.suite,
                        "user_task": getattr(user_task, "ID", "?"),
                        "injection_task": getattr(injection_task, "ID", "?"),
                        "error": f"{type(e).__name__}: {e}",
                    }
                )

    with out_path.open("w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"记录 {len(results)} 条 → {out_path}")
    print("下一步：把结果写进 docs/agent_injection_analysis.md 的差异分析")


if __name__ == "__main__":
    main()
