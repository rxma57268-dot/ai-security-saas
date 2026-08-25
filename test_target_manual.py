"""TargetModel 手动联调脚本：发一句"你好"确认网络与配置可用。

运行方式（项目根目录）：
    .venv\\Scripts\\python test_target_manual.py
"""

import asyncio

from app.target import TargetModel


async def main() -> None:
    model = TargetModel()
    print(f"端点: {model.base_url}")
    print(f"模型: {model.model}")
    print("发送: 你好，请用一句话介绍自己")

    reply = await model.chat([
        {"role": "user", "content": "你好，请用一句话介绍自己"}
    ])
    print(f"响应: {reply}")


if __name__ == "__main__":
    asyncio.run(main())
