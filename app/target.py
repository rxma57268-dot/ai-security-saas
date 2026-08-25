"""靶子模型客户端：以 OpenAI 兼容格式调用目标 LLM（通义/DeepSeek/智谱等）。"""

import os

import httpx
from dotenv import load_dotenv

from .database import REQUEST_TIMEOUT, AsyncRetryTransport

load_dotenv()

# OpenAI 兼容格式的消息：{"role": "system"|"user"|"assistant", "content": "..."}
Message = dict[str, str]


class TargetModel:
    """靶子模型（被攻击对象）的统一调用接口。

    通过环境变量配置，切换厂商只需改 .env：
      TARGET_BASE_URL  OpenAI 兼容端点，如 https://api.deepseek.com/v1
      TARGET_API_KEY   厂商 API Key
      TARGET_MODEL     模型名，如 deepseek-chat / glm-4-flash
    """

    def __init__(self) -> None:
        self.base_url: str | None = os.environ.get("TARGET_BASE_URL")
        self.api_key: str | None = os.environ.get("TARGET_API_KEY")
        self.model: str | None = os.environ.get("TARGET_MODEL")

        if not self.base_url or not self.api_key or not self.model:
            raise RuntimeError(
                "缺少环境变量 TARGET_BASE_URL / TARGET_API_KEY / TARGET_MODEL，"
                "请在 .env 文件或系统环境变量中配置。"
            )

    async def chat(self, messages: list[Message]) -> str:
        """发送对话消息，返回模型的文本响应。

        Args:
            messages: OpenAI 兼容格式的消息列表。

        Returns:
            模型响应的文本内容。

        Raises:
            httpx.TransportError: 网络错误（重试后仍失败）。
            RuntimeError: HTTP 非 200 或响应格式异常。
        """
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        payload = {"model": self.model, "messages": messages}
        headers = {"Authorization": f"Bearer {self.api_key}"}

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(REQUEST_TIMEOUT),
            transport=AsyncRetryTransport(),
        ) as client:
            resp = await client.post(url, json=payload, headers=headers)

        if resp.status_code != 200:
            raise RuntimeError(
                f"靶模型调用失败：HTTP {resp.status_code} {resp.text[:200]}"
            )

        data = resp.json()
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as e:
            raise RuntimeError(f"靶模型响应格式异常：{data!r}") from e
