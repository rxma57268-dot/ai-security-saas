import asyncio
import os
import time

import httpx
from dotenv import load_dotenv
from supabase import Client, create_client
from supabase.lib.client_options import SyncClientOptions

load_dotenv()

# 环境变量延迟到首次使用时校验（懒加载）：import 本模块不炸——
# CI/单测环境没有 .env 也要能 import（评审 P0 修复）。
def _require_env() -> tuple[str, str]:
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_KEY")
    if not url or not key:
        raise RuntimeError(
            "缺少环境变量 SUPABASE_URL 或 SUPABASE_KEY，"
            "请在 .env 文件或系统环境变量中配置后重启服务。"
        )
    return url, key

# ---------- 网络容错配置 ----------
REQUEST_TIMEOUT = 30.0  # 单次请求超时（秒）
MAX_RETRIES = 2  # 失败后自动重试次数（即最多尝试 3 次）
RETRY_BASE_DELAY = 1.0  # 指数退避基数（秒）：第 1 次重试等 1s，第 2 次等 2s
RETRYABLE_STATUS_CODES = {429}  # 速率限制：值得重试的 HTTP 状态码


class RetryTransport(httpx.HTTPTransport):
    """带重试的 httpx 同步传输层。

    重试两类失败（指数退避）：
    - httpx.TransportError：连接失败/超时/连接重置等网络层错误
    - HTTP 429：速率限制
    其他 4xx/5xx 响应是服务端明确结果，直接返回不重试。
    """

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = super().handle_request(request)
            except httpx.TransportError:
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_BASE_DELAY * (2**attempt))
                    continue
                raise
            if (
                response.status_code in RETRYABLE_STATUS_CODES
                and attempt < MAX_RETRIES
            ):
                response.read()  # 读完响应体以释放连接
                time.sleep(RETRY_BASE_DELAY * (2**attempt))
                continue
            return response
        raise RuntimeError("unreachable")


class AsyncRetryTransport(httpx.AsyncHTTPTransport):
    """RetryTransport 的异步版本，供 httpx.AsyncClient 使用（如靶模型调用）。"""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = await super().handle_async_request(request)
            except httpx.TransportError:
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(RETRY_BASE_DELAY * (2**attempt))
                    continue
                raise
            if (
                response.status_code in RETRYABLE_STATUS_CODES
                and attempt < MAX_RETRIES
            ):
                await response.aread()
                await asyncio.sleep(RETRY_BASE_DELAY * (2**attempt))
                continue
            return response
        raise RuntimeError("unreachable")


# 注入统一的 httpx 客户端：postgrest / auth / storage / functions 全部走它
_httpx_client = httpx.Client(
    timeout=httpx.Timeout(REQUEST_TIMEOUT),
    transport=RetryTransport(),
)

_options = SyncClientOptions(
    httpx_client=_httpx_client,
    postgrest_client_timeout=REQUEST_TIMEOUT,
    storage_client_timeout=REQUEST_TIMEOUT,
    function_client_timeout=REQUEST_TIMEOUT,
)

_service_client: Client | None = None


def get_service_client() -> Client:
    """全局 service client（懒加载，首次调用时才校验环境变量并建连）。

    注意：此处 key 应为 anon key——RLS 靠每请求 get_user_client 的用户
    token 生效；service_role key 会绕过 RLS，严禁使用。
    """
    global _service_client
    if _service_client is None:
        url, key = _require_env()
        _service_client = create_client(url, key, options=_options)
    return _service_client


def get_user_client(token: str) -> Client:
    """创建带用户 JWT 的 Supabase client，使 RLS 策略生效。

    通过 postgrest.auth(token) 把用户 token 设置到 PostgREST 请求头，
    数据库侧会以 authenticated 角色 + auth.uid() 执行 RLS 策略。
    每个请求应创建独立 client，不要复用全局 client（避免串号）。
    """
    url, key = _require_env()
    client = create_client(url, key, options=_options)
    client.postgrest.auth(token)
    return client
