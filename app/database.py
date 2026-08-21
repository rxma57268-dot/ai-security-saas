import os
import time

import httpx
from dotenv import load_dotenv
from supabase import Client, create_client
from supabase.lib.client_options import SyncClientOptions

load_dotenv()

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError(
        "缺少环境变量 SUPABASE_URL 或 SUPABASE_KEY，"
        "请在 .env 文件或系统环境变量中配置后重启服务。"
    )

# ---------- 网络容错配置 ----------
REQUEST_TIMEOUT = 30.0  # 单次请求超时（秒）
MAX_RETRIES = 2  # 失败后自动重试次数（即最多尝试 3 次）
RETRY_BASE_DELAY = 1.0  # 指数退避基数（秒）：第 1 次重试等 1s，第 2 次等 2s


class RetryTransport(httpx.HTTPTransport):
    """带重试的 httpx 传输层：网络层错误（连接失败/超时/连接重置等）自动重试。

    仅重试 httpx.TransportError（网络不可达类错误），不重试 HTTP 4xx/5xx
    响应——那些是服务端明确给出的结果，重试没有意义。
    """

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        last_exc: httpx.TransportError | None = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                return super().handle_request(request)
            except httpx.TransportError as exc:
                last_exc = exc
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_BASE_DELAY * (2**attempt))
        raise last_exc  # type: ignore[misc]


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

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY, options=_options)
