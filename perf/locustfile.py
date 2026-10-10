"""
Locust 压测脚本 —— AI 安全测试平台核心接口
仓库：ai-security-saas（FastAPI + Supabase）

压测范围（刻意排除 /execute 与 /probe）：
  只压 CRUD 接口（走 FastAPI → PostgREST → Postgres 全链路）。
  execute/probe 每次调用都真实消耗 LLM API 额度且单轮耗时分钟级，不可压测。

认证设计（踩坑记录，2026-09-11 首轮压测实测）：
  1. GoTrue 登录接口（/auth/v1/token）免费版严格限流，并发登录触发 429
     → on_start 带指数退避重试；
  2. Supabase JWT 默认 1 小时过期，首轮压测 1 小时后全部 401
     → 用 refresh_token 每 45 分钟静默刷新，任务不断流；
  3. Supabase 免费版连接池打满会出现分钟级挂起（观测到 86 分钟长尾）
     → 所有请求加 30s 超时，挂起请求快速失败释放虚拟用户。

运行：
  uvicorn app.main:app --port 8000        # 终端 1
  locust -f perf/locustfile.py            # 终端 2，Web 模式
  locust -f perf/locustfile.py --headless -u 20 -r 5 -t 60s --html report.html
"""

import os
import random
import time
import uuid

from locust import HttpUser, task, between

BASE_URL = os.getenv("TARGET_HOST", "http://localhost:8000")
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
TEST_EMAIL = os.getenv("LOADTEST_EMAIL", "1073408857@qq.com")
TEST_PASSWORD = os.getenv("LOADTEST_PASSWORD", "111111")

TOKEN_REFRESH_INTERVAL = 2700  # 45 分钟，小于 JWT 默认 1 小时有效期
REQUEST_TIMEOUT = 30           # 秒，防连接挂起拖死虚拟用户


class PlatformUser(HttpUser):
    host = BASE_URL
    wait_time = between(0.5, 2)

    # ---------- 认证 ----------

    def _login(self):
        """GoTrue 密码登录，429 时限流退避重试（最多 4 次）"""
        for attempt in range(4):
            r = self.client.post(
                f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
                headers={"apikey": SUPABASE_KEY},
                json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
                name="/auth/token",
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code == 200:
                return r.json()
            if r.status_code == 429:
                time.sleep(3 + attempt * 4 + random.random() * 3)
            else:
                r.raise_for_status()
        raise RuntimeError("登录持续被限流(429)，请降低 spawn rate 或稍后重试")

    def _apply_token(self, data):
        self.client.headers["Authorization"] = f"Bearer {data['access_token']}"
        self.refresh_token = data["refresh_token"]
        self.token_ts = time.time()

    def _ensure_token(self):
        """token 超过 45 分钟则用 refresh_token 静默刷新，401/429 时回退全量登录"""
        if time.time() - self.token_ts < TOKEN_REFRESH_INTERVAL:
            return
        r = self.client.post(
            f"{SUPABASE_URL}/auth/v1/token?grant_type=refresh_token",
            headers={"apikey": SUPABASE_KEY},
            json={"refresh_token": self.refresh_token},
            name="/auth/refresh",
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            self._apply_token(r.json())
        else:
            self._apply_token(self._login())

    def on_start(self):
        time.sleep(random.random() * 3)  # 打散登录时间，规避突发限流
        self._apply_token(self._login())

        resp = self.client.get("/patterns?limit=1", name="/patterns(warm)",
                               timeout=REQUEST_TIMEOUT)
        patterns = resp.json()
        if not patterns:
            r = self.client.post(
                "/patterns", name="POST /patterns(bootstrap)", timeout=REQUEST_TIMEOUT,
                json={
                    "name": "loadtest-bootstrap",
                    "attack_category": "prompt_injection",
                    "attack_sub_type": "loadtest",
                    "target_component": "llm_core",
                    "attack_vector": "user_input",
                    "payload_template": "loadtest only, no LLM call",
                },
            )
            r.raise_for_status()
            self.pattern_id = r.json()["id"]
        else:
            self.pattern_id = patterns[0]["id"]

    # ---------- 压测任务 ----------

    @task(5)
    def list_tasks(self):
        self._ensure_token()
        self.client.get("/tasks?limit=20&offset=0", name="GET /tasks",
                        timeout=REQUEST_TIMEOUT)

    @task(3)
    def list_patterns(self):
        self._ensure_token()
        self.client.get("/patterns?limit=20", name="GET /patterns",
                        timeout=REQUEST_TIMEOUT)

    @task(2)
    def task_detail(self):
        self._ensure_token()
        r = self.client.get("/tasks?limit=5", name="GET /tasks(warm)",
                            timeout=REQUEST_TIMEOUT)
        tasks = r.json()
        if tasks:
            self.client.get(f"/tasks/{tasks[0]['id']}", name="GET /tasks/{id}",
                            timeout=REQUEST_TIMEOUT)

    @task(1)
    def create_task(self):
        self._ensure_token()
        payload = {
            "attack_pattern_id": self.pattern_id,
            "target_name": f"loadtest-{uuid.uuid4().hex[:8]}",
            "payload": "loadtest payload, no LLM will be called",
            "execution_method": "自动脚本",
            "status": "待执行",
        }
        r = self.client.post("/tasks", json=payload, name="POST /tasks",
                             timeout=REQUEST_TIMEOUT)
        if r.status_code == 201:
            self.created_task_id = r.json()["id"]

    @task(1)
    def update_task(self):
        self._ensure_token()
        task_id = getattr(self, "created_task_id", None)
        if task_id:
            self.client.patch(f"/tasks/{task_id}", json={"status": "失败"},
                              name="PATCH /tasks/{id}", timeout=REQUEST_TIMEOUT)