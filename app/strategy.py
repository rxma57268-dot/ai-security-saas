"""攻击策略库（v3 Sprint 4C）：RAG 记忆——Attacker 的跨会话学习。

两级检索（锁定决策）：
  1. 防御签名过滤（硬条件）——纯语义检索在不同表述的拒绝上会翻车
  2. 语义相似度排序（pgvector 余弦，成功率加权）——低成功率策略沉底

数据源两个模式：
  - DB 模式：attack_strategies 表（pgvector），走 match_strategies RPC
  - JSONL 模式：dataset/strategies.jsonl（离线/挖掘直出，Python 内存余弦）

Embedding：OpenAI 兼容 /embeddings 端点（默认智谱 embedding-3，2048 维），
用 EMBEDDING_* 环境变量可换厂商。
"""

import hashlib
import json
import logging
import math
import os
from pathlib import Path
from typing import Any

import httpx

from .database import REQUEST_TIMEOUT, AsyncRetryTransport

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_STRATEGIES_JSONL = ROOT / "dataset" / "strategies.jsonl"

# embedding 内存缓存（评审 P2 修复）：JSONL 模式每次检索不再对每条候选
# 策略重复调 embedding API——按内容 hash 命中进程内缓存
_EMBED_CACHE: dict[str, list[float] | None] = {}


async def embed_text(text: str) -> list[float] | None:
    """文本向量化（OpenAI 兼容 embeddings 端点）。失败返回 None（降级不检索）。
    同一文本进程内只调一次（内容 hash 缓存）。"""
    cache_key = hashlib.sha1(text.encode("utf-8")).hexdigest()
    if cache_key in _EMBED_CACHE:
        return _EMBED_CACHE[cache_key]

    base_url = (
        os.environ.get("EMBEDDING_BASE_URL")
        or os.environ.get("TARGET_BASE_URL")
    )
    api_key = (
        os.environ.get("EMBEDDING_API_KEY") or os.environ.get("TARGET_API_KEY")
    )
    model = os.environ.get("EMBEDDING_MODEL") or "embedding-3"
    result: list[float] | None = None
    if base_url and api_key:
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(REQUEST_TIMEOUT),
                transport=AsyncRetryTransport(),
            ) as client:
                resp = await client.post(
                    f"{base_url.rstrip('/')}/embeddings",
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={"model": model, "input": text},
                )
            if resp.status_code != 200:
                logger.warning("embedding 调用失败: HTTP %s", resp.status_code)
            else:
                result = resp.json()["data"][0]["embedding"]
        except Exception as e:
            logger.warning("embedding 调用异常: %s: %s", type(e).__name__, e)
    # 只缓存成功结果：瞬时网络抖动不该让该文本在进程生命周期内
    # 永远检索不到（评审修复：失败不落缓存，下次检索会重试）
    if result is not None:
        _EMBED_CACHE[cache_key] = result
    return result


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def _strategy_text(s: dict[str, Any]) -> str:
    """策略的可检索文本：手法序列 + 防御签名 + 成功率。"""
    return (
        f"手法序列: {' → '.join(s.get('technique_sequence') or [])}；"
        f"针对防御签名: {s.get('defense_signature')}；"
        f"历史成功率: {s.get('success_rate')}"
    )


class StrategyLibrary:
    """策略库：两级检索（签名过滤 → 语义排序 × 成功率加权）。"""

    def __init__(self, db: Any = None, jsonl_path: Path | None = None) -> None:
        self.db = db  # None 时走 JSONL 模式
        self.jsonl_path = jsonl_path or DEFAULT_STRATEGIES_JSONL

    def _load_jsonl(self) -> list[dict[str, Any]]:
        if not self.jsonl_path.exists():
            return []
        return [
            json.loads(l)
            for l in self.jsonl_path.read_text(encoding="utf-8").splitlines()
            if l.strip()
        ]

    async def retrieve(
        self,
        defense_signature: str,
        query: str,
        top_k: int = 3,
    ) -> list[dict[str, Any]]:
        """检索 Top-K 策略。只返回 approved（门禁内状态不会出库）。"""
        if self.db is not None:
            return await self._retrieve_db(defense_signature, query, top_k)
        return await self._retrieve_jsonl(defense_signature, query, top_k)

    async def _retrieve_db(
        self, signature: str, query: str, top_k: int
    ) -> list[dict[str, Any]]:
        embedding = await embed_text(query)
        if embedding is None:
            return []
        try:
            resp = self.db.rpc(
                "match_strategies",
                {
                    "query_embedding": embedding,
                    "filter_signature": signature,
                    "match_count": top_k,
                },
            ).execute()
            return resp.data or []
        except Exception as e:
            logger.warning("策略检索失败: %s: %s", type(e).__name__, e)
            return []

    async def _retrieve_jsonl(
        self, signature: str, query: str, top_k: int
    ) -> list[dict[str, Any]]:
        # 第一级：防御签名过滤（硬条件）
        candidates = [
            s for s in self._load_jsonl()
            if s.get("status") == "approved"
            and s.get("defense_signature") == signature
        ]
        if not candidates:
            return []
        # 第二级：语义相似度 × 成功率加权
        qe = await embed_text(query)
        if qe is not None:
            for s in candidates:
                se = await embed_text(_strategy_text(s))
                s["_similarity"] = _cosine(qe, se) if se else 0.0
        else:
            for s in candidates:
                s["_similarity"] = 0.0
        for s in candidates:
            s["_score"] = s["_similarity"] * (0.5 + (s.get("success_rate") or 0))
        candidates.sort(key=lambda s: s["_score"], reverse=True)
        return candidates[:top_k]


def format_strategies_for_prompt(strategies: list[dict[str, Any]]) -> str:
    """检索结果渲染进 Attacker prompt。"""
    if not strategies:
        return "（策略库无匹配，自由探索）"
    lines = []
    for i, s in enumerate(strategies, 1):
        seq = " → ".join(s.get("technique_sequence") or [])
        rate = s.get("success_rate")
        lines.append(
            f"策略{i}：手法序列 [{seq}]，历史成功率 {rate:.0%}"
            if rate is not None else f"策略{i}：手法序列 [{seq}]"
        )
    return "\n".join(lines)
