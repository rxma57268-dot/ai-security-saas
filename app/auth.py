from typing import NamedTuple, Optional

import httpx
from fastapi import Header, HTTPException

from .database import supabase

try:
    # supabase-py >= 2.10 左右起，auth 库独立为 supabase_auth
    from supabase_auth.errors import AuthApiError
except ImportError:  # 旧版 supabase-py 使用 gotrue
    from gotrue.errors import AuthApiError


class CurrentUser(NamedTuple):
    """当前登录用户：user_id 用于数据归属，token 用于创建用户级 Supabase client（RLS）。"""

    user_id: str
    token: str


def get_current_user(authorization: Optional[str] = Header(default=None)) -> CurrentUser:
    """FastAPI 依赖：验证 Supabase JWT，返回 CurrentUser。

    期望请求头：Authorization: Bearer <token>
    验证失败一律抛 401。
    """
    scheme, _, token = (authorization or "").partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="缺少 Bearer Token")

    try:
        resp = supabase.auth.get_user(token)
    except AuthApiError:
        # token 无效/过期：认证失败
        raise HTTPException(status_code=401, detail="Token 无效或已过期")
    except httpx.TransportError:
        # Supabase 网络故障：不是用户的锅，返回 503
        raise HTTPException(status_code=503, detail="认证服务暂时不可用，请稍后重试")
    except Exception:
        raise HTTPException(status_code=503, detail="认证服务异常，请稍后重试")

    user = getattr(resp, "user", None)
    if user is None:
        raise HTTPException(status_code=401, detail="Token 无效或已过期")
    return CurrentUser(user_id=str(user.id), token=token)
