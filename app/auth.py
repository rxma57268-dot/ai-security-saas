from typing import Optional

from fastapi import Header, HTTPException

from .database import supabase

try:
    # supabase-py >= 2.10 左右起，auth 库独立为 supabase_auth
    from supabase_auth.errors import AuthApiError
except ImportError:  # 旧版 supabase-py 使用 gotrue
    from gotrue.errors import AuthApiError


def get_current_user(authorization: Optional[str] = Header(default=None)) -> str:
    """FastAPI 依赖：验证 Supabase JWT，返回 user.id。

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
        raise HTTPException(status_code=401, detail="Token 无效或已过期")
    except Exception:
        raise HTTPException(status_code=401, detail="Token 验证失败")

    user = getattr(resp, "user", None)
    if user is None:
        raise HTTPException(status_code=401, detail="Token 无效或已过期")
    return str(user.id)
