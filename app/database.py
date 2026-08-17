import os

from dotenv import load_dotenv
from supabase import Client, create_client

load_dotenv()

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError(
        "缺少环境变量 SUPABASE_URL 或 SUPABASE_KEY，"
        "请在 .env 文件或系统环境变量中配置后重启服务。"
    )

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
