from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# 数据文件路径可通过环境变量覆盖（测试用临时目录）
DATA_DIR = Path(os.environ.get("TENANT_DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = Path(os.environ.get("TENANT_DB_PATH", DATA_DIR / "service.db"))
EXPORT_DIR = Path(os.environ.get("TENANT_EXPORT_DIR", DATA_DIR / "exports"))
EXPORT_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite:///{DB_PATH}"

# 查询缓存默认 TTL（秒），临时授权场景会自动按授权到期时间截断
DEFAULT_CACHE_TTL = 300
