"""测试环境：每个测试用独立临时 SQLite 库与导出目录。"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

# 必须在导入 app 之前设置环境变量
_TMP = Path(tempfile.mkdtemp(prefix="tenant_test_"))
os.environ["TENANT_DATA_DIR"] = str(_TMP)
os.environ["TENANT_DB_PATH"] = str(_TMP / "test.db")
os.environ["TENANT_EXPORT_DIR"] = str(_TMP / "exports")

from fastapi.testclient import TestClient  # noqa: E402

import seed  # noqa: E402
from app.database import Base, engine  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        exists = conn.exec_driver_sql(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'"
        ).fetchone()
        if exists:
            conn.exec_driver_sql("DELETE FROM sqlite_sequence")
    seed.seed()
    # 清空导出目录
    for f in Path(os.environ["TENANT_EXPORT_DIR"]).glob("*"):
        f.unlink()
    with TestClient(app) as c:
        yield c
