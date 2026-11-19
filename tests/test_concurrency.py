"""并发权限变更与缓存失效验证。

两路验证：
1. 服务层：多线程并发查询 + 授权/撤销，校验版本单调无丢失、无残留旧版本缓存
2. HTTP 层：真实 uvicorn 服务下并发请求，不允许出现 5xx 或半变更状态
"""
from __future__ import annotations

import socket
import threading
import time

import httpx
import uvicorn

from app.database import SessionLocal
from app.locks import GLOBAL_RW_LOCK
from app.main import app
from app.models import AuthVersion, Dataset, QueryCache, User
from app.services import auth_service, data_service


def test_concurrent_grants_and_queries_service_layer(client):
    # 每个测试共享同一全局引擎：起始版本以当前数据库实际值为准
    db = SessionLocal()
    start_version = db.query(Dataset).filter(Dataset.id == 1).first().auth_version
    db.close()

    writer_count = 5
    reader_count = 6
    iterations = 8
    errors: list[Exception] = []
    results: list[dict] = []

    def writer(idx: int):
        try:
            for _ in range(2):
                db = SessionLocal()
                ds = db.query(Dataset).filter(Dataset.id == 1).first()
                actor = db.query(User).filter(User.id == 1).first()
                target = db.query(User).filter(User.id == 2).first()
                with GLOBAL_RW_LOCK.write_lock():
                    grant = auth_service.create_temp_grant(
                        db, ds, actor, user_id=target.id, scope="column",
                        columns=["mobile"], ttl_seconds=300, reason=f"writer-{idx}",
                    )
                    auth_service.revoke_grant(db, ds, actor, grant.id)
                db.close()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    def reader():
        try:
            for _ in range(iterations):
                db = SessionLocal()
                ds = db.query(Dataset).filter(Dataset.id == 1).first()
                user = db.query(User).filter(User.id == 2).first()
                with GLOBAL_RW_LOCK.read_lock():
                    res = data_service.execute_query(db, user, ds, new_request_id())
                # 每次返回的结果必须与其携带的权限版本自洽
                assert res["auth_version"] >= start_version
                if "mobile" in res["masked_columns"]:
                    assert all(r["mobile"] == "***REDACTED***" for r in res["rows"])
                else:
                    assert all(r["mobile"] != "***REDACTED***" for r in res["rows"])
                results.append(res)
                db.close()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(writer_count)]
    threads += [threading.Thread(target=reader) for _ in range(reader_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert not errors, f"并发执行出现异常: {errors[:3]}"
    assert len(results) == reader_count * iterations

    # 版本单调、无丢失、无重复（5 writer × 2 轮 × (grant+revoke) = 20 次变更）
    total_changes = writer_count * 2 * 2
    db = SessionLocal()
    ds = db.query(Dataset).filter(Dataset.id == 1).first()
    expected_final = start_version + total_changes
    assert ds.auth_version == expected_final
    versions = [v.version for v in db.query(AuthVersion).filter(AuthVersion.dataset_id == 1).all()]
    assert sorted(versions) == list(range(start_version + 1, expected_final + 1))

    # 不存在旧版本残留缓存
    stale = db.query(QueryCache).filter(QueryCache.auth_version != ds.auth_version).count()
    assert stale == 0
    db.close()


def test_concurrent_http_requests_during_permission_changes(client):
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started
    listener = server.servers[0].sockets[0]
    if isinstance(listener, socket.socket):
        port = listener.getsockname()[1]
    else:  # uvloop PseudoSocket 等非标准对象
        port = listener.getsockname()[1]

    statuses: list[int] = []
    lock = threading.Lock()

    def http_reader():
        with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=30) as http:
            for _ in range(10):
                r = http.post("/api/datasets/1/query", json={}, headers={"X-User-Id": "2"})
                with lock:
                    statuses.append(r.status_code)

    readers = [threading.Thread(target=http_reader) for _ in range(5)]
    for t in readers:
        t.start()

    with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=30) as http:
        for i in range(3):
            g = http.post(
                "/admin/datasets/1/temp-grants",
                json={"user_id": 2, "scope": "column", "columns": ["mobile"],
                      "ttl_seconds": 300, "reason": f"http-{i}"},
                headers={"X-User-Id": "1"},
            ).json()
            http.post(
                f"/admin/datasets/1/temp-grants/{g['grant_id']}/revoke",
                json={}, headers={"X-User-Id": "1"},
            )

    for t in readers:
        t.join(timeout=60)

    assert statuses, "没有采集到响应"
    assert all(s in (200, 403) for s in statuses), f"出现非预期状态码: {set(statuses)}"
    server.should_exit = True
    thread.join(timeout=10)


def new_request_id() -> str:
    from app.services.audit import new_request_id as _nid

    return _nid()
