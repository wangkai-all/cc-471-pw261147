"""缓存失效：版本推进物理清除旧缓存、TTL 被授权到期时间截断。"""
from __future__ import annotations

import time


def test_cache_hit_then_invalidation_on_permission_change(client):
    h = {"X-User-Id": "2"}
    first = client.post("/api/datasets/1/query", json={}, headers=h).json()
    assert first["cache_hit"] is False
    second = client.post("/api/datasets/1/query", json={}, headers=h).json()
    assert second["cache_hit"] is True

    overview = client.get("/console/datasets/1/overview", headers={"X-User-Id": "1"}).json()
    assert overview["cache"]["valid_entries"] == 1
    assert overview["cache"]["total_hits"] == 1

    # 权限变更 → 缓存被物理清除
    client.post(
        "/admin/datasets/1/temp-grants",
        json={"user_id": 2, "scope": "column", "columns": ["mobile"], "ttl_seconds": 300},
        headers={"X-User-Id": "1"},
    )
    overview = client.get("/console/datasets/1/overview", headers={"X-User-Id": "1"}).json()
    assert overview["cache"]["valid_entries"] == 0
    assert overview["cache"]["entries"] == 0

    # 再查不会命中旧缓存（且数据按新权限返回明文）
    third = client.post("/api/datasets/1/query", json={}, headers=h).json()
    assert third["cache_hit"] is False
    assert third["auth_version"] != first["auth_version"]
    assert third["rows"][0]["mobile"] == "13800000001"


def test_cache_ttl_capped_by_grant_expiry(client):
    # 2 秒到期的临时列授权；缓存条目的 TTL 被截断到 ~2 秒
    client.post(
        "/admin/datasets/1/temp-grants",
        json={"user_id": 2, "scope": "column", "columns": ["mobile"], "ttl_seconds": 2},
        headers={"X-User-Id": "1"},
    )
    h = {"X-User-Id": "2"}
    r1 = client.post("/api/datasets/1/query", json={}, headers=h).json()
    assert r1["rows"][0]["mobile"] == "13800000001"
    r2 = client.post("/api/datasets/1/query", json={}, headers=h).json()
    assert r2["cache_hit"] is True  # 授权未过期期间可命中

    time.sleep(2.2)
    # 授权过期 → 版本推进清缓存 + 权限恢复
    r3 = client.post("/api/datasets/1/query", json={}, headers=h).json()
    assert r3["cache_hit"] is False
    assert r3["rows"][0]["mobile"] == "***REDACTED***"


def test_cached_result_never_crosses_versions(client):
    h = {"X-User-Id": "2"}
    v1 = client.post("/api/datasets/1/query", json={}, headers=h).json()
    # 直接用缓存接口再查确认 key 中带版本
    overview = client.get("/console/datasets/1/overview", headers={"X-User-Id": "1"}).json()
    assert overview["cache"]["versions_present"] == [v1["auth_version"]]

    client.post(
        "/admin/datasets/1/policies",
        json={"effect": "deny", "scope": "row", "subject_user_id": 2,
              "row_scope": "custom", "custom_predicate": {"field": "region", "op": "==", "value": "north"}},
        headers={"X-User-Id": "1"},
    )
    body = client.post("/api/datasets/1/query", json={}, headers=h).json()
    assert body["cache_hit"] is False
    assert body["row_count"] == 1
