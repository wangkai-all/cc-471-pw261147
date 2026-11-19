"""临时授权、撤销、过期；列级授权与 deny 覆盖。"""
from __future__ import annotations

import time


def test_temp_column_grant_unmasks_then_revoke_remasks(client):
    # 初始：alice 看不到 mobile 明文
    body = client.post("/api/datasets/1/query", json={}, headers={"X-User-Id": "2"}).json()
    assert body["rows"][0]["mobile"] == "***REDACTED***"
    v0 = body["auth_version"]

    # 临时授予 mobile 列权限
    r = client.post(
        "/admin/datasets/1/temp-grants",
        json={"user_id": 2, "scope": "column", "columns": ["mobile"], "ttl_seconds": 300,
              "reason": "客服工单临时查看"},
        headers={"X-User-Id": "1"},
    )
    assert r.status_code == 200
    assert r.json()["auth_version"] == v0 + 1

    body = client.post("/api/datasets/1/query", json={}, headers={"X-User-Id": "2"}).json()
    assert body["rows"][0]["mobile"] == "13800000001"
    assert "mobile" not in body["masked_columns"]
    # 命中规则里包含 temp_grant 来源
    assert any(rule["source"] == "temp_grant" and "mobile" in rule["columns"] for rule in body["matched_rules"])

    # 撤销后立即重新脱敏，版本再次 +1
    grants = client.get("/console/datasets/1/overview", headers={"X-User-Id": "1"}).json()["temp_grants"]
    grant_id = grants[0]["id"]
    r = client.post(f"/admin/datasets/1/temp-grants/{grant_id}/revoke", json={}, headers={"X-User-Id": "1"})
    assert r.json()["auth_version"] == v0 + 2

    body = client.post("/api/datasets/1/query", json={}, headers={"X-User-Id": "2"}).json()
    assert body["rows"][0]["mobile"] == "***REDACTED***"


def test_temp_row_grant_all_tenant_access_then_expires(client):
    # bob 原本只能看 tenant 2 的 2 行；临时授予全租户行权限
    client.post(
        "/admin/datasets/1/temp-grants",
        json={"user_id": 3, "scope": "row", "row_scope": "all", "ttl_seconds": 1, "reason": "跨租户审计"},
        headers={"X-User-Id": "1"},
    )
    body = client.post("/api/datasets/1/query", json={}, headers={"X-User-Id": "3"}).json()
    assert body["row_count"] == 5

    # 等待过期：下次查询时清扫过期授权并推进版本
    time.sleep(1.2)
    body = client.post("/api/datasets/1/query", json={}, headers={"X-User-Id": "3"}).json()
    assert body["row_count"] == 2
    assert {row["_tenant_id"] for row in body["rows"]} == {2}

    overview = client.get("/console/datasets/1/overview", headers={"X-User-Id": "1"}).json()
    assert any(v["change_type"] == "grant_expired" for v in overview["versions"])
    grant = overview["temp_grants"][0]
    assert grant["expired_swept"] is True


def test_column_deny_policy_overrides_temp_grant(client):
    # 先临时授权 mobile
    client.post(
        "/admin/datasets/1/temp-grants",
        json={"user_id": 2, "scope": "column", "columns": ["mobile"], "ttl_seconds": 300},
        headers={"X-User-Id": "1"},
    )
    # 再下发 deny 策略
    client.post(
        "/admin/datasets/1/policies",
        json={"effect": "deny", "scope": "column", "subject_user_id": 2, "columns": ["mobile"]},
        headers={"X-User-Id": "1"},
    )
    body = client.post("/api/datasets/1/query", json={}, headers={"X-User-Id": "2"}).json()
    assert body["rows"][0]["mobile"] == "***REDACTED***"


def test_invalid_grant_inputs_rejected(client):
    r = client.post(
        "/admin/datasets/1/temp-grants",
        json={"user_id": 2, "scope": "column", "columns": [], "ttl_seconds": 60},
        headers={"X-User-Id": "1"},
    )
    assert r.status_code == 400
    r = client.post(
        "/admin/datasets/1/temp-grants",
        json={"user_id": 2, "scope": "row", "ttl_seconds": 0},
        headers={"X-User-Id": "1"},
    )
    assert r.status_code == 422  # pydantic 校验 ttl > 0


def test_non_admin_cannot_manage_policies(client):
    r = client.post(
        "/admin/datasets/1/policies",
        json={"effect": "allow", "scope": "row", "row_scope": "all"},
        headers={"X-User-Id": "2"},
    )
    assert r.status_code == 403
