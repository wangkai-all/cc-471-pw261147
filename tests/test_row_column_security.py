"""行级租户隔离与列级敏感字段权限。"""
from __future__ import annotations


def test_admin_sees_all_rows_and_columns(client):
    r = client.post("/api/datasets/1/query", json={}, headers={"X-User-Id": "1"})
    assert r.status_code == 200
    body = r.json()
    assert body["row_count"] == 5
    assert body["masked_columns"] == []
    assert all("***" not in str(row.get("mobile", "")) for row in body["rows"])


def test_tenant_row_level_isolation(client):
    # alice (user 2, tenant 1) 只能看到 ACME 的 3 行
    r = client.post("/api/datasets/1/query", json={}, headers={"X-User-Id": "2"})
    assert r.status_code == 200
    body = r.json()
    assert body["row_count"] == 3
    assert {row["_tenant_id"] for row in body["rows"]} == {1}

    # bob (user 3, tenant 2) 只能看到 BETA 的 2 行
    r = client.post("/api/datasets/1/query", json={}, headers={"X-User-Id": "3"})
    body = r.json()
    assert body["row_count"] == 2
    assert {row["_tenant_id"] for row in body["rows"]} == {2}


def test_sensitive_columns_masked_by_default(client):
    r = client.post("/api/datasets/1/query", json={}, headers={"X-User-Id": "2"})
    body = r.json()
    for row in body["rows"]:
        assert row["mobile"] == "***REDACTED***"
        assert str(row["salary"]).startswith("hash:")  # 该列默认 hash 脱敏
    assert set(body["masked_columns"]) == {"mobile", "salary"}


def test_missing_identity_is_401(client):
    r = client.post("/api/datasets/1/query", json={})
    assert r.status_code == 401


def test_deny_row_policy_overrides_allow(client):
    # 对 alice 增加 deny 行策略（custom 谓词：region=north 的行禁止）
    r = client.post(
        "/admin/datasets/1/policies",
        json={
            "effect": "deny", "scope": "row", "subject_user_id": 2,
            "row_scope": "custom",
            "custom_predicate": {"field": "region", "op": "==", "value": "north"},
            "description": "禁止查看北区订单",
        },
        headers={"X-User-Id": "1"},
    )
    assert r.status_code == 200
    body = client.post("/api/datasets/1/query", json={}, headers={"X-User-Id": "2"}).json()
    assert body["row_count"] == 1  # 3 条 ACME 行中 2 条 region=north 被拒
    assert {row["order_id"] for row in body["rows"]} == {"A-1002"}


def test_deny_all_row_policy_blocks_entire_dataset_and_audits(client):
    client.post(
        "/admin/datasets/1/policies",
        json={"effect": "deny", "scope": "row", "subject_user_id": 3, "row_scope": "all"},
        headers={"X-User-Id": "1"},
    )
    r = client.post("/api/datasets/1/query", json={}, headers={"X-User-Id": "3"})
    assert r.status_code == 403

    audits = client.get("/console/audit?user_id=3&decision=deny", headers={"X-User-Id": "1"}).json()
    assert any(a["action"] == "query" and a["decision"] == "deny" for a in audits["audit_logs"])
    # 越权记录带 request_id 与命中规则
    entry = audits["audit_logs"][0]
    assert entry["request_id"]
    assert any(rule["effect"] == "deny" for rule in entry["matched_rules"])


def test_query_filters_apply_after_permissions(client):
    r = client.post(
        "/api/datasets/1/query",
        json={"filters": {"amount": {"op": ">", "value": 1000}}},
        headers={"X-User-Id": "2"},
    )
    body = r.json()
    assert body["row_count"] == 2
    assert all(row["amount"] > 1000 for row in body["rows"])
