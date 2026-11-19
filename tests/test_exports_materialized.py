"""导出失效/保留审计、物化结果 stale 重算。"""
from __future__ import annotations


def test_export_invalidated_on_permission_change_and_download_blocked(client):
    h_alice = {"X-User-Id": "2"}
    job = client.post("/api/datasets/1/exports", json={}, headers=h_alice).json()
    assert job["status"] == "ready"
    export_id = job["export_id"]

    # 可下载，内容是脱敏后的快照
    r = client.get(f"/api/exports/{export_id}/download", headers=h_alice)
    assert r.status_code == 200
    assert "***REDACTED***" in r.text

    # 权限变更 → 导出失效
    client.post(
        "/admin/datasets/1/temp-grants",
        json={"user_id": 2, "scope": "column", "columns": ["mobile"], "ttl_seconds": 300},
        headers={"X-User-Id": "1"},
    )
    info = client.get(f"/api/exports/{export_id}", headers=h_alice).json()
    assert info["status"] == "invalidated"
    assert "v" + str(job["auth_version"] + 1) in info["invalidate_reason"]

    r = client.get(f"/api/exports/{export_id}/download", headers=h_alice)
    assert r.status_code == 410

    # 尝试下载失效导出写了 deny 审计，可追溯
    audits = client.get("/console/audit?action=export_download&decision=deny",
                        headers={"X-User-Id": "1"}).json()
    assert audits["audit_logs"], "失效导出的越权下载必须有审计"


def test_export_retain_audit_policy_keeps_record_but_blocks_download(client):
    # 新建 retain_audit 策略的数据集
    r = client.post(
        "/admin/datasets",
        json={
            "name": "salary_book", "owner_tenant_id": 1, "export_policy": "retain_audit",
            "columns": [
                {"name": "emp", "sensitive": False},
                {"name": "salary", "sensitive": True, "default_mask": "redact"},
            ],
            "rows": [
                {"tenant_id": 1, "emp": "e1", "salary": 100},
                {"tenant_id": 2, "emp": "e2", "salary": 200},
            ],
        },
        headers={"X-User-Id": "1"},
    )
    ds2 = r.json()["id"]
    client.post(
        f"/admin/datasets/{ds2}/policies",
        json={"effect": "allow", "scope": "row", "subject_tenant_id": 1, "row_scope": "tenant"},
        headers={"X-User-Id": "1"},
    )
    job = client.post(f"/api/datasets/{ds2}/exports", json={}, headers={"X-User-Id": "2"}).json()
    assert job["status"] == "ready"

    # 再下发一条策略触发版本变更
    client.post(
        f"/admin/datasets/{ds2}/policies",
        json={"effect": "allow", "scope": "column", "subject_user_id": 2, "columns": ["salary"]},
        headers={"X-User-Id": "1"},
    )
    info = client.get(f"/api/exports/{job['export_id']}", headers={"X-User-Id": "2"}).json()
    assert info["status"] == "retained_audit"

    r = client.get(f"/api/exports/{job['export_id']}/download", headers={"X-User-Id": "2"})
    assert r.status_code == 410

    # 控制台仍能看到保留的导出审计记录
    overview = client.get(f"/console/datasets/{ds2}/overview", headers={"X-User-Id": "1"}).json()
    assert any(e["status"] == "retained_audit" for e in overview["exports"])


def test_cannot_download_other_users_export(client):
    job = client.post("/api/datasets/1/exports", json={}, headers={"X-User-Id": "2"}).json()
    r = client.get(f"/api/exports/{job['export_id']}/download", headers={"X-User-Id": "3"})
    assert r.status_code == 403


def test_materialized_result_goes_stale_and_recomputes(client):
    body = {
        "name": "amount_by_region",
        "group_by": ["region"],
        "agg": {"amount": "sum"},
    }
    mat = client.post("/api/datasets/1/materialize", json=body, headers={"X-User-Id": "2"}).json()
    assert mat["status"] == "fresh"
    # alice 只有 ACME 行：north=1200+800=2000, south=3400
    groups = {g["region"]: g["sum_amount"] for g in mat["result"]["groups"]}
    assert groups == {"north": 2000, "south": 3400}

    # 权限变更 → stale
    client.post(
        "/admin/datasets/1/temp-grants",
        json={"user_id": 2, "scope": "row", "row_scope": "all", "ttl_seconds": 300},
        headers={"X-User-Id": "1"},
    )
    overview = client.get("/console/datasets/1/overview", headers={"X-User-Id": "1"}).json()
    assert overview["materialized"][0]["status"] == "stale"

    # 读取时按新权限重算（现在含 BETA 行：north 增加 560，west=2900）
    refreshed = client.get("/api/datasets/1/materialized/amount_by_region", headers={"X-User-Id": "2"}).json()
    assert refreshed["status"] == "fresh"
    groups = {g["region"]: g["sum_amount"] for g in refreshed["result"]["groups"]}
    assert groups == {"north": 2560, "south": 3400, "west": 2900}
    assert refreshed["auth_version"] == overview["dataset"]["auth_version"]


def test_materialize_on_sensitive_column_denied(client):
    r = client.post(
        "/api/datasets/1/materialize",
        json={"name": "salary_agg", "group_by": ["region"], "agg": {"salary": "avg"}},
        headers={"X-User-Id": "2"},
    )
    assert r.status_code == 403
    audits = client.get("/console/audit?decision=deny", headers={"X-User-Id": "1"}).json()
    assert any(a["action"] == "materialize" for a in audits["audit_logs"])
