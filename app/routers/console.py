"""控制台：展示授权版本、命中规则、导出状态、缓存/物化状态与审计记录。"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_session
from ..deps import current_user
from ..models import (
    AuthVersion,
    Dataset,
    ExportJob,
    MaterializedResult,
    Policy,
    QueryCache,
    TempGrant,
    User,
    AuditLog,
)
from ..services.permissions import effective_permissions

router = APIRouter(prefix="/console", tags=["console"])

CONSOLE_HTML = Path(__file__).resolve().parent.parent / "static" / "console.html"


@router.get("", include_in_schema=False)
@router.get("/", include_in_schema=False)
def console_page():
    from fastapi.responses import HTMLResponse

    return HTMLResponse(CONSOLE_HTML.read_text(encoding="utf-8"))


@router.get("/datasets")
def list_datasets(db: Session = Depends(get_session), user: User = Depends(current_user)):
    out = []
    for ds in db.query(Dataset).order_by(Dataset.id).all():
        out.append(
            {
                "id": ds.id,
                "name": ds.name,
                "description": ds.description,
                "owner_tenant_id": ds.owner_tenant_id,
                "auth_version": ds.auth_version,
                "export_policy": ds.export_policy,
            }
        )
    return {"datasets": out}


@router.get("/datasets/{dataset_id}/overview")
def dataset_overview(dataset_id: int, db: Session = Depends(get_session), user: User = Depends(current_user)):
    ds = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if ds is None:
        raise HTTPException(404, "dataset not found")

    versions = [
        {
            "version": v.version,
            "change_type": v.change_type,
            "detail": v.detail,
            "actor_user_id": v.actor_user_id,
            "created_at": v.created_at.isoformat(),
        }
        for v in db.query(AuthVersion)
        .filter(AuthVersion.dataset_id == dataset_id)
        .order_by(AuthVersion.version.desc())
        .all()
    ]
    policies = [
        {
            "id": p.id,
            "effect": p.effect,
            "scope": p.scope,
            "subject_user_id": p.subject_user_id,
            "subject_tenant_id": p.subject_tenant_id,
            "row_scope": p.row_scope,
            "custom_predicate": p.custom_predicate,
            "columns": p.columns,
            "description": p.description,
            "active": p.active,
            "created_at": p.created_at.isoformat(),
        }
        for p in db.query(Policy).filter(Policy.dataset_id == dataset_id).order_by(Policy.id).all()
    ]
    grants = [
        {
            "id": g.id,
            "user_id": g.user_id,
            "scope": g.scope,
            "row_scope": g.row_scope,
            "columns": g.columns,
            "reason": g.reason,
            "granted_version": g.granted_version,
            "revoked_version": g.revoked_version,
            "expires_at": g.expires_at.isoformat(),
            "revoked": g.revoked,
            "expired_swept": g.expired_swept,
            "granted_at": g.granted_at.isoformat(),
        }
        for g in db.query(TempGrant)
        .filter(TempGrant.dataset_id == dataset_id)
        .order_by(TempGrant.id.desc())
        .all()
    ]
    exports = [
        {
            "id": j.id,
            "requested_by": j.requested_by,
            "auth_version": j.auth_version,
            "status": j.status,
            "row_count": j.row_count,
            "invalidate_reason": j.invalidate_reason,
            "invalidated_at": j.invalidated_at.isoformat() if j.invalidated_at else None,
            "created_at": j.created_at.isoformat(),
        }
        for j in db.query(ExportJob)
        .filter(ExportJob.dataset_id == dataset_id)
        .order_by(ExportJob.id.desc())
        .all()
    ]
    materialized = [
        {
            "id": m.id,
            "name": m.name,
            "requested_by": m.requested_by,
            "auth_version": m.auth_version,
            "status": m.status,
            "group_by": m.group_by,
            "agg": m.agg,
            "refreshed_at": m.refreshed_at.isoformat() if m.refreshed_at else None,
        }
        for m in db.query(MaterializedResult)
        .filter(MaterializedResult.dataset_id == dataset_id)
        .order_by(MaterializedResult.id.desc())
        .all()
    ]
    cache_rows = db.query(QueryCache).filter(QueryCache.dataset_id == dataset_id).all()
    cache_info = {
        "entries": len(cache_rows),
        "valid_entries": sum(1 for c in cache_rows if c.valid),
        "total_hits": sum(c.hits for c in cache_rows),
        "versions_present": sorted({c.auth_version for c in cache_rows}),
    }
    audits = [
        {
            "id": a.id,
            "request_id": a.request_id,
            "actor_name": a.actor_name,
            "action": a.action,
            "decision": a.decision,
            "reason": a.reason,
            "auth_version": a.auth_version,
            "created_at": a.created_at.isoformat(),
        }
        for a in db.query(AuditLog)
        .filter(AuditLog.resource_id == str(dataset_id))
        .order_by(AuditLog.id.desc())
        .limit(20)
        .all()
    ]
    return {
        "dataset": {
            "id": ds.id,
            "name": ds.name,
            "auth_version": ds.auth_version,
            "export_policy": ds.export_policy,
        },
        "versions": versions,
        "policies": policies,
        "temp_grants": grants,
        "exports": exports,
        "materialized": materialized,
        "cache": cache_info,
        "recent_audit": audits,
    }


@router.get("/datasets/{dataset_id}/effective-permissions")
def effective_permissions_preview(
    dataset_id: int, user_id: int, db: Session = Depends(get_session), actor: User = Depends(current_user)
):
    """展示指定用户在数据集上的当前有效权限与命中规则（页面“命中规则”来源）。"""
    ds = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if ds is None:
        raise HTTPException(404, "dataset not found")
    target = db.query(User).filter(User.id == user_id).first()
    if target is None:
        raise HTTPException(404, f"user {user_id} not found")
    perms = effective_permissions(db, target, ds)
    return {
        "user_id": target.id,
        "username": target.username,
        "tenant_id": target.tenant_id,
        "dataset_id": ds.id,
        "auth_version": perms.auth_version,
        "is_admin": perms.is_admin,
        "row_scope": perms.row_scope,
        "visible_columns": sorted(perms.visible_columns),
        "masked_columns": perms.masked_columns,
        "grant_expires_at": perms.grant_expires_at.isoformat() if perms.grant_expires_at else None,
        "matched_rules": perms.matched_rule_dicts(),
    }


@router.get("/audit")
def query_audit(
    dataset_id: int | None = None,
    user_id: int | None = None,
    decision: str | None = None,
    action: str | None = None,
    limit: int = 100,
    db: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    q = db.query(AuditLog)
    if dataset_id is not None:
        q = q.filter(AuditLog.resource_id == str(dataset_id))
    if user_id is not None:
        q = q.filter(AuditLog.actor_user_id == user_id)
    if decision:
        q = q.filter(AuditLog.decision == decision)
    if action:
        q = q.filter(AuditLog.action == action)
    rows = q.order_by(AuditLog.id.desc()).limit(min(limit, 500)).all()
    return {
        "audit_logs": [
            {
                "id": a.id,
                "request_id": a.request_id,
                "tenant_id": a.tenant_id,
                "actor_user_id": a.actor_user_id,
                "actor_name": a.actor_name,
                "action": a.action,
                "resource_type": a.resource_type,
                "resource_id": a.resource_id,
                "decision": a.decision,
                "reason": a.reason,
                "auth_version": a.auth_version,
                "matched_rules": a.matched_rules,
                "detail": a.detail,
                "created_at": a.created_at.isoformat(),
            }
            for a in rows
        ]
    }
