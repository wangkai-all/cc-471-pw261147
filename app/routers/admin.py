"""管理端 API：租户/用户/数据集/策略/临时授权/撤销。写操作均在写锁内完成。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_session
from ..deps import admin_user
from ..locks import GLOBAL_RW_LOCK
from ..models import Dataset, DatasetColumn, DatasetRow, Tenant, User
from ..schemas import (
    DatasetCreate,
    PolicyCreate,
    RowInsert,
    TempGrantCreate,
    TenantCreate,
    UserCreate,
)
from ..services import auth_service
from ..services.audit import new_request_id, record_audit

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/tenants")
def create_tenant(body: TenantCreate, db: Session = Depends(get_session), admin: User = Depends(admin_user)):
    if db.query(Tenant).filter(Tenant.name == body.name).first():
        raise HTTPException(409, f"tenant {body.name} already exists")
    tenant = Tenant(name=body.name)
    db.add(tenant)
    db.commit()
    return {"id": tenant.id, "name": tenant.name}


@router.post("/users")
def create_user(body: UserCreate, db: Session = Depends(get_session), admin: User = Depends(admin_user)):
    if db.query(Tenant).filter(Tenant.id == body.tenant_id).first() is None:
        raise HTTPException(404, f"tenant {body.tenant_id} not found")
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(409, f"user {body.username} already exists")
    user = User(
        username=body.username,
        display_name=body.display_name,
        tenant_id=body.tenant_id,
        is_admin=body.is_admin,
    )
    db.add(user)
    db.commit()
    return {"id": user.id, "username": user.username, "tenant_id": user.tenant_id, "is_admin": user.is_admin}


@router.post("/datasets")
def create_dataset(body: DatasetCreate, db: Session = Depends(get_session), admin: User = Depends(admin_user)):
    if db.query(Tenant).filter(Tenant.id == body.owner_tenant_id).first() is None:
        raise HTTPException(404, f"tenant {body.owner_tenant_id} not found")
    if body.export_policy not in ("invalidate", "retain_audit"):
        raise HTTPException(400, "export_policy must be invalidate or retain_audit")
    with GLOBAL_RW_LOCK.write_lock():
        dataset = Dataset(
            name=body.name,
            description=body.description,
            owner_tenant_id=body.owner_tenant_id,
            export_policy=body.export_policy,
            auth_version=1,
        )
        db.add(dataset)
        db.flush()
        for spec in body.columns:
            db.add(
                DatasetColumn(
                    dataset_id=dataset.id,
                    name=spec.name,
                    data_type=spec.data_type,
                    sensitive=spec.sensitive,
                    default_mask=spec.default_mask,
                )
            )
        for r in body.rows:
            db.add(DatasetRow(dataset_id=dataset.id, tenant_id=r.pop("tenant_id"), data=r))
        db.commit()
    return {
        "id": dataset.id,
        "name": dataset.name,
        "auth_version": dataset.auth_version,
        "export_policy": dataset.export_policy,
        "columns": [c.name for c in body.columns],
        "row_count": len(body.rows),
    }


@router.post("/datasets/{dataset_id}/rows")
def insert_row(dataset_id: int, body: RowInsert, db: Session = Depends(get_session), admin: User = Depends(admin_user)):
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if dataset is None:
        raise HTTPException(404, "dataset not found")
    row = DatasetRow(dataset_id=dataset_id, tenant_id=body.tenant_id, data=body.data)
    db.add(row)
    db.commit()
    return {"id": row.id, "dataset_id": dataset_id, "tenant_id": body.tenant_id}


@router.post("/datasets/{dataset_id}/policies")
def create_policy(dataset_id: int, body: PolicyCreate, db: Session = Depends(get_session), admin: User = Depends(admin_user)):
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if dataset is None:
        raise HTTPException(404, "dataset not found")
    request_id = new_request_id()
    try:
        with GLOBAL_RW_LOCK.write_lock():
            policy = auth_service.create_policy(
                db, dataset, admin,
                effect=body.effect, scope=body.scope,
                subject_user_id=body.subject_user_id, subject_tenant_id=body.subject_tenant_id,
                row_scope=body.row_scope, custom_predicate=body.custom_predicate,
                columns=body.columns, description=body.description,
            )
        record_audit(
            db, request_id=request_id, actor=admin, action="policy_create", decision="allow",
            resource_type="dataset", resource_id=dataset_id,
            reason=f"policy {policy.id} {body.effect}:{body.scope}",
            auth_version=dataset.auth_version,
            detail={"policy_id": policy.id, "body": body.model_dump()},
        )
    except auth_service.AuthServiceError as exc:
        raise HTTPException(400, str(exc))
    db.refresh(dataset)
    return {"policy_id": policy.id, "auth_version": dataset.auth_version, "request_id": request_id}


@router.delete("/datasets/{dataset_id}/policies/{policy_id}")
def delete_policy(dataset_id: int, policy_id: int, db: Session = Depends(get_session), admin: User = Depends(admin_user)):
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if dataset is None:
        raise HTTPException(404, "dataset not found")
    request_id = new_request_id()
    try:
        with GLOBAL_RW_LOCK.write_lock():
            auth_service.delete_policy(db, dataset, admin, policy_id)
    except auth_service.AuthServiceError as exc:
        raise HTTPException(404, str(exc))
    record_audit(
        db, request_id=request_id, actor=admin, action="policy_delete", decision="allow",
        resource_type="dataset", resource_id=dataset_id, reason=f"policy {policy_id} deleted",
        auth_version=dataset.auth_version,
    )
    return {"deleted": policy_id, "auth_version": dataset.auth_version, "request_id": request_id}


@router.post("/datasets/{dataset_id}/temp-grants")
def create_temp_grant(dataset_id: int, body: TempGrantCreate, db: Session = Depends(get_session), admin: User = Depends(admin_user)):
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if dataset is None:
        raise HTTPException(404, "dataset not found")
    target = db.query(User).filter(User.id == body.user_id).first()
    if target is None:
        raise HTTPException(404, f"user {body.user_id} not found")
    request_id = new_request_id()
    try:
        with GLOBAL_RW_LOCK.write_lock():
            grant = auth_service.create_temp_grant(
                db, dataset, admin,
                user_id=body.user_id, scope=body.scope, ttl_seconds=body.ttl_seconds,
                row_scope=body.row_scope, custom_predicate=body.custom_predicate,
                columns=body.columns, reason=body.reason,
            )
    except auth_service.AuthServiceError as exc:
        raise HTTPException(400, str(exc))
    record_audit(
        db, request_id=request_id, actor=admin, action="temp_grant_create", decision="allow",
        resource_type="dataset", resource_id=dataset_id,
        reason=f"grant {grant.id} for user {body.user_id} ttl={body.ttl_seconds}s",
        auth_version=dataset.auth_version,
        detail={"grant_id": grant.id, "body": body.model_dump()},
    )
    db.refresh(grant)
    return {
        "grant_id": grant.id,
        "auth_version": dataset.auth_version,
        "expires_at": grant.expires_at.isoformat(),
        "request_id": request_id,
    }


@router.post("/datasets/{dataset_id}/temp-grants/{grant_id}/revoke")
def revoke_grant(dataset_id: int, grant_id: int, db: Session = Depends(get_session), admin: User = Depends(admin_user)):
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if dataset is None:
        raise HTTPException(404, "dataset not found")
    request_id = new_request_id()
    try:
        with GLOBAL_RW_LOCK.write_lock():
            grant = auth_service.revoke_grant(db, dataset, admin, grant_id)
    except auth_service.AuthServiceError as exc:
        raise HTTPException(400, str(exc))
    record_audit(
        db, request_id=request_id, actor=admin, action="temp_grant_revoke", decision="allow",
        resource_type="dataset", resource_id=dataset_id,
        reason=f"grant {grant_id} revoked", auth_version=dataset.auth_version,
    )
    return {
        "revoked_grant_id": grant.id,
        "auth_version": dataset.auth_version,
        "revoked_at": grant.revoked_at.isoformat(),
        "request_id": request_id,
    }
