"""授权管理服务：策略变更 / 临时授权 / 撤销 → 推进权限版本 → 级联失效。

每次权限变更在写锁内完成：
  1. dataset.auth_version 单调 +1，写 AuthVersion 流水
  2. 查询缓存：旧版本条目物理删除（命中前若残留则按版本校验拒绝）
  3. 物化结果：标记 stale，下次访问按新版本重算
  4. 已生成导出：按 dataset.export_policy 失效（invalidate）或保留审计（retain_audit）
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from ..models import (
    AuthVersion,
    Dataset,
    ExportJob,
    MaterializedResult,
    Policy,
    QueryCache,
    TempGrant,
    User,
    utcnow,
)


class AuthServiceError(Exception):
    pass


def _bump_version(
    db: Session,
    dataset: Dataset,
    change_type: str,
    detail: dict[str, Any],
    actor: User | None,
) -> int:
    """推进版本并执行级联失效。必须在 GLOBAL_RW_LOCK 写锁内调用。"""
    # 写锁串行化所有写事务；强制重读以避免本会话 identity map 中的旧快照造成丢失更新
    db.expire_all()
    dataset = db.query(Dataset).filter(Dataset.id == dataset.id).first()
    dataset.auth_version += 1
    new_version = dataset.auth_version
    db.add(
        AuthVersion(
            dataset_id=dataset.id,
            version=new_version,
            change_type=change_type,
            detail=detail,
            actor_user_id=actor.id if actor else None,
        )
    )

    # 1) 查询缓存：删除该数据集的全部旧版本缓存
    deleted_cache = (
        db.query(QueryCache).filter(QueryCache.dataset_id == dataset.id).delete(synchronize_session=False)
    )

    # 2) 物化结果：全部标记 stale（其结果按旧权限算出）
    mat_rows = db.query(MaterializedResult).filter(MaterializedResult.dataset_id == dataset.id).all()
    for m in mat_rows:
        m.status = "stale"

    # 3) 已生成且仍可用的导出：按数据集策略处置
    exports = (
        db.query(ExportJob)
        .filter(ExportJob.dataset_id == dataset.id, ExportJob.status == "ready")
        .all()
    )
    invalidated = retained = 0
    for job in exports:
        if dataset.export_policy == "retain_audit":
            job.status = "retained_audit"
            job.invalidate_reason = (
                f"permission change v{new_version} ({change_type}); retained for audit, download blocked"
            )
            job.invalidated_at = utcnow()
            retained += 1
        else:
            job.status = "invalidated"
            job.invalidate_reason = f"permission change v{new_version} ({change_type})"
            job.invalidated_at = utcnow()
            invalidated += 1

    db.commit()
    detail_out = dict(detail)
    detail_out.update(
        cache_entries_cleared=deleted_cache,
        materialized_marked_stale=len(mat_rows),
        exports_invalidated=invalidated,
        exports_retained_audit=retained,
    )
    return new_version


def has_expired_grants(db: Session, dataset_id: int) -> bool:
    """轻量检测：是否存在未清扫的过期授权（不做任何写操作，可在读锁内调用）。"""
    now = utcnow()
    return (
        db.query(TempGrant.id)
        .filter(
            TempGrant.dataset_id == dataset_id,
            TempGrant.revoked.is_(False),
            TempGrant.expired_swept.is_(False),
            TempGrant.expires_at <= now,
        )
        .first()
        is not None
    )


def sweep_expired_grants(db: Session, dataset: Dataset) -> bool:
    """推进过期授权的版本。必须在写锁内（或读锁之外）调用。"""
    from ..locks import GLOBAL_RW_LOCK

    now = utcnow()
    expired = (
        db.query(TempGrant)
        .filter(
            TempGrant.dataset_id == dataset.id,
            TempGrant.revoked.is_(False),
            TempGrant.expired_swept.is_(False),
            TempGrant.expires_at <= now,
        )
        .all()
    )
    if not expired:
        return False
    with GLOBAL_RW_LOCK.write_lock():
        # 双重检查：拿到写锁后重新查询，避免与其他线程的清扫重复 bump
        db.expire_all()
        fresh_dataset = db.query(Dataset).filter(Dataset.id == dataset.id).first()
        fresh_expired = (
            db.query(TempGrant)
            .filter(
                TempGrant.dataset_id == dataset.id,
                TempGrant.revoked.is_(False),
                TempGrant.expired_swept.is_(False),
                TempGrant.expires_at <= now,
            )
            .all()
        )
        if not fresh_expired:
            return False
        # 注意：_bump_version 内部会 expire_all 并提交，标记位必须在 bump 之后再写
        grant_ids = [g.id for g in fresh_expired]
        new_version = _bump_version(
            db,
            fresh_dataset,
            "grant_expired",
            {"expired_grant_ids": grant_ids},
            None,
        )
        for g in db.query(TempGrant).filter(TempGrant.id.in_(grant_ids)).all():
            g.expired_swept = True
        db.commit()
        return new_version


def create_policy(
    db: Session,
    dataset: Dataset,
    actor: User,
    *,
    effect: str,
    scope: str,
    subject_user_id: int | None = None,
    subject_tenant_id: int | None = None,
    row_scope: str | None = None,
    custom_predicate: dict[str, Any] | None = None,
    columns: list[str] | None = None,
    description: str = "",
) -> Policy:
    if effect not in ("allow", "deny"):
        raise AuthServiceError("effect must be allow or deny")
    if scope not in ("row", "column"):
        raise AuthServiceError("scope must be row or column")
    if scope == "row" and row_scope not in ("all", "tenant", "custom"):
        raise AuthServiceError("row policy requires row_scope in all|tenant|custom")
    if scope == "row" and row_scope == "custom" and not custom_predicate:
        raise AuthServiceError("custom row policy requires custom_predicate")
    if scope == "column" and not columns:
        raise AuthServiceError("column policy requires columns")

    policy = Policy(
        dataset_id=dataset.id,
        subject_user_id=subject_user_id,
        subject_tenant_id=subject_tenant_id,
        effect=effect,
        scope=scope,
        row_scope=row_scope,
        custom_predicate=custom_predicate,
        columns=columns,
        description=description,
        created_by=actor.id,
    )
    db.add(policy)
    db.flush()
    _bump_version(
        db,
        dataset,
        "policy_created",
        {"policy_id": policy.id, "effect": effect, "scope": scope},
        actor,
    )
    return policy


def delete_policy(db: Session, dataset: Dataset, actor: User, policy_id: int) -> None:
    policy = db.query(Policy).filter(Policy.id == policy_id, Policy.dataset_id == dataset.id).first()
    if policy is None:
        raise AuthServiceError(f"policy {policy_id} not found in dataset {dataset.id}")
    db.delete(policy)
    _bump_version(db, dataset, "policy_deleted", {"policy_id": policy_id}, actor)


def create_temp_grant(
    db: Session,
    dataset: Dataset,
    actor: User,
    *,
    user_id: int,
    scope: str,
    ttl_seconds: int,
    row_scope: str | None = None,
    custom_predicate: dict[str, Any] | None = None,
    columns: list[str] | None = None,
    reason: str = "",
) -> TempGrant:
    if ttl_seconds <= 0:
        raise AuthServiceError("ttl_seconds must be positive")
    if scope not in ("row", "column"):
        raise AuthServiceError("scope must be row or column")
    if scope == "row" and row_scope not in ("all", "tenant", "custom"):
        raise AuthServiceError("row grant requires row_scope in all|tenant|custom")
    if scope == "column" and not columns:
        raise AuthServiceError("column grant requires columns")

    grant = TempGrant(
        dataset_id=dataset.id,
        user_id=user_id,
        scope=scope,
        row_scope=row_scope,
        custom_predicate=custom_predicate,
        columns=columns,
        reason=reason,
        granted_by=actor.id,
        granted_version=dataset.auth_version + 1,  # 占位，bump 后以返回版本为准
        expires_at=utcnow() + timedelta(seconds=ttl_seconds),
    )
    db.add(grant)
    db.flush()
    new_version = _bump_version(
        db,
        dataset,
        "temp_grant_created",
        {"grant_id": grant.id, "user_id": user_id, "scope": scope, "ttl_seconds": ttl_seconds},
        actor,
    )
    grant.granted_version = new_version
    db.commit()
    return grant


def revoke_grant(db: Session, dataset: Dataset, actor: User, grant_id: int) -> TempGrant:
    grant = (
        db.query(TempGrant)
        .filter(TempGrant.id == grant_id, TempGrant.dataset_id == dataset.id)
        .first()
    )
    if grant is None:
        raise AuthServiceError(f"grant {grant_id} not found in dataset {dataset.id}")
    if grant.revoked:
        raise AuthServiceError(f"grant {grant_id} already revoked")
    grant.revoked_version = dataset.auth_version + 1
    new_version = _bump_version(
        db,
        dataset,
        "temp_grant_revoked",
        {"grant_id": grant.id, "user_id": grant.user_id},
        actor,
    )
    # revoked/revoked_at/revoked_version 在 bump 的 expire_all 之后写，避免被覆盖
    fresh = db.query(TempGrant).filter(TempGrant.id == grant_id).first()
    fresh.revoked = True
    fresh.revoked_at = utcnow()
    fresh.revoked_version = new_version
    db.commit()
    return fresh
