"""数据服务：查询、缓存、导出、物化结果——全部经过权限引擎并写审计。

一致性约定：
- 读路径在读锁内执行；权限变更在写锁内推进版本，二者互斥
- 缓存 key 内含 auth_version，版本变更后旧 key 永不可能再命中；
  同时版本推进时主动物理删除旧条目（双重保障）
- 导出/物化均保存权限快照版本；下载与刷新时校验当前版本
"""
from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import DEFAULT_CACHE_TTL, EXPORT_DIR
from ..models import (
    Dataset,
    DatasetColumn,
    DatasetRow,
    ExportJob,
    MaterializedResult,
    QueryCache,
    User,
    utcnow,
)
from .audit import record_audit
from .permissions import EffectivePerms, effective_permissions


class DataServiceError(Exception):
    pass


# ---------------------------------------------------------------- 内部工具

def _cache_key(user_id: int, dataset_id: int, version: int, filters: dict[str, Any] | None) -> str:
    raw = json.dumps(
        {"u": user_id, "d": dataset_id, "v": version, "f": filters or {}},
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(raw.encode()).hexdigest()


def _upsert_cache(db: Session, key: str, dataset_id: int, user_id: int,
                  version: int, result: dict, ttl: int) -> None:
    """并发安全的缓存写入：同 key 冲突时回滚并重试为更新。"""
    for attempt in range(3):
        existing = db.query(QueryCache).filter(QueryCache.cache_key == key).first()
        try:
            if existing is not None:
                existing.result = result
                existing.valid = True
                existing.expires_at = utcnow() + timedelta(seconds=ttl)
            else:
                db.add(
                    QueryCache(
                        cache_key=key, dataset_id=dataset_id, user_id=user_id,
                        auth_version=version, result=result,
                        expires_at=utcnow() + timedelta(seconds=ttl),
                    )
                )
            db.commit()
            return
        except IntegrityError:
            # 并发读者同时插入同一 key：回滚后重新查询转更新
            db.rollback()
    # 最终兜底：再查一次更新；仍失败则放弃缓存（不影响查询正确性）
    existing = db.query(QueryCache).filter(QueryCache.cache_key == key).first()
    if existing is not None:
        existing.result = result
        existing.expires_at = utcnow() + timedelta(seconds=ttl)
        db.commit()


def _apply_filters(row: DatasetRow, filters: dict[str, Any] | None) -> bool:
    if not filters:
        return True
    data = row.data or {}
    for field_name, cond in filters.items():
        if isinstance(cond, dict) and "op" in cond:
            pred = {"field": field_name, "op": cond["op"], "value": cond.get("value")}
        else:
            pred = {"field": field_name, "op": "==", "value": cond}
        from .permissions import _predicate_matches  # 复用同一套谓词语义

        if not _predicate_matches(pred, data):
            return False
    return True


def _visible_rows(db: Session, dataset: Dataset, perms: EffectivePerms, filters: dict[str, Any] | None):
    rows = db.query(DatasetRow).filter(DatasetRow.dataset_id == dataset.id).all()
    out = []
    for row in rows:
        if not _apply_filters(row, filters):
            continue
        if perms.can_see_row(row):
            out.append(row)
    return out


def _project(db: Session, dataset: Dataset, perms: EffectivePerms, rows: list[DatasetRow]) -> list[dict]:
    columns = db.query(DatasetColumn).filter(DatasetColumn.dataset_id == dataset.id).all()
    return [perms.project_row(row, columns) for row in rows]


# ---------------------------------------------------------------- 查询 + 缓存

def execute_query(
    db: Session,
    user: User,
    dataset: Dataset,
    request_id: str,
    *,
    filters: dict[str, Any] | None = None,
    use_cache: bool = True,
) -> dict[str, Any]:
    # 读锁内重读版本：防止本会话对象停留在写者 bump 之前的旧快照
    db.expire_all()
    current = db.query(Dataset).filter(Dataset.id == dataset.id).first()
    perms = effective_permissions(db, user, current)

    # 完全没有行级权限 → 越权拒绝并审计
    if not user.is_admin and perms.row_scope == "none":
        record_audit(
            db,
            request_id=request_id,
            actor=user,
            action="query",
            decision="deny",
            resource_type="dataset",
            resource_id=dataset.id,
            reason="no row-level permission on dataset",
            auth_version=perms.auth_version,
            matched_rules=perms.matched_rule_dicts(),
        )
        raise DataServiceError("403: no row-level permission on this dataset")

    key = _cache_key(user.id, dataset.id, perms.auth_version, filters)

    if use_cache:
        cached = db.query(QueryCache).filter(QueryCache.cache_key == key).first()
        if cached and cached.valid and cached.expires_at > utcnow():
            # 版本内校验（key 已含版本，这里是防御性二次确认）
            if cached.auth_version == perms.auth_version:
                cached.hits += 1
                db.commit()
                record_audit(
                    db,
                    request_id=request_id,
                    actor=user,
                    action="query",
                    decision="allow",
                    resource_type="dataset",
                    resource_id=dataset.id,
                    reason="cache hit",
                    auth_version=perms.auth_version,
                    matched_rules=perms.matched_rule_dicts(),
                    detail={
                        "cache_hit": True,
                        "cache_key": key,
                        "row_count": cached.result.get("row_count", 0),
                        "filters": filters or {},
                    },
                )
                cached.result["cache_hit"] = True
                cached.result["cache_key"] = key
                return cached.result

    rows = _visible_rows(db, dataset, perms, filters)
    projected = _project(db, dataset, perms, rows)
    result = {
        "dataset_id": dataset.id,
        "dataset_name": dataset.name,
        "auth_version": perms.auth_version,
        "row_count": len(projected),
        "rows": projected,
        "masked_columns": sorted(perms.masked_columns.keys()),
        "matched_rules": perms.matched_rule_dicts(),
        "cache_hit": False,
    }

    # 写缓存：TTL 受临时授权到期时间截断，保证授权过期后缓存不会多活
    ttl = DEFAULT_CACHE_TTL
    if perms.grant_expires_at is not None:
        remaining = (perms.grant_expires_at - utcnow()).total_seconds()
        ttl = max(1, min(ttl, int(remaining)))
    # 写入前再次确认权限版本未被并发写者超越（读锁期间无写者，这里是防御性校验）
    db.expire_all()
    latest_version = db.query(Dataset.auth_version).filter(Dataset.id == dataset.id).scalar()
    if latest_version == perms.auth_version:
        _upsert_cache(db, key, dataset.id, user.id, perms.auth_version, result, ttl)
    else:
        # 已发生权限变更：丢弃旧版本缓存，并把结果标记为非缓存命中
        result["auth_version"] = latest_version

    record_audit(
        db,
        request_id=request_id,
        actor=user,
        action="query",
        decision="allow",
        resource_type="dataset",
        resource_id=dataset.id,
        reason="row/column filters applied",
        auth_version=perms.auth_version,
        matched_rules=perms.matched_rule_dicts(),
        detail={"cache_hit": False, "cache_key": key, "row_count": len(projected), "filters": filters or {}},
    )
    result["cache_key"] = key
    return result


# ---------------------------------------------------------------- 导出

def create_export(
    db: Session,
    user: User,
    dataset: Dataset,
    request_id: str,
    *,
    filters: dict[str, Any] | None = None,
) -> ExportJob:
    # 读锁临界区内重读当前版本（与 execute_query 保持一致）
    db.expire_all()
    dataset = db.query(Dataset).filter(Dataset.id == dataset.id).first()
    perms = effective_permissions(db, user, dataset)

    if not user.is_admin and perms.row_scope == "none":
        record_audit(
            db,
            request_id=request_id,
            actor=user,
            action="export",
            decision="deny",
            resource_type="dataset",
            resource_id=dataset.id,
            reason="no row-level permission on dataset",
            auth_version=perms.auth_version,
            matched_rules=perms.matched_rule_dicts(),
        )
        raise DataServiceError("403: no row-level permission on this dataset")

    rows = _visible_rows(db, dataset, perms, filters)
    projected = _project(db, dataset, perms, rows)
    columns = [c.name for c in db.query(DatasetColumn).filter(DatasetColumn.dataset_id == dataset.id).all()]

    job = ExportJob(
        dataset_id=dataset.id,
        requested_by=user.id,
        request_id=request_id,
        auth_version=perms.auth_version,
        row_count=len(projected),
        columns=columns,
        filters=filters or {},
        status="ready",
    )
    db.add(job)
    db.flush()  # 取 job.id 作为文件名

    file_path = EXPORT_DIR / f"export_{job.id}.jsonl"
    with open(file_path, "w", encoding="utf-8") as fh:
        for item in projected:
            fh.write(json.dumps(item, ensure_ascii=False) + "\n")
    job.file_path = str(file_path)
    db.commit()

    record_audit(
        db,
        request_id=request_id,
        actor=user,
        action="export",
        decision="allow",
        resource_type="export",
        resource_id=job.id,
        reason=f"exported {len(projected)} rows at v{perms.auth_version}",
        auth_version=perms.auth_version,
        matched_rules=perms.matched_rule_dicts(),
        detail={"export_id": job.id, "row_count": len(projected), "masked_columns": sorted(perms.masked_columns.keys())},
    )
    return job


def download_export(db: Session, user: User, job: ExportJob, request_id: str) -> tuple[str, bytes]:
    """返回 (文件名, 文件内容)；失效/保留审计的导出禁止下载并写越权审计。"""
    if job.status == "ready":
        if user.id != job.requested_by and not user.is_admin:
            record_audit(
                db, request_id=request_id, actor=user, action="export_download",
                decision="deny", resource_type="export", resource_id=job.id,
                reason="not the export owner", auth_version=job.auth_version,
            )
            raise DataServiceError("403: cannot download another user's export")
        with open(job.file_path, "rb") as fh:
            content = fh.read()
        record_audit(
            db, request_id=request_id, actor=user, action="export_download",
            decision="allow", resource_type="export", resource_id=job.id,
            reason=f"download export v{job.auth_version}", auth_version=job.auth_version,
        )
        return f"export_{job.id}.jsonl", content

    # 权限变更后的导出：失效或仅保留审计，均不可下载
    record_audit(
        db, request_id=request_id, actor=user, action="export_download",
        decision="deny", resource_type="export", resource_id=job.id,
        reason=f"export {job.status}: {job.invalidate_reason}",
        auth_version=job.auth_version,
        detail={"snapshot_version": job.auth_version},
    )
    raise DataServiceError(f"410: export is {job.status}; download blocked per policy")


# ---------------------------------------------------------------- 物化结果

def materialize(
    db: Session,
    user: User,
    dataset: Dataset,
    request_id: str,
    *,
    name: str,
    group_by: list[str],
    agg: dict[str, str],
) -> MaterializedResult:
    # 读锁临界区内重读当前版本
    db.expire_all()
    dataset = db.query(Dataset).filter(Dataset.id == dataset.id).first()
    perms = effective_permissions(db, user, dataset)

    if not user.is_admin and perms.row_scope == "none":
        record_audit(
            db, request_id=request_id, actor=user, action="materialize",
            decision="deny", resource_type="dataset", resource_id=dataset.id,
            reason="no row-level permission on dataset",
            auth_version=perms.auth_version, matched_rules=perms.matched_rule_dicts(),
        )
        raise DataServiceError("403: no row-level permission on this dataset")

    col_names = {c.name for c in db.query(DatasetColumn).filter(DatasetColumn.dataset_id == dataset.id).all()}
    requested = set(group_by) | set(agg.keys())
    forbidden = requested - col_names
    if forbidden:
        raise DataServiceError(f"400: unknown columns: {sorted(forbidden)}")
    # 敏感列必须在可见列中
    hidden = {c for c in requested if c not in perms.visible_columns and not user.is_admin}
    if hidden:
        record_audit(
            db, request_id=request_id, actor=user, action="materialize",
            decision="deny", resource_type="dataset", resource_id=dataset.id,
            reason=f"sensitive columns not permitted: {sorted(hidden)}",
            auth_version=perms.auth_version, matched_rules=perms.matched_rule_dicts(),
        )
        raise DataServiceError(f"403: sensitive columns not permitted: {sorted(hidden)}")

    result = _compute_agg(db, dataset, perms, group_by, agg)
    existing = (
        db.query(MaterializedResult)
        .filter(MaterializedResult.dataset_id == dataset.id, MaterializedResult.name == name)
        .first()
    )
    if existing:
        existing.group_by = group_by
        existing.agg = agg
        existing.result = result
        existing.auth_version = perms.auth_version
        existing.status = "fresh"
        existing.refreshed_at = utcnow()
        mat = existing
    else:
        mat = MaterializedResult(
            dataset_id=dataset.id,
            requested_by=user.id,
            name=name,
            group_by=group_by,
            agg=agg,
            result=result,
            auth_version=perms.auth_version,
            status="fresh",
        )
        db.add(mat)
    db.commit()
    record_audit(
        db, request_id=request_id, actor=user, action="materialize",
        decision="allow", resource_type="materialized", resource_id=name,
        reason=f"materialized at v{perms.auth_version}",
        auth_version=perms.auth_version, matched_rules=perms.matched_rule_dicts(),
    )
    return mat


def _compute_agg(db: Session, dataset: Dataset, perms: EffectivePerms, group_by: list[str], agg: dict[str, str]):
    rows = _visible_rows(db, dataset, perms, None)
    projected = _project(db, dataset, perms, rows)
    groups: dict[tuple, list[dict]] = {}
    for row in projected:
        key = tuple(row.get(g) for g in group_by)
        groups.setdefault(key, []).append(row)

    out = []
    for key, members in sorted(groups.items(), key=lambda kv: tuple(str(x) for x in kv[0])):
        entry = {g: k for g, k in zip(group_by, key)}
        for col, func in agg.items():
            values = [m.get(col) for m in members if isinstance(m.get(col), (int, float))]
            if func == "count":
                entry[f"{func}_{col}"] = len(members)
            elif func == "sum":
                entry[f"{func}_{col}"] = sum(values)
            elif func == "avg":
                entry[f"{func}_{col}"] = (sum(values) / len(values)) if values else None
            elif func == "min":
                entry[f"{func}_{col}"] = min(values) if values else None
            elif func == "max":
                entry[f"{func}_{col}"] = max(values) if values else None
            else:
                raise DataServiceError(f"400: unsupported agg function {func}")
        out.append(entry)
    return {"groups": out, "row_count": len(projected)}


def get_materialized(db: Session, user: User, dataset: Dataset, name: str, request_id: str) -> MaterializedResult:
    """读取物化结果；若因权限变更标记 stale，则按当前请求人权限重算。"""
    mat = (
        db.query(MaterializedResult)
        .filter(MaterializedResult.dataset_id == dataset.id, MaterializedResult.name == name)
        .first()
    )
    if mat is None:
        raise DataServiceError(f"404: materialized result {name} not found")

    if mat.status == "stale":
        # 读锁临界区内重读当前版本后再按新权限重算
        db.expire_all()
        dataset = db.query(Dataset).filter(Dataset.id == dataset.id).first()
        perms = effective_permissions(db, user, dataset)
        if not user.is_admin and perms.row_scope == "none":
            record_audit(
                db, request_id=request_id, actor=user, action="materialized_read",
                decision="deny", resource_type="materialized", resource_id=name,
                reason="no row-level permission; stale result cannot be refreshed",
                auth_version=perms.auth_version, matched_rules=perms.matched_rule_dicts(),
            )
            raise DataServiceError("403: no row-level permission on this dataset")
        mat.result = _compute_agg(db, dataset, perms, mat.group_by, mat.agg)
        mat.auth_version = perms.auth_version
        mat.status = "fresh"
        mat.refreshed_at = utcnow()
        db.commit()
        record_audit(
            db, request_id=request_id, actor=user, action="materialized_refresh",
            decision="allow", resource_type="materialized", resource_id=name,
            reason=f"stale result recomputed at v{perms.auth_version}",
            auth_version=perms.auth_version, matched_rules=perms.matched_rule_dicts(),
        )
    else:
        record_audit(
            db, request_id=request_id, actor=user, action="materialized_read",
            decision="allow", resource_type="materialized", resource_id=name,
            reason=f"fresh at v{mat.auth_version}", auth_version=mat.auth_version,
        )
    return mat
