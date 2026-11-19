"""ORM 模型：租户 / 用户 / 数据集 / 策略 / 临时授权 / 版本 / 审计 / 导出 / 缓存 / 物化。"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    # 全系统统一 naive UTC（SQLite 不保留 tzinfo），比较时两侧均为 naive
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), default="")
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Dataset(Base):
    __tablename__ = "datasets"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(512), default="")
    owner_tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    # 当前生效的权限版本号，任何权限变更都单调 +1
    auth_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    # 权限失效后已生成导出的处置策略：invalidate（默认）或 retain_audit
    export_policy: Mapped[str] = mapped_column(String(32), default="invalidate")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    columns: Mapped[list["DatasetColumn"]] = relationship(
        back_populates="dataset", cascade="all, delete-orphan"
    )
    rows: Mapped[list["DatasetRow"]] = relationship(
        back_populates="dataset", cascade="all, delete-orphan"
    )


class DatasetColumn(Base):
    __tablename__ = "dataset_columns"
    id: Mapped[int] = mapped_column(primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    data_type: Mapped[str] = mapped_column(String(32), default="string")
    sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    default_mask: Mapped[str] = mapped_column(String(16), default="redact")  # redact|hash|none

    dataset: Mapped[Dataset] = relationship(back_populates="columns")


class DatasetRow(Base):
    __tablename__ = "dataset_rows"
    id: Mapped[int] = mapped_column(primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id"), nullable=False)
    tenant_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)

    dataset: Mapped[Dataset] = relationship(back_populates="rows")


Index("ix_rows_dataset_tenant", DatasetRow.dataset_id, DatasetRow.tenant_id)


class Policy(Base):
    """持久化授权策略。effect: allow / deny；scope: row / column。"""
    __tablename__ = "policies"
    id: Mapped[int] = mapped_column(primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id"), nullable=False, index=True)
    subject_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    subject_tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id"), nullable=True)
    effect: Mapped[str] = mapped_column(String(8), nullable=False)  # allow|deny
    scope: Mapped[str] = mapped_column(String(8), nullable=False)  # row|column
    # row: tenant(同租户) / all / custom(custom_predicate 表达式)
    row_scope: Mapped[str | None] = mapped_column(String(32), nullable=True)
    custom_predicate: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # column: 列名列表
    columns: Mapped[list | None] = mapped_column(JSON, nullable=True)
    description: Mapped[str] = mapped_column(String(512), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class TempGrant(Base):
    """临时授权：带过期时间，可撤销；撤销后立刻进入下一权限版本。"""
    __tablename__ = "temp_grants"
    id: Mapped[int] = mapped_column(primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id"), nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    scope: Mapped[str] = mapped_column(String(8), nullable=False)  # row|column
    row_scope: Mapped[str | None] = mapped_column(String(32), nullable=True)
    custom_predicate: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    columns: Mapped[list | None] = mapped_column(JSON, nullable=True)
    reason: Mapped[str] = mapped_column(String(512), default="")
    granted_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    granted_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # 过期后是否已触发版本推进（避免重复 bump）
    expired_swept: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    # 授权/撤销发生时的权限版本
    granted_version: Mapped[int] = mapped_column(Integer, nullable=False)
    revoked_version: Mapped[int | None] = mapped_column(Integer, nullable=True)


class AuthVersion(Base):
    """权限版本流水：每次授权/撤销/策略变更一条。"""
    __tablename__ = "auth_versions"
    id: Mapped[int] = mapped_column(primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id"), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    change_type: Mapped[str] = mapped_column(String(32), nullable=False)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True)
    tenant_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actor_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    actor_name: Mapped[str] = mapped_column(String(128), default="")
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(32), default="")
    resource_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    decision: Mapped[str] = mapped_column(String(16), nullable=False, index=True)  # allow|deny|error
    reason: Mapped[str] = mapped_column(String(512), default="")
    auth_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    matched_rules: Mapped[list | None] = mapped_column(JSON, nullable=True)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class ExportJob(Base):
    __tablename__ = "export_jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id"), nullable=False, index=True)
    requested_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    request_id: Mapped[str] = mapped_column(String(64), index=True)
    # 导出时的权限快照
    auth_version: Mapped[int] = mapped_column(Integer, nullable=False)
    row_count: Mapped[int] = mapped_column(Integer, default=0)
    columns: Mapped[list] = mapped_column(JSON, default=list)
    filters: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="ready", index=True)
    # ready | invalidated | retained_audit | failed
    invalidated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    invalidate_reason: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class QueryCache(Base):
    """查询结果缓存：key 中带 auth_version，版本变更后旧条目主动删除并标记逻辑失效。"""
    __tablename__ = "query_cache"
    id: Mapped[int] = mapped_column(primary_key=True)
    cache_key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id"), nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    auth_version: Mapped[int] = mapped_column(Integer, nullable=False)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    valid: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class MaterializedResult(Base):
    """物化结果（聚合）：按某权限版本生成，权限变更后标记 stale 并自动重算。"""
    __tablename__ = "materialized_results"
    id: Mapped[int] = mapped_column(primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id"), nullable=False, index=True)
    requested_by: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    group_by: Mapped[list] = mapped_column(JSON, default=list)
    agg: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    auth_version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="fresh", index=True)  # fresh|stale
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    refreshed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


Index("ix_audit_dataset_time", AuditLog.resource_id, AuditLog.created_at)
