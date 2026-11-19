from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


# ---------- 管理端 ----------

class TenantCreate(BaseModel):
    name: str


class UserCreate(BaseModel):
    username: str
    display_name: str = ""
    tenant_id: int
    is_admin: bool = False


class DatasetColumnSpec(BaseModel):
    name: str
    data_type: str = "string"
    sensitive: bool = False
    default_mask: str = "redact"


class DatasetCreate(BaseModel):
    name: str
    description: str = ""
    owner_tenant_id: int
    export_policy: str = "invalidate"  # invalidate | retain_audit
    columns: list[DatasetColumnSpec]
    rows: list[dict[str, Any]] = []


class RowInsert(BaseModel):
    tenant_id: int
    data: dict[str, Any]


class PolicyCreate(BaseModel):
    effect: str  # allow | deny
    scope: str   # row | column
    subject_user_id: int | None = None
    subject_tenant_id: int | None = None
    row_scope: str | None = None
    custom_predicate: dict[str, Any] | None = None
    columns: list[str] | None = None
    description: str = ""


class TempGrantCreate(BaseModel):
    user_id: int
    scope: str
    ttl_seconds: int = Field(gt=0)
    row_scope: str | None = None
    custom_predicate: dict[str, Any] | None = None
    columns: list[str] | None = None
    reason: str = ""


# ---------- 数据访问端 ----------

class QueryRequest(BaseModel):
    filters: dict[str, Any] | None = None
    use_cache: bool = True


class ExportRequest(BaseModel):
    filters: dict[str, Any] | None = None


class MaterializeRequest(BaseModel):
    name: str
    group_by: list[str] = []
    agg: dict[str, str] = {}  # 列 -> count|sum|avg|min|max
