"""权限引擎：行级租户隔离 + 列级敏感字段权限 + 临时授权 + deny 覆盖。

判定结果携带命中规则与权限版本，供审计和页面展示；缓存/导出/物化
全部以 EffectivePerms.auth_version 为一致性锚点。
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy.orm import Session

from ..models import Dataset, Policy, TempGrant, User, utcnow

if TYPE_CHECKING:
    from ..models import DatasetColumn

REDACTED = "***REDACTED***"


@dataclass
class RuleHit:
    source: str          # policy / temp_grant
    rule_id: int
    effect: str
    scope: str
    detail: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "rule_id": self.rule_id,
            "effect": self.effect,
            "scope": self.scope,
            **self.detail,
        }


@dataclass
class EffectivePerms:
    user_id: int
    tenant_id: int
    dataset_id: int
    auth_version: int
    is_admin: bool
    row_scope: str = "none"                       # all | tenant | custom | none
    visible_columns: set[str] = field(default_factory=set)
    masked_columns: dict[str, str] = field(default_factory=dict)
    hits: list[RuleHit] = field(default_factory=list)
    grant_expires_at: datetime | None = None

    # ---- 行级判定 ----
    def can_see_row(self, row: Any) -> bool:
        if self.is_admin:
            return True
        data = row.data or {}
        tenant_id = getattr(row, "tenant_id", None)

        # 1. deny 优先
        for hit in self.hits:
            if hit.scope != "row" or hit.effect != "deny":
                continue
            if hit.detail.get("row_scope") == "all":
                return False
            if hit.detail.get("row_scope") == "tenant" and tenant_id == self.tenant_id:
                return False
            pred = hit.detail.get("predicate")
            if pred and _predicate_matches(pred, data):
                return False

        # 2. allow
        if self.row_scope == "all":
            return True
        if self.row_scope == "tenant" and tenant_id == self.tenant_id:
            return True
        if self.row_scope == "custom":
            for hit in self.hits:
                if hit.scope == "row" and hit.effect == "allow":
                    pred = hit.detail.get("predicate")
                    if pred and _predicate_matches(pred, data):
                        return True
        return False

    # ---- 列级投影 ----
    def project_row(self, row: Any, columns: list[DatasetColumn]) -> dict[str, Any]:
        data = dict(row.data or {})
        out: dict[str, Any] = {}
        for col in columns:
            if self.is_admin or col.name in self.visible_columns:
                out[col.name] = data.get(col.name)
            else:
                out[col.name] = _mask_value(data.get(col.name), self.masked_columns.get(col.name, "redact"))
        out["_row_id"] = getattr(row, "id", None)
        out["_tenant_id"] = getattr(row, "tenant_id", None)
        return out

    def matched_rule_dicts(self) -> list[dict[str, Any]]:
        return [h.as_dict() for h in self.hits]


def _predicate_matches(pred: dict[str, Any], data: dict[str, Any]) -> bool:
    field_name = pred.get("field")
    op = pred.get("op", "==")
    expected = pred.get("value")
    actual = data.get(field_name)
    try:
        if op == "==":
            return actual == expected
        if op == "!=":
            return actual != expected
        if op == ">":
            return actual is not None and actual > expected
        if op == ">=":
            return actual is not None and actual >= expected
        if op == "<":
            return actual is not None and actual < expected
        if op == "<=":
            return actual is not None and actual <= expected
        if op == "in":
            return actual in (expected or [])
        if op == "not in":
            return actual not in (expected or [])
    except TypeError:
        return False
    return False


def _mask_value(value: Any, mask_type: str) -> Any:
    if value is None:
        return None
    if mask_type == "none":
        return value
    if mask_type == "hash":
        return "hash:" + hashlib.sha256(str(value).encode()).hexdigest()[:16]
    return REDACTED


def _rule_applies(subject_user: int | None, subject_tenant: int | None, user: User) -> bool:
    if subject_user is not None:
        return subject_user == user.id
    if subject_tenant is not None:
        return subject_tenant == user.tenant_id
    return True  # 全局规则


def effective_permissions(db: Session, user: User, dataset: Dataset, *, now: datetime | None = None) -> EffectivePerms:
    """计算用户在数据集上的当前有效权限（策略 + 未过期未撤销的临时授权）。"""
    now = now or utcnow()
    perms = EffectivePerms(
        user_id=user.id,
        tenant_id=user.tenant_id,
        dataset_id=dataset.id,
        auth_version=dataset.auth_version,
        is_admin=bool(user.is_admin),
    )
    if user.is_admin:
        perms.row_scope = "all"
        perms.visible_columns = {c.name for c in dataset.columns}
        return perms

    # ---- 持久策略 ----
    policies: list[Policy] = (
        db.query(Policy)
        .filter(Policy.dataset_id == dataset.id, Policy.active.is_(True))
        .all()
    )
    for p in policies:
        if not _rule_applies(p.subject_user_id, p.subject_tenant_id, user):
            continue
        hit = RuleHit(
            source="policy",
            rule_id=p.id,
            effect=p.effect,
            scope=p.scope,
            detail={
                "row_scope": p.row_scope,
                "predicate": p.custom_predicate,
                "columns": p.columns or [],
                "description": p.description,
            },
        )
        perms.hits.append(hit)

    # ---- 临时授权（未撤销且未过期）----
    grants: list[TempGrant] = (
        db.query(TempGrant)
        .filter(
            TempGrant.dataset_id == dataset.id,
            TempGrant.user_id == user.id,
            TempGrant.revoked.is_(False),
        )
        .all()
    )
    for g in grants:
        if g.expires_at <= now:
            continue  # 过期授权不产生权限
        hit = RuleHit(
            source="temp_grant",
            rule_id=g.id,
            effect="allow",
            scope=g.scope,
            detail={
                "row_scope": g.row_scope,
                "predicate": g.custom_predicate,
                "columns": g.columns or [],
                "expires_at": g.expires_at.isoformat() + "Z",
                "reason": g.reason,
            },
        )
        perms.hits.append(hit)
        if perms.grant_expires_at is None or g.expires_at < perms.grant_expires_at:
            perms.grant_expires_at = g.expires_at

    # ---- 汇总行级范围 ----
    deny_all = any(
        h.scope == "row" and h.effect == "deny" and h.detail.get("row_scope") == "all"
        for h in perms.hits
    )
    allow_all = any(
        h.scope == "row" and h.effect == "allow" and h.detail.get("row_scope") == "all"
        for h in perms.hits
    )
    allow_tenant = any(
        h.scope == "row" and h.effect == "allow" and h.detail.get("row_scope") == "tenant"
        for h in perms.hits
    )
    allow_custom = any(
        h.scope == "row" and h.effect == "allow" and h.detail.get("predicate") is not None
        for h in perms.hits
    )
    if deny_all:
        perms.row_scope = "none"
    elif allow_all:
        perms.row_scope = "all"
    elif allow_tenant:
        perms.row_scope = "tenant"
    elif allow_custom:
        perms.row_scope = "custom"

    # ---- 汇总列级权限 ----
    denied_cols: set[str] = set()
    allowed_cols: set[str] = set()
    for h in perms.hits:
        if h.scope != "column":
            continue
        cols = set(h.detail.get("columns") or [])
        if h.effect == "deny":
            denied_cols |= cols
        else:
            allowed_cols |= cols
    for col in dataset.columns:
        if col.name in denied_cols:
            perms.masked_columns[col.name] = col.default_mask
            continue
        if not col.sensitive:
            perms.visible_columns.add(col.name)
        elif col.name in allowed_cols:
            perms.visible_columns.add(col.name)
        else:
            perms.masked_columns[col.name] = col.default_mask

    return perms
