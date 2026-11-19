"""审计服务：所有访问判定（allow/deny/error）均落库，越权可追溯。"""
from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from ..models import AuditLog, User


def new_request_id() -> str:
    return uuid.uuid4().hex


def record_audit(
    db: Session,
    *,
    request_id: str,
    actor: User | None,
    action: str,
    decision: str,
    resource_type: str = "",
    resource_id: str = "",
    reason: str = "",
    auth_version: int | None = None,
    matched_rules: list[dict[str, Any]] | None = None,
    detail: dict[str, Any] | None = None,
    tenant_id: int | None = None,
) -> AuditLog:
    entry = AuditLog(
        request_id=request_id,
        tenant_id=tenant_id if tenant_id is not None else (actor.tenant_id if actor else None),
        actor_user_id=actor.id if actor else None,
        actor_name=actor.username if actor else "anonymous",
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id),
        decision=decision,
        reason=reason,
        auth_version=auth_version,
        matched_rules=matched_rules or [],
        detail=detail or {},
    )
    db.add(entry)
    db.commit()
    return entry
