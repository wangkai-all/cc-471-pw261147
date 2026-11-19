"""请求鉴权依赖：通过 X-User-Id 请求头识别调用者（演示用）。"""
from __future__ import annotations

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from .database import get_session
from .models import User


def current_user(
    x_user_id: int | None = Header(default=None, alias="X-User-Id"),
    db: Session = Depends(get_session),
) -> User:
    if x_user_id is None:
        raise HTTPException(status_code=401, detail="missing X-User-Id header")
    user = db.query(User).filter(User.id == x_user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail=f"user {x_user_id} not found")
    return user


def admin_user(user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="admin only")
    return user
