"""FastAPI 依赖：把 Authorization 头解析成当前登录用户。"""
from __future__ import annotations

from fastapi import Header

from app.security.service import security_service
from app.security.store import User


def current_principal(
    authorization: str | None = Header(default=None),
) -> User:
    """路由依赖：未携带有效令牌时抛 401，由统一异常处理器转成响应。"""
    return security_service.authenticate_token(authorization)
