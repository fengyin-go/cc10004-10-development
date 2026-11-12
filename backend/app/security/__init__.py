"""受控连接与身份边界子系统。

这里不依赖任何外部认证服务或生产数据库，只使用标准库完成最小可用的
身份验证（PBKDF2 口令 + HMAC 签名令牌）与授权（负责人 / 被委派人）。
"""
from app.security.errors import (
    AccessDenied,
    AuthError,
    ConflictError,
    NotFound,
    Unauthorized,
)
from app.security.dependencies import current_principal

__all__ = [
    "AccessDenied",
    "AuthError",
    "ConflictError",
    "NotFound",
    "Unauthorized",
    "current_principal",
]
