"""安全子系统的错误类型。

约定：错误消息里只出现连接编号、数据集编号等非敏感标识，
绝不拼接接入地址的认证段或原始凭据。
"""
from __future__ import annotations


class AuthError(Exception):
    """安全相关错误的基类，携带对外可展示的 HTTP 状态码与提示。"""

    status_code = 400

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        if status_code is not None:
            self.status_code = status_code


class Unauthorized(AuthError):
    """缺少有效身份，或令牌无效 / 过期。"""

    status_code = 401


class AccessDenied(AuthError):
    """身份已识别，但不具备目标资源的访问权限。"""

    status_code = 403


class NotFound(AuthError):
    """目标受控对象不存在（无权限时也统一报不存在，避免侧信道枚举）。"""

    status_code = 404


class ConflictError(AuthError):
    """对象状态与请求冲突，例如重复委派、重复移交确认。"""

    status_code = 409
