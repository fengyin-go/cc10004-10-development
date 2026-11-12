"""密码学最小工具集：只用标准库实现口令哈希与签名令牌。

- 口令存储：PBKDF2-HMAC-SHA256，每用户独立随机盐；
- 会话令牌：HMAC-SHA256 签名的自包含令牌（用户标识 + 过期时间戳）。

令牌签名密钥在进程启动时随机生成，不落盘、不进日志；
应用重启后所有会话自然失效，需要重新登录。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time

_PBKDF2_ITERATIONS = 200_000
_SALT_BYTES = 16
_TOKEN_TTL_SECONDS = 8 * 3600

# 进程级随机密钥：32 字节，仅存活于内存。
_SERVER_SECRET = os.urandom(32)


def hash_password(password: str) -> str:
    """返回 ``pbkdf2$迭代次数$盐$摘要`` 形式的口令记录。"""
    salt = os.urandom(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS
    )
    return "pbkdf2${iterations}${salt}${digest}".format(
        iterations=_PBKDF2_ITERATIONS,
        salt=base64.b64encode(salt).decode("ascii"),
        digest=base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, stored: str) -> bool:
    """恒定时间比较口令是否匹配；格式异常时直接返回 False。"""
    try:
        scheme, iterations_raw, salt_raw, digest_raw = stored.split("$", 3)
        if scheme != "pbkdf2":
            return False
        iterations = int(iterations_raw)
        salt = base64.b64decode(salt_raw)
        expected = base64.b64decode(digest_raw)
    except (ValueError, TypeError):
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return hmac.compare_digest(candidate, expected)


def issue_token(username: str, *, ttl_seconds: int = _TOKEN_TTL_SECONDS) -> str:
    """签发自包含令牌：base64(payload).base64(hmac)。"""
    expires_at = int(time.time()) + ttl_seconds
    payload = "{}:{}".format(username, expires_at).encode("utf-8")
    payload_part = base64.urlsafe_b64encode(payload)
    signature = hmac.new(_SERVER_SECRET, payload_part, hashlib.sha256).digest()
    return "{}.{}".format(
        payload_part.decode("ascii"),
        base64.urlsafe_b64encode(signature).decode("ascii"),
    )


def parse_token(token: str) -> str | None:
    """校验签名与有效期，成功返回用户名，失败返回 None。"""
    try:
        payload_part, signature_part = token.split(".", 1)
        expected = hmac.new(
            _SERVER_SECRET, payload_part.encode("ascii"), hashlib.sha256
        ).digest()
        provided = base64.urlsafe_b64decode(signature_part)
        if not hmac.compare_digest(expected, provided):
            return None
        payload = base64.urlsafe_b64decode(payload_part).decode("utf-8")
        username, expires_raw = payload.rsplit(":", 1)
        if int(expires_raw) < int(time.time()):
            return None
    except (ValueError, TypeError, UnicodeDecodeError):
        return None
    return username or None
