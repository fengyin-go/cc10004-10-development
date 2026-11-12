"""日志脱敏：防止凭据与地址认证段进入任何日志出口。

- 对 URL 中的 ``user:pass@`` 认证段做正则替换；
- 对当前内存中所有受控连接的原始凭据 / 原始地址做字面量替换。

过滤器挂到根 logger 上，uvicorn 与应用自身的日志都会经过它。
"""
from __future__ import annotations

import logging
import re

from app.security.store import security_store

_URL_CREDENTIAL_RE = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)[^/@\s]+@")
_MASK = "******"


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = self._redact(str(record.msg))
            if record.args:
                record.args = tuple(
                    self._redact(str(arg)) for arg in record.args
                )
            # 异常堆栈里也可能携带敏感原文
            if record.exc_info and record.exc_info[1] is not None:
                record.exc_text = self._redact(
                    logging.Formatter().formatException(record.exc_info)
                )
        except Exception:  # noqa: BLE001 - 日志脱敏绝不能打断业务
            return True
        return True

    @staticmethod
    def _redact(text: str) -> str:
        text = _URL_CREDENTIAL_RE.sub(lambda match: match.group("scheme") + _MASK + "@", text)
        # 历史敏感值（含已轮换的旧凭据、旧地址）统一抹除
        for term in security_store.redact_terms():
            if term and term in text:
                text = text.replace(term, _MASK)
        return text


def install_redaction() -> None:
    redacting_filter = RedactingFilter()
    root = logging.getLogger()
    root.addFilter(redacting_filter)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "app"):
        logger = logging.getLogger(name)
        logger.addFilter(redacting_filter)
