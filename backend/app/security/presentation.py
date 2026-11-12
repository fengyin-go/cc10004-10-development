"""脱敏展示层：任何对外响应都经过这里，保证原始凭据不外泄。

规则：
- 认证凭据（口令 / token / 密钥）永远只回显掩码，不区分角色；
- 接入地址对非负责人脱敏：隐藏 userinfo，主机名只保留首尾字符；
- 负责人可见完整地址，但地址中的认证段（user:pass@）仍会被剥除。
"""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from app.security.store import (
    ControlledConnection,
    Delegation,
    OwnershipHandover,
    User,
)

_CREDENTIAL_MASK = "******"


def mask_credential(credential: str) -> str:
    """凭据统一替换成固定掩码，不泄露长度与字符构成。"""
    if not credential:
        return ""
    return _CREDENTIAL_MASK


def _mask_host(host: str) -> str:
    if not host:
        return host
    # 保留端口，只对主机名本体做首尾保留
    if ":" in host and host.rsplit(":", 1)[1].isdigit():
        hostname, port = host.rsplit(":", 1)
        return "{}:{}".format(_mask_host(hostname), port)
    if len(host) <= 2:
        return host[0] + "*" if host else host
    return "{}{}{}".format(host[0], "*" * min(len(host) - 2, 6), host[-1])


def mask_address(address: str) -> str:
    """普通浏览者视角的地址：去认证段、主机名脱敏，路径保留。"""
    if not address:
        return ""
    try:
        parts = urlsplit(address)
    except ValueError:
        # 非标准 URI：退化为按 @ 截断后整体打码
        cleaned = address.split("@", 1)[-1]
        return _mask_host(cleaned)
    if not parts.scheme:
        # 没有 scheme 时 urlsplit 解析不出主机，按普通字符串处理
        cleaned = address.split("@", 1)[-1]
        return _mask_host(cleaned)
    netloc = _mask_host(parts.hostname or "")
    if parts.port is not None:
        netloc = "{}:{}".format(netloc, parts.port)
    return urlunsplit(
        (parts.scheme, netloc, parts.path or "", parts.query, parts.fragment)
    )


def owner_view_address(address: str) -> str:
    """负责人视角：可见完整主机与路径，但认证段必须剥除。"""
    if not address:
        return ""
    try:
        parts = urlsplit(address)
    except ValueError:
        return address.split("@", 1)[-1]
    if not parts.scheme:
        return address.split("@", 1)[-1]
    netloc = parts.hostname or ""
    if parts.port is not None:
        netloc = "{}:{}".format(netloc, parts.port)
    return urlunsplit(
        (parts.scheme, netloc, parts.path or "", parts.query, parts.fragment)
    )


def present_user(user: User) -> dict:
    return {
        "username": user.username,
        "display_name": user.display_name,
        "disabled": user.disabled,
    }


def present_connection(
    conn: ControlledConnection, *, viewer: str
) -> dict:
    """连接对外结构。viewer 为负责人时可见完整（去认证段）地址。"""
    is_owner = conn.owner == viewer
    return {
        "id": conn.id,
        "name": conn.name,
        "connection_type": conn.connection_type,
        "address": (
            owner_view_address(conn.address)
            if is_owner
            else mask_address(conn.address)
        ),
        "credential": mask_credential(conn.credential),
        "owner": conn.owner,
        "is_owner": is_owner,
        "credential_version": conn.credential_version,
        "address_version": conn.address_version,
        "created_at": conn.created_at,
        "updated_at": conn.updated_at,
    }


def present_delegation(delegation: Delegation) -> dict:
    return {
        "id": delegation.id,
        "connection_id": delegation.connection_id,
        "dataset_code": delegation.dataset_code,
        "granter": delegation.granter,
        "grantee": delegation.grantee,
        "status": delegation.status,
        "suspended_address_version": delegation.suspended_address_version,
        "created_at": delegation.created_at,
        "updated_at": delegation.updated_at,
    }


def present_handover(handover: OwnershipHandover) -> dict:
    return {
        "id": handover.id,
        "connection_id": handover.connection_id,
        "from_owner": handover.from_owner,
        "to_owner": handover.to_owner,
        "status": handover.status,
        "created_at": handover.created_at,
        "decided_at": handover.decided_at,
    }
