"""安全子系统的内存仓库：账号、受控连接、委派、负责人移交与审计记录。

与业务模块的 ``app.store`` 一样只驻留内存，不接触真实数据库。
所有写操作都同步追加一条审计事件，审计事件里只记录非敏感字段，
凭据与地址认证段一律不入库到日志。
"""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.security.crypto import hash_password

# 委派 / 移交的状态常量
DELEGATION_ACTIVE = "有效"
DELEGATION_SUSPENDED = "待重新确认"
DELEGATION_REVOKED = "已撤回"

HANDOVER_PENDING = "待接收"
HANDOVER_DONE = "已移交"
HANDOVER_CANCELLED = "已取消"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_id() -> str:
    return uuid.uuid4().hex


@dataclass
class User:
    username: str
    display_name: str
    password_hash: str
    disabled: bool = False


@dataclass
class ControlledConnection:
    """受控连接：凭据与访问边界都挂在这个对象上。"""

    id: str
    name: str
    connection_type: str
    # address 与 credential 是敏感原文，只有内部授权逻辑可读；
    # 对外展示一律走 presentation 层脱敏。
    address: str
    credential: str
    owner: str
    credential_version: int = 1
    address_version: int = 1
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)


@dataclass
class Delegation:
    """负责人针对「指定数据集 + 指定连接」授予的使用权。

    被委派人只能消费连接（由系统代取凭据建立连接），
    永远不能读取原始凭据或地址认证段。
    """

    id: str
    connection_id: str
    dataset_code: str
    granter: str  # 发起委派时的负责人
    grantee: str
    status: str = DELEGATION_ACTIVE
    # 地址变更后挂起，记录挂起时的地址版本，供负责人重新确认
    suspended_address_version: int | None = None
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)


@dataclass
class OwnershipHandover:
    """负责人移交记录：旧负责人移交后不再拥有写权限。"""

    id: str
    connection_id: str
    from_owner: str
    to_owner: str
    status: str = HANDOVER_PENDING
    created_at: str = field(default_factory=utc_now_iso)
    decided_at: str | None = None


@dataclass
class AuditEvent:
    id: str
    at: str
    actor: str
    action: str
    connection_id: str | None
    dataset_code: str | None
    detail: str


class SecurityStore:
    """线程安全的内存安全仓库（演示用单实例）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._users: dict[str, User] = {}
        self._connections: dict[str, ControlledConnection] = {}
        self._delegations: dict[str, Delegation] = {}
        self._handovers: dict[str, OwnershipHandover] = {}
        self._audit: list[AuditEvent] = []
        # 历史敏感值登记表：凭据轮换后旧值仍需在日志中被抹除
        self._redact_terms: set[str] = set()

    def register_redact_term(self, term: str) -> None:
        """登记一个需要在日志中永久脱敏的敏感原文。"""
        term = (term or "").strip()
        if term:
            with self._lock:
                self._redact_terms.add(term)

    def redact_terms(self) -> list[str]:
        with self._lock:
            # 长的先替换，避免短串是长串子串时留下残余
            return sorted(self._redact_terms, key=len, reverse=True)

    # ---- 账号 -------------------------------------------------------
    def seed_user(self, username: str, display_name: str, password: str) -> None:
        with self._lock:
            if username not in self._users:
                self._users[username] = User(
                    username=username,
                    display_name=display_name,
                    password_hash=hash_password(password),
                )

    def get_user(self, username: str) -> User | None:
        with self._lock:
            return self._users.get(username)

    def list_users(self) -> list[User]:
        with self._lock:
            return sorted(self._users.values(), key=lambda item: item.username)

    # ---- 受控连接 ---------------------------------------------------
    def add_connection(self, conn: ControlledConnection) -> None:
        with self._lock:
            self._connections[conn.id] = conn

    def get_connection(self, connection_id: str) -> ControlledConnection | None:
        with self._lock:
            return self._connections.get(connection_id)

    def list_connections(self) -> list[ControlledConnection]:
        with self._lock:
            return sorted(
                self._connections.values(), key=lambda item: item.created_at
            )

    def find_connection_by_name(self, name: str, owner: str) -> ControlledConnection | None:
        """同名连接按负责人隔离：跨负责人的同名对象不是同一个。"""
        with self._lock:
            for conn in self._connections.values():
                if conn.name == name and conn.owner == owner:
                    return conn
            return None

    # ---- 委派 -------------------------------------------------------
    def add_delegation(self, delegation: Delegation) -> None:
        with self._lock:
            self._delegations[delegation.id] = delegation

    def get_delegation(self, delegation_id: str) -> Delegation | None:
        with self._lock:
            return self._delegations.get(delegation_id)

    def list_delegations(
        self, *, connection_id: str | None = None
    ) -> list[Delegation]:
        with self._lock:
            items = list(self._delegations.values())
        if connection_id:
            items = [item for item in items if item.connection_id == connection_id]
        return sorted(items, key=lambda item: item.created_at)

    def find_active_delegation(
        self, connection_id: str, dataset_code: str, grantee: str
    ) -> Delegation | None:
        with self._lock:
            for item in self._delegations.values():
                if (
                    item.connection_id == connection_id
                    and item.dataset_code == dataset_code
                    and item.grantee == grantee
                    and item.status == DELEGATION_ACTIVE
                ):
                    return item
            return None

    # ---- 负责人移交 -------------------------------------------------
    def add_handover(self, handover: OwnershipHandover) -> None:
        with self._lock:
            self._handovers[handover.id] = handover

    def get_handover(self, handover_id: str) -> OwnershipHandover | None:
        with self._lock:
            return self._handovers.get(handover_id)

    def list_handovers(
        self, *, connection_id: str | None = None
    ) -> list[OwnershipHandover]:
        with self._lock:
            items = list(self._handovers.values())
        if connection_id:
            items = [item for item in items if item.connection_id == connection_id]
        return sorted(items, key=lambda item: item.created_at)

    def pending_handover_for(self, connection_id: str) -> OwnershipHandover | None:
        with self._lock:
            for item in self._handovers.values():
                if (
                    item.connection_id == connection_id
                    and item.status == HANDOVER_PENDING
                ):
                    return item
            return None

    # ---- 审计 -------------------------------------------------------
    def record_audit(
        self,
        *,
        actor: str,
        action: str,
        connection_id: str | None = None,
        dataset_code: str | None = None,
        detail: str = "",
    ) -> None:
        with self._lock:
            self._audit.append(
                AuditEvent(
                    id=new_id(),
                    at=utc_now_iso(),
                    actor=actor,
                    action=action,
                    connection_id=connection_id,
                    dataset_code=dataset_code,
                    detail=detail,
                )
            )

    def list_audit(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            events = list(self._audit)[-limit:]
        return [
            {
                "id": event.id,
                "at": event.at,
                "actor": event.actor,
                "action": event.action,
                "connection_id": event.connection_id,
                "dataset_code": event.dataset_code,
                "detail": event.detail,
            }
            for event in reversed(events)
        ]


security_store = SecurityStore()
