"""受控连接安全服务：身份验证、访问边界、委派与负责人移交的全部规则。

关键不变量：
1. 原始凭据与地址认证段只在本模块内部使用，任何返回结构都经 presentation 脱敏；
2. 委派只能消费连接，不能读取原始凭据；
3. 接入地址主机变更后，既有委派一律挂起，需负责人重新确认；
4. 凭据轮换不动授权；授权按连接 + 数据集维度存在，不会被其他数据集继承；
5. 负责人移交落审计，旧负责人立即失去连接写权限；
6. 跨负责人的同名连接以 UUID 区分，永远不会被当成同一对象。
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from app.security import presentation
from app.security.crypto import issue_token, parse_token, verify_password
from app.security.errors import (
    AccessDenied,
    ConflictError,
    NotFound,
    Unauthorized,
)
from app.security.store import (
    DELEGATION_ACTIVE,
    DELEGATION_REVOKED,
    DELEGATION_SUSPENDED,
    HANDOVER_CANCELLED,
    HANDOVER_DONE,
    HANDOVER_PENDING,
    ControlledConnection,
    Delegation,
    OwnershipHandover,
    new_id,
    security_store,
    utc_now_iso,
)
from app.security.store import User

_TOKEN_PREFIX = "Bearer "


class SecurityService:
    # ---- 身份验证 ---------------------------------------------------
    def login(self, username: str, password: str) -> dict[str, Any]:
        user = security_store.get_user(username)
        # 用户不存在与口令错误给出同一提示，避免账号枚举
        if user is None or user.disabled or not verify_password(
            password, user.password_hash
        ):
            raise Unauthorized("用户名或口令不正确")
        token = issue_token(user.username)
        security_store.record_audit(
            actor=user.username, action="登录", detail="口令校验通过并签发会话令牌"
        )
        return {
            "token": token,
            "token_type": "Bearer",
            "user": presentation.present_user(user),
        }

    def authenticate_token(self, token: str | None) -> User:
        if not token:
            raise Unauthorized("缺少认证令牌，请先登录")
        if token.startswith(_TOKEN_PREFIX):
            token = token[len(_TOKEN_PREFIX):]
        username = parse_token(token)
        if username is None:
            raise Unauthorized("令牌无效或已过期，请重新登录")
        user = security_store.get_user(username)
        if user is None or user.disabled:
            raise Unauthorized("账号不可用，请联系管理员")
        return user

    # ---- 内部对象获取（不做脱敏，仅供授权逻辑） ---------------------
    def _require_connection(self, connection_id: str) -> ControlledConnection:
        conn = security_store.get_connection(connection_id)
        if conn is None:
            # 对无权限 / 不存在统一口径，避免通过响应差异枚举连接
            raise NotFound("受控连接不存在或无权访问")
        return conn

    def _require_owner(self, user: User, conn: ControlledConnection) -> None:
        if conn.owner != user.username:
            raise AccessDenied("仅连接负责人可以执行该操作")

    # ---- 受控连接管理 ----------------------------------------------
    def create_connection(
        self,
        user: User,
        *,
        name: str,
        connection_type: str,
        address: str,
        credential: str,
    ) -> dict[str, Any]:
        name = name.strip()
        connection_type = connection_type.strip()
        address = address.strip()
        if not name or not connection_type or not address or not credential:
            raise Unauthorized("名称、类型、接入地址与认证凭据均为必填", status_code=400)
        # 同一负责人下名称不可重复；跨负责人同名是不同对象，允许存在
        if security_store.find_connection_by_name(name, user.username) is not None:
            raise ConflictError("你名下已存在同名受控连接，请更换名称")
        conn = ControlledConnection(
            id=new_id(),
            name=name,
            connection_type=connection_type,
            address=address,
            credential=credential,
            owner=user.username,
        )
        security_store.add_connection(conn)
        security_store.register_redact_term(credential)
        security_store.register_redact_term(address)
        security_store.record_audit(
            actor=user.username,
            action="创建受控连接",
            connection_id=conn.id,
            detail="连接类型：{}（凭据与地址原文已隐藏）".format(connection_type),
        )
        return presentation.present_connection(conn, viewer=user.username)

    def list_connections(self, user: User) -> list[dict[str, Any]]:
        # 浏览者可见连接清单（含他人连接），但只能看到脱敏地址
        return [
            presentation.present_connection(conn, viewer=user.username)
            for conn in security_store.list_connections()
        ]

    def get_connection(self, user: User, connection_id: str) -> dict[str, Any]:
        conn = self._require_connection(connection_id)
        # 详情接口同样不能绕过脱敏：非负责人拿到的仍是脱敏地址与掩码凭据
        return presentation.present_connection(conn, viewer=user.username)

    def update_address(
        self, user: User, connection_id: str, new_address: str
    ) -> dict[str, Any]:
        conn = self._require_connection(connection_id)
        self._require_owner(user, conn)
        new_address = new_address.strip()
        if not new_address:
            raise Unauthorized("新的接入地址不能为空", status_code=400)
        old_host = self._host_of(conn.address)
        new_host = self._host_of(new_address)
        conn.address = new_address
        security_store.register_redact_term(new_address)
        conn.updated_at = utc_now_iso()
        # 只有主机变化才触发委派重确认；仅换路径 / 端口不触发
        host_changed = bool(old_host and new_host and old_host != new_host)
        if host_changed:
            conn.address_version += 1
            suspended = 0
            for delegation in security_store.list_delegations(
                connection_id=connection_id
            ):
                if delegation.status == DELEGATION_ACTIVE:
                    delegation.status = DELEGATION_SUSPENDED
                    delegation.suspended_address_version = conn.address_version
                    delegation.updated_at = utc_now_iso()
                    suspended += 1
            security_store.record_audit(
                actor=user.username,
                action="变更接入主机",
                connection_id=connection_id,
                detail="主机由 {} 切换为 {}，{} 条委派挂起待重新确认".format(
                    old_host, new_host, suspended
                ),
            )
        else:
            security_store.record_audit(
                actor=user.username,
                action="更新接入地址",
                connection_id=connection_id,
                detail="主机未变化，既有授权保持有效",
            )
        return presentation.present_connection(conn, viewer=user.username)

    def rotate_credential(
        self, user: User, connection_id: str, new_credential: str
    ) -> dict[str, Any]:
        conn = self._require_connection(connection_id)
        self._require_owner(user, conn)
        new_credential = new_credential.strip()
        if not new_credential:
            raise Unauthorized("新的认证凭据不能为空", status_code=400)
        # 凭据轮换只提升凭据版本，授权（含已挂起 / 有效的委派）原样保留，
        # 且作用域仍限定在本连接，不会影响或扩散到其他数据集。
        conn.credential = new_credential
        security_store.register_redact_term(new_credential)
        conn.credential_version += 1
        conn.updated_at = utc_now_iso()
        security_store.record_audit(
            actor=user.username,
            action="轮换认证凭据",
            connection_id=connection_id,
            detail="凭据版本升至 v{}，既有授权保持有效".format(conn.credential_version),
        )
        return presentation.present_connection(conn, viewer=user.username)

    # ---- 委派管理 ---------------------------------------------------
    def grant_delegation(
        self,
        user: User,
        *,
        connection_id: str,
        dataset_code: str,
        grantee: str,
    ) -> dict[str, Any]:
        conn = self._require_connection(connection_id)
        self._require_owner(user, conn)
        dataset_code = dataset_code.strip()
        grantee = grantee.strip()
        if not dataset_code or not grantee:
            raise Unauthorized("数据集编号与被委派人均为必填", status_code=400)
        target_user = security_store.get_user(grantee)
        if target_user is None or target_user.disabled:
            raise NotFound("被委派人账号不存在或已停用")
        if grantee == user.username:
            raise ConflictError("负责人无需向自己委派使用权")
        existing = security_store.find_active_delegation(
            connection_id, dataset_code, grantee
        )
        if existing is not None:
            raise ConflictError("该被委派人在此数据集上已有有效委派")
        delegation = Delegation(
            id=new_id(),
            connection_id=connection_id,
            dataset_code=dataset_code,
            granter=user.username,
            grantee=grantee,
        )
        security_store.add_delegation(delegation)
        security_store.record_audit(
            actor=user.username,
            action="授予委派",
            connection_id=connection_id,
            dataset_code=dataset_code,
            detail="被委派人：{}，范围仅限该数据集的连接消费".format(grantee),
        )
        return presentation.present_delegation(delegation)

    def list_delegations(
        self, user: User, *, connection_id: str | None = None
    ) -> list[dict[str, Any]]:
        items = security_store.list_delegations(connection_id=connection_id)
        # 被委派人只能看到与自己相关的委派；负责人能看到自己连接上的全部委派
        visible = [
            item
            for item in items
            if item.grantee == user.username
            or self._require_connection(item.connection_id).owner == user.username
        ]
        return [presentation.present_delegation(item) for item in visible]

    def reconfirm_delegation(
        self, user: User, delegation_id: str
    ) -> dict[str, Any]:
        delegation = security_store.get_delegation(delegation_id)
        if delegation is None:
            raise NotFound("委派记录不存在")
        conn = self._require_connection(delegation.connection_id)
        self._require_owner(user, conn)
        if delegation.status != DELEGATION_SUSPENDED:
            raise ConflictError("仅挂起状态的委派需要重新确认")
        delegation.status = DELEGATION_ACTIVE
        delegation.suspended_address_version = None
        delegation.updated_at = utc_now_iso()
        security_store.record_audit(
            actor=user.username,
            action="重新确认委派",
            connection_id=conn.id,
            dataset_code=delegation.dataset_code,
            detail="主机变更后的委派已恢复有效",
        )
        return presentation.present_delegation(delegation)

    def revoke_delegation(self, user: User, delegation_id: str) -> dict[str, Any]:
        delegation = security_store.get_delegation(delegation_id)
        if delegation is None:
            raise NotFound("委派记录不存在")
        conn = self._require_connection(delegation.connection_id)
        self._require_owner(user, conn)
        if delegation.status == DELEGATION_REVOKED:
            raise ConflictError("委派已处于撤回状态")
        delegation.status = DELEGATION_REVOKED
        delegation.updated_at = utc_now_iso()
        security_store.record_audit(
            actor=user.username,
            action="撤回委派",
            connection_id=conn.id,
            dataset_code=delegation.dataset_code,
            detail="被委派人：{}".format(delegation.grantee),
        )
        return presentation.present_delegation(delegation)

    # ---- 连接消费（委派的唯一凭据使用通道） -------------------------
    def consume_connection(
        self, user: User, *, connection_id: str, dataset_code: str
    ) -> dict[str, Any]:
        """被委派人通过该接口消费连接。

        返回的是可直接使用的连接句柄描述（类型 + 去认证段地址 + 句柄标识），
        原始凭据由系统在内部代取，绝不出现在响应里。
        """
        conn = self._require_connection(connection_id)
        dataset_code = dataset_code.strip()
        is_owner = conn.owner == user.username
        delegation = None
        if not is_owner:
            delegation = security_store.find_active_delegation(
                connection_id, dataset_code, user.username
            )
            if delegation is None:
                # 不区分「无委派」与「委派挂起」，统一拒绝，避免侧信道
                raise AccessDenied(
                    "没有该数据集上的有效连接使用权，或委派尚待负责人重新确认"
                )
        # 双保险：即便内部取数，也只生成句柄号，不回吐凭据原文
        handle = "handle-{}".format(new_id()[:12])
        security_store.record_audit(
            actor=user.username,
            action="消费连接",
            connection_id=connection_id,
            dataset_code=dataset_code,
            detail="通过{}建立连接句柄，凭据未外露".format(
                "负责人权限" if is_owner else "委派授权"
            ),
        )
        return {
            "connection_id": conn.id,
            "dataset_code": dataset_code,
            "connection_type": conn.connection_type,
            "endpoint": presentation.owner_view_address(conn.address),
            "credential_handle": handle,
            "credential_version": conn.credential_version,
            "via": "owner" if is_owner else "delegation",
        }

    # ---- 数据集登记入口的跨模块授权校验 -----------------------------
    def authorize_dataset_registration(
        self, user: User, *, connection_id: str, dataset_code: str
    ) -> None:
        """数据集登记调用：越权提交直接抛 AccessDenied。"""
        conn = self._require_connection(connection_id)
        if conn.owner == user.username:
            return
        delegation = security_store.find_active_delegation(
            connection_id, dataset_code, user.username
        )
        if delegation is None:
            raise AccessDenied(
                "数据集登记被拒绝：缺少该受控连接在数据集 {} 上的有效授权".format(
                    dataset_code
                )
            )

    # ---- 负责人移交 -------------------------------------------------
    def begin_handover(
        self, user: User, *, connection_id: str, to_owner: str
    ) -> dict[str, Any]:
        conn = self._require_connection(connection_id)
        self._require_owner(user, conn)
        to_owner = to_owner.strip()
        target = security_store.get_user(to_owner)
        if target is None or target.disabled:
            raise NotFound("新负责人账号不存在或已停用")
        if to_owner == user.username:
            raise ConflictError("不能向自己发起负责人移交")
        if security_store.pending_handover_for(connection_id) is not None:
            raise ConflictError("该连接已有待接收的移交，请先处理")
        handover = OwnershipHandover(
            id=new_id(),
            connection_id=connection_id,
            from_owner=user.username,
            to_owner=to_owner,
        )
        security_store.add_handover(handover)
        security_store.record_audit(
            actor=user.username,
            action="发起负责人移交",
            connection_id=connection_id,
            detail="拟由 {} 接收，等待对方确认".format(to_owner),
        )
        return presentation.present_handover(handover)

    def accept_handover(self, user: User, handover_id: str) -> dict[str, Any]:
        handover = security_store.get_handover(handover_id)
        if handover is None:
            raise NotFound("移交记录不存在")
        if handover.status != HANDOVER_PENDING:
            raise ConflictError("该移交已处理，不能重复确认")
        if handover.to_owner != user.username:
            raise AccessDenied("只有指定的新负责人可以接收移交")
        conn = self._require_connection(handover.connection_id)
        old_owner = conn.owner
        conn.owner = user.username
        conn.updated_at = utc_now_iso()
        handover.status = HANDOVER_DONE
        handover.decided_at = utc_now_iso()
        # 既有委派的 granter 留痕为旧负责人，但访问边界跟随连接；
        # 旧负责人此刻起不再是 owner，任何写操作都会被 _require_owner 拒绝。
        security_store.record_audit(
            actor=user.username,
            action="完成负责人移交",
            connection_id=conn.id,
            detail="责任关系由 {} 移交至 {}，旧负责人写权限已收回".format(
                old_owner, user.username
            ),
        )
        return presentation.present_handover(handover)

    def cancel_handover(self, user: User, handover_id: str) -> dict[str, Any]:
        handover = security_store.get_handover(handover_id)
        if handover is None:
            raise NotFound("移交记录不存在")
        if handover.status != HANDOVER_PENDING:
            raise ConflictError("该移交已处理，不能取消")
        conn = self._require_connection(handover.connection_id)
        # 现任负责人（可能仍是旧负责人）可以取消
        self._require_owner(user, conn)
        handover.status = HANDOVER_CANCELLED
        handover.decided_at = utc_now_iso()
        security_store.record_audit(
            actor=user.username,
            action="取消负责人移交",
            connection_id=conn.id,
            detail="移交至 {} 的流程已终止".format(handover.to_owner),
        )
        return presentation.present_handover(handover)

    def list_handovers(
        self, user: User, *, connection_id: str | None = None
    ) -> list[dict[str, Any]]:
        items = security_store.list_handovers(connection_id=connection_id)
        return [presentation.present_handover(item) for item in items]

    # ---- 审计 -------------------------------------------------------
    def list_audit(self, user: User) -> list[dict[str, Any]]:
        return security_store.list_audit()

    # ---- 工具 -------------------------------------------------------
    @staticmethod
    def _host_of(address: str) -> str:
        try:
            parts = urlsplit(address)
        except ValueError:
            return ""
        return parts.hostname or ""


security_service = SecurityService()
