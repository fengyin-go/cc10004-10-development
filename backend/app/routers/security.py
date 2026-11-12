"""受控连接安全接口：登录、连接边界、委派、消费、负责人移交与审计。

所有写接口都依赖 ``current_principal`` 完成身份验证；
所有响应都经过 presentation 脱敏，原始凭据不会出现在任何出口。
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.security.dependencies import current_principal
from app.security.service import security_service
from app.security.store import User

router = APIRouter(prefix="/api/security", tags=["受控连接安全"])


# ---- 请求模型 -------------------------------------------------------
class LoginPayload(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class ConnectionCreatePayload(BaseModel):
    name: str = Field(min_length=1)
    connection_type: str = Field(min_length=1)
    address: str = Field(min_length=1)
    credential: str = Field(min_length=1)


class AddressPayload(BaseModel):
    address: str = Field(min_length=1)


class CredentialPayload(BaseModel):
    credential: str = Field(min_length=1)


class DelegationPayload(BaseModel):
    connection_id: str = Field(min_length=1)
    dataset_code: str = Field(min_length=1)
    grantee: str = Field(min_length=1)


class ConsumePayload(BaseModel):
    connection_id: str = Field(min_length=1)
    dataset_code: str = Field(min_length=1)


class HandoverPayload(BaseModel):
    connection_id: str = Field(min_length=1)
    to_owner: str = Field(min_length=1)


# ---- 身份 -----------------------------------------------------------
@router.post("/auth/login")
def login(payload: LoginPayload) -> dict[str, Any]:
    """应用内最小登录：校验口令并签发 HMAC 签名的 Bearer 令牌。"""
    return security_service.login(payload.username, payload.password)


@router.get("/auth/me")
def me(user: User = Depends(current_principal)) -> dict[str, Any]:
    from app.security.presentation import present_user

    return present_user(user)


# ---- 受控连接 -------------------------------------------------------
@router.post("/connections")
def create_connection(
    payload: ConnectionCreatePayload, user: User = Depends(current_principal)
) -> dict[str, Any]:
    return security_service.create_connection(
        user,
        name=payload.name,
        connection_type=payload.connection_type,
        address=payload.address,
        credential=payload.credential,
    )


@router.get("/connections")
def list_connections(user: User = Depends(current_principal)) -> dict[str, Any]:
    return {"items": security_service.list_connections(user)}


@router.get("/connections/{connection_id}")
def get_connection(
    connection_id: str, user: User = Depends(current_principal)
) -> dict[str, Any]:
    # 详情接口同样受脱敏层约束，无法借此绕过看到原始凭据
    return security_service.get_connection(user, connection_id)


@router.put("/connections/{connection_id}/address")
def update_address(
    connection_id: str,
    payload: AddressPayload,
    user: User = Depends(current_principal),
) -> dict[str, Any]:
    return security_service.update_address(user, connection_id, payload.address)


@router.put("/connections/{connection_id}/credential")
def rotate_credential(
    connection_id: str,
    payload: CredentialPayload,
    user: User = Depends(current_principal),
) -> dict[str, Any]:
    return security_service.rotate_credential(
        user, connection_id, payload.credential
    )


# ---- 委派 -----------------------------------------------------------
@router.post("/delegations")
def grant_delegation(
    payload: DelegationPayload, user: User = Depends(current_principal)
) -> dict[str, Any]:
    return security_service.grant_delegation(
        user,
        connection_id=payload.connection_id,
        dataset_code=payload.dataset_code,
        grantee=payload.grantee,
    )


@router.get("/delegations")
def list_delegations(
    connection_id: str | None = None, user: User = Depends(current_principal)
) -> dict[str, Any]:
    return {
        "items": security_service.list_delegations(
            user, connection_id=connection_id
        )
    }


@router.post("/delegations/{delegation_id}/reconfirm")
def reconfirm_delegation(
    delegation_id: str, user: User = Depends(current_principal)
) -> dict[str, Any]:
    return security_service.reconfirm_delegation(user, delegation_id)


@router.post("/delegations/{delegation_id}/revoke")
def revoke_delegation(
    delegation_id: str, user: User = Depends(current_principal)
) -> dict[str, Any]:
    return security_service.revoke_delegation(user, delegation_id)


# ---- 连接消费（委派唯一凭据通道） -----------------------------------
@router.post("/connections/consume")
def consume_connection(
    payload: ConsumePayload, user: User = Depends(current_principal)
) -> dict[str, Any]:
    return security_service.consume_connection(
        user,
        connection_id=payload.connection_id,
        dataset_code=payload.dataset_code,
    )


# ---- 负责人移交 -----------------------------------------------------
@router.post("/handovers")
def begin_handover(
    payload: HandoverPayload, user: User = Depends(current_principal)
) -> dict[str, Any]:
    return security_service.begin_handover(
        user, connection_id=payload.connection_id, to_owner=payload.to_owner
    )


@router.get("/handovers")
def list_handovers(
    connection_id: str | None = None, user: User = Depends(current_principal)
) -> dict[str, Any]:
    return {
        "items": security_service.list_handovers(
            user, connection_id=connection_id
        )
    }


@router.post("/handovers/{handover_id}/accept")
def accept_handover(
    handover_id: str, user: User = Depends(current_principal)
) -> dict[str, Any]:
    return security_service.accept_handover(user, handover_id)


@router.post("/handovers/{handover_id}/cancel")
def cancel_handover(
    handover_id: str, user: User = Depends(current_principal)
) -> dict[str, Any]:
    return security_service.cancel_handover(user, handover_id)


# ---- 审计 -----------------------------------------------------------
@router.get("/audit")
def list_audit(user: User = Depends(current_principal)) -> dict[str, Any]:
    return {"items": security_service.list_audit(user)}
