"""旧数据源模块（source）的凭据出口脱敏验证。

受控连接的权威边界在 app.security；这里保证旧模块即使收了凭据字段，
列表、详情、导出、动作响应也都不会把原文带出去。
"""
from __future__ import annotations

import sys

from starlette.testclient import TestClient

from app.main import app

FAILED: list[str] = []


def check(name: str, condition: bool, extra: object = None) -> None:
    print(f"[{'PASS' if condition else 'FAIL'}] {name}" + (f" -> {extra}" if extra and not condition else ""))
    if not condition:
        FAILED.append(name)


def main() -> int:
    secret = "legacy-secret-value-777"
    with TestClient(app) as client:
        token = client.post(
            "/api/security/auth/login",
            json={"username": "alice", "password": "alice-pass-2026"},
        ).json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        created = client.post(
            "/api/source",
            headers=headers,
            json={
                "values": {
                    "配置编号": "SOUR-SEC-1",
                    "连接类型": "mysql",
                    "接入地址": "mysql://u:legacy-secret-value-777@host:3306/db",
                    "认证凭证": secret,
                }
            },
        ).json()
        check("创建响应凭据已掩码", created["entry"]["认证凭证"] == "******")

        listing = client.get("/api/source?keyword=SOUR-SEC-1", headers=headers).text
        check("列表不泄露凭据", secret not in listing)

        exported = client.get("/api/source/export", headers=headers).text
        check("导出不泄露凭据", secret not in exported)

        entry_id = created["entry"]["id"]
        detail = client.get(f"/api/source/{entry_id}", headers=headers).json()
        check("详情凭据已掩码", detail["认证凭证"] == "******")

        action = client.post(
            f"/api/source/{entry_id}/actions",
            headers=headers,
            json={"values": {"action": "建立连接"}},
        ).text
        check("动作响应不泄露凭据", secret not in action)

    print("\n" + ("全部通过" if not FAILED else f"{len(FAILED)} 项失败：{FAILED}"))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
