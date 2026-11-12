"""受控连接安全边界的端到端验证。

只用标准库断言 + Starlette TestClient，覆盖需求中的每一条不变量：
1. 凭据不出现在列表 / 详情 / 错误 / 日志出口；
2. 委派只能消费连接，读不到原始凭据；
3. 主机变更挂起委派，重新确认后恢复；
4. 凭据轮换保留授权，且不向无关数据集扩散；
5. 负责人移交留痕，旧负责人失去写权限；
6. 数据集登记入口的跨模块授权，越权提交被拒；
7. 跨负责人同名连接是两个不同对象。

运行：.venv/bin/python -m tests.test_security_boundary
"""
from __future__ import annotations

import logging
import sys
import uuid

from starlette.testclient import TestClient

from app.main import app
from app.security.store import security_store

FAILED = []


def check(name: str, condition: bool, extra: object = None) -> None:
    mark = "PASS" if condition else "FAIL"
    print(f"[{mark}] {name}" + (f" -> {extra}" if extra and not condition else ""))
    if not condition:
        FAILED.append(name)


def login(client: TestClient, username: str, password: str) -> str:
    response = client.post(
        "/api/security/auth/login",
        json={"username": username, "password": password},
    )
    assert response.status_code == 200, response.text
    return response.json()["token"]


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def main() -> int:
    # 每次运行使用独立的内存状态
    with TestClient(app) as client:
        alice = login(client, "alice", "alice-pass-2026")
        bob = login(client, "bob", "bob-pass-2026")
        carol = login(client, "carol", "carol-pass-2026")
        dave = login(client, "dave", "dave-pass-2026")

        secret_credential = "s3cr3t-token-" + uuid.uuid4().hex
        secret_address = "mysql://svc:passw0rd@db-primary.internal:3306/warehouse"
        other_credential = "other-secret-" + uuid.uuid4().hex

        # ---- 1. 负责人创建受控连接 ------------------------------
        response = client.post(
            "/api/security/connections",
            headers=auth(alice),
            json={
                "name": "订单库连接",
                "connection_type": "mysql",
                "address": secret_address,
                "credential": secret_credential,
            },
        )
        check("负责人创建连接", response.status_code == 200, response.text)
        conn = response.json()
        conn_id = conn["id"]

        # ---- 2. 凭据在任何对外结构里都不可见 --------------------
        check("创建响应不回显原始凭据", conn["credential"] == "******")
        check("负责人地址剥除认证段", "svc:passw0rd" not in conn["address"])
        check("负责人可见主机名", "db-primary.internal" in conn["address"])

        detail = client.get(
            f"/api/security/connections/{conn_id}", headers=auth(carol)
        ).json()
        check(
            "浏览者详情接口不泄露凭据",
            detail["credential"] == "******" and secret_credential not in str(detail),
        )
        check(
            "浏览者地址脱敏（主机名打码）",
            "db-primary.internal" not in detail["address"] and "*" in detail["address"],
            detail["address"],
        )
        check(
            "浏览者地址不含认证段",
            "svc:passw0rd" not in detail["address"],
            detail["address"],
        )

        listing = client.get("/api/security/connections", headers=auth(carol)).text
        check("列表接口不泄露凭据", secret_credential not in listing)
        check("列表接口不泄露认证段", "svc:passw0rd" not in listing)

        # ---- 3. 无身份 / 非法令牌被拒 ---------------------------
        check(
            "缺少令牌访问连接被拒",
            client.get("/api/security/connections").status_code == 401,
        )
        check(
            "伪造令牌被拒",
            client.get(
                "/api/security/connections", headers=auth("not-a-real-token")
            ).status_code
            == 401,
        )

        # ---- 4. 跨负责人同名连接是两个对象 ----------------------
        response = client.post(
            "/api/security/connections",
            headers=auth(dave),
            json={
                "name": "订单库连接",
                "connection_type": "postgres",
                "address": "postgres://other-host.internal:5432/sales",
                "credential": other_credential,
            },
        )
        check(
            "跨负责人允许同名连接", response.status_code == 200, response.text
        )
        dave_conn = response.json()
        check("同名连接拥有不同 UUID", dave_conn["id"] != conn_id)
        check(
            "Alice 看不到 Dave 连接的明文",
            client.get(
                f"/api/security/connections/{dave_conn['id']}", headers=auth(alice)
            ).json()["address"].count("*")
            > 0,
        )
        # 同一负责人下重名必须被拒
        dup = client.post(
            "/api/security/connections",
            headers=auth(alice),
            json={
                "name": "订单库连接",
                "connection_type": "mysql",
                "address": "mysql://x.internal:3306/y",
                "credential": "whatever",
            },
        )
        check("同一负责人重名被拒", dup.status_code == 409)

        # ---- 5. 非负责人不能修改连接 ----------------------------
        forbidden_addr = client.put(
            f"/api/security/connections/{conn_id}/address",
            headers=auth(bob),
            json={"address": "mysql://hacked.internal:3306/x"},
        )
        check("非负责人改地址被拒", forbidden_addr.status_code == 403)
        forbidden_cred = client.put(
            f"/api/security/connections/{conn_id}/credential",
            headers=auth(bob),
            json={"credential": "new"},
        )
        check("非负责人轮换凭据被拒", forbidden_cred.status_code == 403)

        # ---- 6. 负责人委派：按数据集授予使用权 ------------------
        dataset_a = "DATA-1001"
        dataset_b = "DATA-1002"
        response = client.post(
            "/api/security/delegations",
            headers=auth(alice),
            json={
                "connection_id": conn_id,
                "dataset_code": dataset_a,
                "grantee": "bob",
            },
        )
        check("负责人授予委派", response.status_code == 200, response.text)
        delegation_a = response.json()
        check("委派初始有效", delegation_a["status"] == "有效")

        # 普通浏览者不能自行委派
        rogue = client.post(
            "/api/security/delegations",
            headers=auth(carol),
            json={
                "connection_id": conn_id,
                "dataset_code": dataset_a,
                "grantee": "carol",
            },
        )
        check("非负责人委派被拒", rogue.status_code == 403)

        # ---- 7. 委派只能消费连接，读不到凭据 --------------------
        consume = client.post(
            "/api/security/connections/consume",
            headers=auth(bob),
            json={"connection_id": conn_id, "dataset_code": dataset_a},
        )
        check("被委派人可消费连接", consume.status_code == 200, consume.text)
        payload = consume.json()
        check(
            "消费响应不返回原始凭据",
            secret_credential not in str(payload)
            and set(payload) == {
                "connection_id",
                "dataset_code",
                "connection_type",
                "endpoint",
                "credential_handle",
                "credential_version",
                "via",
            },
            payload,
        )
        check("消费只给凭据句柄", payload["credential_handle"].startswith("handle-"))
        check("消费通道标记为委派", payload["via"] == "delegation")

        # 未被委派的数据集 / 用户不能消费
        no_scope = client.post(
            "/api/security/connections/consume",
            headers=auth(bob),
            json={"connection_id": conn_id, "dataset_code": dataset_b},
        )
        check("无该数据集委派时消费被拒", no_scope.status_code == 403)
        no_user = client.post(
            "/api/security/connections/consume",
            headers=auth(carol),
            json={"connection_id": conn_id, "dataset_code": dataset_a},
        )
        check("未委派用户消费被拒", no_user.status_code == 403)
        check("拒绝消息不含凭据", secret_credential not in no_scope.text)

        # ---- 8. 数据集登记入口：跨模块授权 ----------------------
        def register(user_token: str, dataset_code: str, connection: str):
            return client.post(
                "/api/datastore",
                headers=auth(user_token),
                json={
                    "values": {
                        "数据集编号": dataset_code,
                        "数据集名称": "登记数据集",
                        "来源表名": "tbl",
                        "受控连接编号": connection,
                    }
                },
            )

        # 未登录直接被认证层拦截
        check(
            "未登录登记被拒",
            client.post(
                "/api/datastore",
                json={"values": {"数据集编号": "DATA-X"}},
            ).status_code
            == 401,
        )
        # Bob 有 dataset_a 的委派：登记成功
        ok = register(bob, dataset_a, conn_id)
        check("被委派人登记授权数据集成功", ok.status_code == 200, ok.text)
        check(
            "数据集记录只保存连接引用",
            ok.json()["entry"]["受控连接编号"] == conn_id
            and secret_credential not in ok.text,
        )
        # Bob 对 dataset_b 无授权：越权提交 403
        denied = register(bob, dataset_b, conn_id)
        check("越权登记被拒绝", denied.status_code == 403, denied.text)
        # Carol 完全无授权
        denied2 = register(carol, dataset_a, conn_id)
        check("无授权用户登记被拒绝", denied2.status_code == 403)
        # 负责人本人可登记
        owner_reg = register(alice, dataset_b, conn_id)
        check("负责人登记成功", owner_reg.status_code == 200, owner_reg.text)
        # 引用不存在的连接
        ghost = register(bob, dataset_a, uuid.uuid4().hex)
        check("引用不存在连接被拒", ghost.status_code == 404)

        # ---- 9. 主机变更：委派挂起，必须重新确认 ----------------
        change = client.put(
            f"/api/security/connections/{conn_id}/address",
            headers=auth(alice),
            json={"address": "mysql://svc:newpass@db-standby.internal:3306/warehouse"},
        )
        check("负责人变更主机", change.status_code == 200, change.text)
        check("地址版本递增", change.json()["address_version"] == 2)

        suspended_consume = client.post(
            "/api/security/connections/consume",
            headers=auth(bob),
            json={"connection_id": conn_id, "dataset_code": dataset_a},
        )
        check("主机变更后委派挂起、消费被拒", suspended_consume.status_code == 403)
        suspended_register = register(bob, dataset_a, conn_id)
        check("挂起期间数据集登记被拒", suspended_register.status_code == 403)

        delegations = client.get(
            "/api/security/delegations",
            headers=auth(alice),
            params={"connection_id": conn_id},
        ).json()["items"]
        suspended = next(item for item in delegations if item["id"] == delegation_a["id"])
        check("委派状态为待重新确认", suspended["status"] == "待重新确认")
        check("记录挂起时的地址版本", suspended["suspended_address_version"] == 2)

        reconfirm = client.post(
            f"/api/security/delegations/{delegation_a['id']}/reconfirm",
            headers=auth(alice),
        )
        check("负责人重新确认委派", reconfirm.status_code == 200, reconfirm.text)
        check("确认后委派恢复有效", reconfirm.json()["status"] == "有效")
        consume_again = client.post(
            "/api/security/connections/consume",
            headers=auth(bob),
            json={"connection_id": conn_id, "dataset_code": dataset_a},
        )
        check("重新确认后消费恢复", consume_again.status_code == 200)

        # 仅路径变化、主机不变不应挂起
        client.put(
            f"/api/security/connections/{conn_id}/address",
            headers=auth(alice),
            json={"address": "mysql://db-standby.internal:3306/warehouse_v2"},
        )
        after = client.get(
            "/api/security/delegations", headers=auth(bob)
        ).json()["items"]
        check(
            "主机不变时授权保持有效",
            all(item["status"] == "有效" for item in after)
            and all(item["suspended_address_version"] is None for item in after),
            after,
        )

        # ---- 10. 凭据轮换：授权保留，不扩散到无关数据集 ----------
        rotate = client.put(
            f"/api/security/connections/{conn_id}/credential",
            headers=auth(alice),
            json={"credential": "rotated-credential-" + uuid.uuid4().hex},
        )
        check("负责人轮换凭据", rotate.status_code == 200)
        check("凭据版本递增", rotate.json()["credential_version"] == 2)
        check("轮换响应仍不回显凭据", rotate.json()["credential"] == "******")

        still_works = client.post(
            "/api/security/connections/consume",
            headers=auth(bob),
            json={"connection_id": conn_id, "dataset_code": dataset_a},
        )
        check("轮换后既有授权仍有效", still_works.status_code == 200)
        still_denied = client.post(
            "/api/security/connections/consume",
            headers=auth(bob),
            json={"connection_id": conn_id, "dataset_code": dataset_b},
        )
        check(
            "授权未向无关数据集继承", still_denied.status_code == 403
        )

        # ---- 11. 负责人移交：留痕 + 旧负责人失权 -----------------
        handover = client.post(
            "/api/security/handovers",
            headers=auth(alice),
            json={"connection_id": conn_id, "to_owner": "dave"},
        )
        check("旧负责人发起移交", handover.status_code == 200, handover.text)
        handover_id = handover.json()["id"]
        check("移交初始待接收", handover.json()["status"] == "待接收")

        # 第三方不能接收
        third = client.post(
            f"/api/security/handovers/{handover_id}/accept", headers=auth(bob)
        )
        check("非指定接收人确认被拒", third.status_code == 403)

        accepted = client.post(
            f"/api/security/handovers/{handover_id}/accept", headers=auth(dave)
        )
        check("新负责人接收移交", accepted.status_code == 200, accepted.text)
        check("移交记录状态为已移交", accepted.json()["status"] == "已移交")

        owner_now = client.get(
            f"/api/security/connections/{conn_id}", headers=auth(dave)
        ).json()
        check("连接负责人已变更", owner_now["owner"] == "dave" and owner_now["is_owner"])

        old_owner_write = client.put(
            f"/api/security/connections/{conn_id}/address",
            headers=auth(alice),
            json={"address": "mysql://db-standby.internal:3306/new"},
        )
        check("旧负责人无法再改动连接", old_owner_write.status_code == 403)
        old_owner_grant = client.post(
            "/api/security/delegations",
            headers=auth(alice),
            json={
                "connection_id": conn_id,
                "dataset_code": "DATA-NEW",
                "grantee": "carol",
            },
        )
        check("旧负责人无法再委派", old_owner_grant.status_code == 403)

        history = client.get("/api/security/handovers", headers=auth(dave)).json()[
            "items"
        ]
        record = next(item for item in history if item["id"] == handover_id)
        check(
            "移交留痕包含新旧负责人",
            record["from_owner"] == "alice"
            and record["to_owner"] == "dave"
            and record["decided_at"],
            record,
        )

        # 新负责人可以继续管理；Bob 的既有委派仍按连接保留
        new_owner_rotate = client.put(
            f"/api/security/connections/{conn_id}/credential",
            headers=auth(dave),
            json={"credential": "dave-credential"},
        )
        check("新负责人可管理连接", new_owner_rotate.status_code == 200)
        bob_still = client.post(
            "/api/security/connections/consume",
            headers=auth(bob),
            json={"connection_id": conn_id, "dataset_code": dataset_a},
        )
        check("移交后既有委派仍可消费", bob_still.status_code == 200)

        # ---- 12. 撤回委派立即失效 --------------------------------
        delegation_id = client.get(
            "/api/security/delegations",
            headers=auth(dave),
            params={"connection_id": conn_id},
        ).json()["items"][0]["id"]
        revoked = client.post(
            f"/api/security/delegations/{delegation_id}/revoke", headers=auth(dave)
        )
        check("负责人撤回委派", revoked.status_code == 200)
        after_revoke = client.post(
            "/api/security/connections/consume",
            headers=auth(bob),
            json={"connection_id": conn_id, "dataset_code": dataset_a},
        )
        check("撤回后消费立即被拒", after_revoke.status_code == 403)

        # ---- 13. 审计与日志不含凭据 -----------------------------
        audit = client.get("/api/security/audit", headers=auth(alice)).text
        check("审计记录不含原始凭据", secret_credential not in audit)
        check("审计记录不含地址认证段", "passw0rd" not in audit and "newpass" not in audit)

        # 触发一次错误，验证异常处理器不回显内部信息
        boom = client.put(
            f"/api/security/connections/{conn_id}/credential",
            headers=auth(alice),
            json={"credential": "x"},
        )
        check("越权错误响应不含凭据", boom.status_code == 403 and "dave-credential" not in boom.text)

        # 日志过滤器直接验证
        from app.security.logging import RedactingFilter

        record = logging.LogRecord(
            name="t",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=f"connecting with {secret_address} token {secret_credential}",
            args=(),
            exc_info=None,
        )
        RedactingFilter().filter(record)
        check(
            "日志过滤器抹除认证段与凭据",
            "passw0rd" not in record.getMessage()
            and secret_credential not in record.getMessage(),
            record.getMessage(),
        )

    print("\n" + ("全部通过" if not FAILED else f"{len(FAILED)} 项失败：{FAILED}"))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
