# 受控连接安全边界（应用内最小方案）

不依赖任何外部认证服务，也不连接真实生产数据库：身份、连接、委派、移交全部
驻留在应用内存里，用标准库完成口令哈希与令牌签名。重启进程后数据清空，
适合本地演示与自动化验证。

## 演示账号（应用启动时自动注入）

| 用户名 | 口令 | 角色 |
| --- | --- | --- |
| alice | `alice-pass-2026` | 连接负责人 |
| bob | `bob-pass-2026` | 数据集负责人 / 被委派人 |
| carol | `carol-pass-2026` | 普通浏览者 |
| dave | `dave-pass-2026` | 另一连接负责人 |

## 目录结构

```
backend/app/security/
├── crypto.py        # PBKDF2 口令哈希 + HMAC-SHA256 签名令牌（仅标准库）
├── store.py         # 账号/受控连接/委派/移交/审计 的线程安全内存仓库 + 历史敏感值登记
├── presentation.py  # 唯一对外序列化出口：凭据掩码、地址按角色脱敏、剥除 URL 认证段
├── service.py       # 全部授权规则：边界、委派、主机变更、凭据轮换、负责人移交
├── dependencies.py  # FastAPI 依赖：Authorization 头 -> 当前登录用户
├── errors.py        # 401/403/404/409 错误类型，消息不含敏感上下文
├── logging.py       # 根日志过滤器：URL 认证段 + 历史凭据/地址原文统一抹除
└── seed.py          # 演示身份
backend/app/routers/security.py   # /api/security/* 接口
backend/app/services/datastore.py # 数据集登记入口的跨模块授权接入点
backend/tests/                    # 66 + 5 条端到端断言，纯标准库可直接运行
```

## 关键不变量与实现位置

1. **凭据与负责人纳入访问边界**
   连接对象（`ControlledConnection`）持有 `credential` 原文与 `owner`；
   原文只在 `service.py` 内部用于「消费连接」，对外只经 `presentation.py`
   输出 `******` 掩码与脱敏地址。

2. **负责人按数据集委派使用权，委派只能消费连接**
   `POST /api/security/delegations` 仅负责人可调，委派维度是
   `connection_id + dataset_code + grantee`。被委派人通过
   `POST /api/security/connections/consume` 拿到的是 `credential_handle`
   句柄与去认证段地址，响应结构里不存在原始凭据字段。

3. **普通浏览者只能看脱敏地址，详情接口不能绕过**
   列表与详情共用 `present_connection`：非负责人主机名打码（首尾保留）、
   端口保留、认证段剥除；凭据对所有角色一律掩码。

4. **换主机必须重新确认委派**
   `update_address` 比较新旧 URL 的 hostname：主机变化时
   `address_version + 1`，该连接所有「有效」委派转为「待重新确认」并记录
   `suspended_address_version`；挂起期间消费与数据集登记均被拒。
   负责人 `POST /delegations/{id}/reconfirm` 后恢复。仅路径/端口变化不触发。

5. **凭据轮换保留有效授权、不向无关数据集扩散**
   `rotate_credential` 只提升 `credential_version` 并登记新的日志脱敏词，
   不动任何委派；授权始终绑定具体连接 + 数据集，其他数据集天然无法继承。

6. **负责人换人有移交记录，旧负责人立即失权**
   `POST /handovers` 发起（待接收）→ 指定新负责人 `accept` 后连接 `owner`
   变更、移交记录落审计。此后旧负责人的任何写操作都被 `_require_owner`
   以 403 拒绝。

7. **跨模块接到数据集登记入口，越权提交拒绝**
   `DatastoreService.create_entry` 强制要求 `受控连接编号`，调用
   `security_service.authorize_dataset_registration`：无负责人身份且无有效
   委派（含挂起）时抛 403。数据集记录只保存连接 UUID 引用，不复制凭据。

8. **跨负责人同名连接不会被误认**
   连接主键是随机 UUID；重名校验只在「同一负责人」范围内生效
   （`find_connection_by_name` 同时匹配 name 与 owner），跨负责人同名是
   两个独立对象。

9. **日志与错误响应不泄露凭据**
   - `RedactingFilter` 挂在根 logger：正则抹除 URL `user:pass@`，并按
     `SecurityStore` 登记的全部历史敏感值（含已轮换旧值）做字面量替换；
   - 422 校验处理器剔除请求原文 `input`，不回显提交的凭据；
   - 500 兜底只返回通用提示；审计事件只记录动作与非敏感标识。

## 接口速览（均以 `/api/security` 为前缀，除登录外都要 Bearer 令牌）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/auth/login` | 口令换 HMAC 签名令牌 |
| GET | `/auth/me` | 当前身份 |
| POST/GET | `/connections`、`GET /connections/{id}` | 受控连接登记 / 列表 / 详情（脱敏） |
| PUT | `/connections/{id}/address` | 改地址（主机变更触发委派挂起） |
| PUT | `/connections/{id}/credential` | 凭据轮换（授权保留） |
| POST | `/connections/consume` | 委派唯一凭据通道，返回句柄而非凭据 |
| POST/GET | `/delegations` | 授予 / 查询委派 |
| POST | `/delegations/{id}/reconfirm`、`/revoke` | 重新确认 / 撤回 |
| POST/GET | `/handovers` | 发起 / 查询负责人移交 |
| POST | `/handovers/{id}/accept`、`/cancel` | 接收 / 取消移交 |
| GET | `/audit` | 审计记录（无敏感值） |
| POST | `/api/datastore` | 数据集登记：强制连接授权校验（403 拒绝越权） |

## 运行与验证

```bash
make backend          # 启动后端 http://127.0.0.1:8000 （/docs 可交互调试）
make frontend         # 启动前端 http://127.0.0.1:5173
make test             # 后端两组端到端断言 + 前端严格类型检查构建
```

前端入口：顶栏「登录」→ 侧边「受控连接安全」控制台（连接 / 委派 / 移交 /
审计四个页签）；数据集管理页的「登记数据集定义」会弹出受控连接选择器，
越权时直接展示服务端返回的 403 原因。
