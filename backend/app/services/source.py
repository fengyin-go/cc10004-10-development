"""数据源接入业务规则：状态流转、字段校验与筛选口径都收在这里。

安全约束：认证凭据属于受控敏感字段，列表 / 详情 / 导出出口一律只回显掩码，
原始值不随任何响应离开服务端；真正的连接访问边界由 app.security 子系统统一管理。
"""
from __future__ import annotations

from typing import Any

from app.security.presentation import owner_view_address
from app.store import store

MODULE = "source"
REQUIRED_FIELDS = ["配置编号", "连接类型", "接入地址"]
CREDENTIAL_FIELD = "认证凭证"
ADDRESS_FIELD = "接入地址"
CREDENTIAL_MASK = "******"
STATUS_ORDER = ["草稿", "待校验", "已连接", "已断开"]
ACTION_RULES = {"提交校验": "待校验", "建立连接": "已连接", "断开连接": "已断开"}
NEGATIVE_ACTIONS = []


def _mask_credential(row: dict[str, Any]) -> dict[str, Any]:
    """返回行副本：凭据替换为固定掩码，地址中的认证段（user:pass@）一并剥除。"""
    safe = dict(row)
    if safe.get(CREDENTIAL_FIELD):
        safe[CREDENTIAL_FIELD] = CREDENTIAL_MASK
    if safe.get(ADDRESS_FIELD):
        safe[ADDRESS_FIELD] = owner_view_address(str(safe[ADDRESS_FIELD]))
    return safe


class SourceService:
    def list_entries(
        self,
        *,
        keyword: str | None = None,
        status: str | None = None,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        rows = store.rows(MODULE)
        if keyword:
            rows = [row for row in rows if keyword in str(row.get("配置编号", ""))]
        if status:
            rows = [row for row in rows if row.get("status") == status]
        total = len(rows)
        start = max(page - 1, 0) * size
        page_rows = [_mask_credential(row) for row in rows[start:start + size]]
        return page_rows, total

    def get_entry(self, entry_id: int) -> dict[str, Any] | None:
        row = store.find(MODULE, entry_id)
        return _mask_credential(row) if row is not None else None

    def create_entry(self, values: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
        missing = [field for field in REQUIRED_FIELDS if not str(values.get(field) or "").strip()]
        if missing:
            return None, missing
        rows = store.rows(MODULE)
        entry = {"id": max((int(row.get("id", 0)) for row in rows), default=0) + 1}
        entry.update({field: values.get(field) for field in REQUIRED_FIELDS})
        # 凭据原文只进内存存储层，任何读取出口都经过 _mask_credential
        if str(values.get(CREDENTIAL_FIELD) or "").strip():
            entry[CREDENTIAL_FIELD] = values[CREDENTIAL_FIELD]
        entry["status"] = STATUS_ORDER[0]
        entry["pending"] = True
        entry["abnormal"] = False
        rows.append(entry)
        return _mask_credential(entry), []

    def run_action(self, entry_id: int, action: str) -> tuple[dict[str, Any] | None, str]:
        entry = store.find(MODULE, entry_id)
        if entry is None:
            return None, f"接入配置 {entry_id} 不存在或已归档"
        if action not in ACTION_RULES:
            return None, f"动作「{action}」不属于数据源接入可执行范围"
        target = ACTION_RULES[action]
        if target not in STATUS_ORDER:
            return None, f"目标状态「{target}」不在允许的状态序列里"
        entry["status"] = target
        entry["pending"] = target != STATUS_ORDER[-1]
        entry["abnormal"] = action in NEGATIVE_ACTIONS
        return _mask_credential(entry), f"接入配置已{action}"
