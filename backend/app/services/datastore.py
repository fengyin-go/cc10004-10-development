"""数据集管理业务规则：状态流转、字段校验与筛选口径都收在这里。

数据集登记入口跨模块接入受控连接：登记时必须提交受控连接编号，
并通过安全子系统校验当前用户对该连接 + 数据集是否具备有效授权
（负责人身份或有效委派）。越权提交在这里被拒绝，凭据不进入数据集记录。
"""
from __future__ import annotations

from typing import Any

from app.security.service import security_service
from app.security.store import User
from app.store import store

MODULE = "datastore"
REQUIRED_FIELDS = ["数据集编号", "数据集名称", "来源表名"]
# 受控连接为跨模块强制字段
CONNECTION_FIELD = "受控连接编号"
STATUS_ORDER = ["草稿", "待审核", "已生效", "已废弃"]
ACTION_RULES = {"提交审核": "待审核", "生效发布": "已生效", "废弃下线": "已废弃"}
NEGATIVE_ACTIONS = []


class DatastoreService:
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
            rows = [row for row in rows if keyword in str(row.get("数据集编号", ""))]
        if status:
            rows = [row for row in rows if row.get("status") == status]
        total = len(rows)
        start = max(page - 1, 0) * size
        return rows[start:start + size], total

    def get_entry(self, entry_id: int) -> dict[str, Any] | None:
        return store.find(MODULE, entry_id)

    def create_entry(
        self, values: dict[str, Any], principal: User
    ) -> tuple[dict[str, Any] | None, list[str]]:
        missing = [
            field
            for field in REQUIRED_FIELDS + [CONNECTION_FIELD]
            if not str(values.get(field) or "").strip()
        ]
        if missing:
            return None, missing
        connection_id = str(values[CONNECTION_FIELD]).strip()
        dataset_code = str(values["数据集编号"]).strip()

        # 跨模块访问边界：先确认受控连接存在，再确认当前身份有授权。
        # 越权（无负责人身份且无有效委派 / 委派已挂起）一律抛 AccessDenied。
        security_service.authorize_dataset_registration(
            principal, connection_id=connection_id, dataset_code=dataset_code
        )

        rows = store.rows(MODULE)
        entry = {"id": max((int(row.get("id", 0)) for row in rows), default=0) + 1}
        entry.update({field: values.get(field) for field in REQUIRED_FIELDS})
        # 只保存连接的 UUID 引用，凭据与地址原文绝不复制进数据集记录
        entry[CONNECTION_FIELD] = connection_id
        entry["登记人"] = principal.username
        entry["status"] = STATUS_ORDER[0]
        entry["pending"] = True
        entry["abnormal"] = False
        rows.append(entry)
        return entry, []

    def run_action(self, entry_id: int, action: str) -> tuple[dict[str, Any] | None, str]:
        entry = store.find(MODULE, entry_id)
        if entry is None:
            return None, f"数据集定义 {entry_id} 不存在或已归档"
        if action not in ACTION_RULES:
            return None, f"动作「{action}」不属于数据集管理可执行范围"
        target = ACTION_RULES[action]
        if target not in STATUS_ORDER:
            return None, f"目标状态「{target}」不在允许的状态序列里"
        entry["status"] = target
        entry["pending"] = target != STATUS_ORDER[-1]
        entry["abnormal"] = action in NEGATIVE_ACTIONS
        return entry, f"数据集定义已{action}"
