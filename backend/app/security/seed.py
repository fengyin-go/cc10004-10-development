"""安全子系统的初始化账号。

仅用于本地演示与自动化测试的最小身份集合，不接任何外部用户目录。
"""
from __future__ import annotations

from app.security.store import security_store

# 用户名 -> (显示名, 初始口令)
SEED_USERS: dict[str, tuple[str, str]] = {
    "alice": ("Alice（连接负责人）", "alice-pass-2026"),
    "bob": ("Bob（数据集负责人）", "bob-pass-2026"),
    "carol": ("Carol（普通浏览者）", "carol-pass-2026"),
    "dave": ("Dave（另一连接负责人）", "dave-pass-2026"),
}


def seed_identities() -> None:
    for username, (display_name, password) in SEED_USERS.items():
        security_store.seed_user(username, display_name, password)
