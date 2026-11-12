"""数据洞察分析工作台 后端服务入口。

启动：uvicorn app.main:app --host 127.0.0.1 --port 8000
健康检查：GET /api/health
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.routers import ROUTERS
from app.security.errors import AuthError
from app.security.logging import install_redaction
from app.security.seed import seed_identities
from app.store import store

# 在任何业务日志产生之前安装脱敏过滤器
install_redaction()
logger = logging.getLogger("app")

app = FastAPI(title="数据洞察分析工作台", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

for module in ROUTERS:
    app.include_router(module.router)


@app.on_event("startup")
def _startup() -> None:
    # 初始化最小身份集合（仅内存，不接外部认证服务）
    seed_identities()
    logger.info("安全子系统就绪，演示身份已加载")


@app.exception_handler(AuthError)
def handle_auth_error(_: Request, exc: AuthError) -> JSONResponse:
    """安全错误统一出口：只回传可读提示与状态码，不回传任何敏感上下文。"""
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@app.exception_handler(RequestValidationError)
def handle_validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    """校验错误去掉请求原文（input），避免凭据随 422 响应回显。"""
    safe_errors = []
    for error in exc.errors():
        safe_errors.append(
            {
                "loc": list(error.get("loc", [])),
                "msg": error.get("msg", "请求参数不合法"),
                "type": error.get("type", "value_error"),
            }
        )
    return JSONResponse(status_code=422, content={"detail": safe_errors})


@app.exception_handler(Exception)
def handle_unexpected(_: Request, exc: Exception) -> JSONResponse:
    """兜底 500：记录脱敏后的异常，对外只给通用提示，不泄露内部细节。"""
    logger.exception("未处理异常：%s", type(exc).__name__)
    return JSONResponse(
        status_code=500,
        content={"detail": "服务内部错误，请稍后重试或联系管理员"},
    )


@app.get("/api/health")
def health() -> dict[str, object]:
    """健康检查：确认服务已经监听、示例数据已经就绪。"""
    return {"ok": True, "app": settings.app_name, "modules": len(store.module_names())}


@app.get("/api/overview")
def overview() -> dict[str, object]:
    """运营概览：把各业务模块的待处理量汇总成看板卡片。"""
    return store.overview()
