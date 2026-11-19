from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .database import Base, engine
from .routers import admin, console, data
from .services.audit import new_request_id
from .services.auth_service import AuthServiceError
from .services.data_service import DataServiceError

# 建表（演示规模；生产环境使用迁移工具）
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="多租户数据集服务",
    description="行级租户隔离 / 列级敏感字段权限 / 临时授权与撤销 / 版本化缓存失效 / 审计追溯",
    version="1.0.0",
)

app.include_router(admin.router)
app.include_router(data.router)
app.include_router(console.router)


@app.exception_handler(AuthServiceError)
def auth_service_error_handler(request: Request, exc: AuthServiceError):
    return JSONResponse(status_code=400, content={"detail": str(exc), "request_id": new_request_id()})


@app.exception_handler(DataServiceError)
def data_service_error_handler(request: Request, exc: DataServiceError):
    message = str(exc)
    status = int(message[:3]) if message[:3].isdigit() else 400
    return JSONResponse(
        status_code=status,
        content={"detail": message[4:].strip() if len(message) > 4 else message, "request_id": new_request_id()},
    )


@app.get("/health", tags=["system"])
def health():
    return {"status": "ok"}
