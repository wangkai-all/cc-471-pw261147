"""数据访问 API：查询 / 导出 / 下载 / 物化。

并发模型：
- 过期授权清扫在锁外执行（内部取写锁推进版本）
- 实际读操作整体处于读锁临界区；进入临界区后 expire_all 重读当前版本，
  临界区内不可能有写者插入，因此缓存写入的 auth_version 恒等于当前版本，
  从根本上杜绝“旧版本缓存残留”
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..database import get_session
from ..deps import current_user
from ..locks import GLOBAL_RW_LOCK
from ..models import Dataset, ExportJob, User
from ..schemas import ExportRequest, MaterializeRequest, QueryRequest
from ..services import auth_service, data_service
from ..services.audit import new_request_id

router = APIRouter(prefix="/api", tags=["data"])


def _prepare(db: Session, dataset_id: int) -> Dataset:
    """锁外清扫过期授权，然后返回最新数据集对象。"""
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if dataset is None:
        raise HTTPException(404, "dataset not found")
    auth_service.sweep_expired_grants(db, dataset)
    return dataset


def _http_error(exc: Exception) -> HTTPException:
    message = str(exc)
    if message[:3].isdigit():
        return HTTPException(int(message[:3]), message[4:].strip())
    return HTTPException(400, message)


@router.post("/datasets/{dataset_id}/query")
def query_dataset(dataset_id: int, body: QueryRequest, db: Session = Depends(get_session), user: User = Depends(current_user)):
    _prepare(db, dataset_id)
    request_id = new_request_id()
    try:
        with GLOBAL_RW_LOCK.read_lock():
            # 临界区内重读：写者必须等待本临界区结束，期间版本恒定
            db.expire_all()
            dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
            result = data_service.execute_query(
                db, user, dataset, request_id,
                filters=body.filters, use_cache=body.use_cache,
            )
    except data_service.DataServiceError as exc:
        raise _http_error(exc)
    result["request_id"] = request_id
    return result


@router.post("/datasets/{dataset_id}/exports")
def create_export(dataset_id: int, body: ExportRequest, db: Session = Depends(get_session), user: User = Depends(current_user)):
    _prepare(db, dataset_id)
    request_id = new_request_id()
    try:
        with GLOBAL_RW_LOCK.read_lock():
            db.expire_all()
            dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
            job = data_service.create_export(db, user, dataset, request_id, filters=body.filters)
    except data_service.DataServiceError as exc:
        raise _http_error(exc)
    return {
        "export_id": job.id,
        "dataset_id": dataset_id,
        "auth_version": job.auth_version,
        "status": job.status,
        "row_count": job.row_count,
        "columns": job.columns,
        "request_id": request_id,
    }


@router.get("/exports/{export_id}/download")
def download_export(export_id: int, db: Session = Depends(get_session), user: User = Depends(current_user)):
    job = db.query(ExportJob).filter(ExportJob.id == export_id).first()
    if job is None:
        raise HTTPException(404, "export not found")
    request_id = new_request_id()
    try:
        with GLOBAL_RW_LOCK.read_lock():
            filename, content = data_service.download_export(db, user, job, request_id)
    except data_service.DataServiceError as exc:
        raise _http_error(exc)
    return Response(
        content=content,
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/exports/{export_id}")
def get_export(export_id: int, db: Session = Depends(get_session), user: User = Depends(current_user)):
    job = db.query(ExportJob).filter(ExportJob.id == export_id).first()
    if job is None:
        raise HTTPException(404, "export not found")
    return {
        "export_id": job.id,
        "dataset_id": job.dataset_id,
        "auth_version": job.auth_version,
        "status": job.status,
        "row_count": job.row_count,
        "invalidated_at": job.invalidated_at.isoformat() if job.invalidated_at else None,
        "invalidate_reason": job.invalidate_reason,
        "created_at": job.created_at.isoformat(),
    }


@router.post("/datasets/{dataset_id}/materialize")
def materialize(dataset_id: int, body: MaterializeRequest, db: Session = Depends(get_session), user: User = Depends(current_user)):
    _prepare(db, dataset_id)
    request_id = new_request_id()
    try:
        with GLOBAL_RW_LOCK.read_lock():
            db.expire_all()
            dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
            mat = data_service.materialize(
                db, user, dataset, request_id,
                name=body.name, group_by=body.group_by, agg=body.agg,
            )
    except data_service.DataServiceError as exc:
        raise _http_error(exc)
    return {
        "name": mat.name,
        "auth_version": mat.auth_version,
        "status": mat.status,
        "result": mat.result,
        "request_id": request_id,
    }


@router.get("/datasets/{dataset_id}/materialized/{name}")
def get_materialized(dataset_id: int, name: str, db: Session = Depends(get_session), user: User = Depends(current_user)):
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if dataset is None:
        raise HTTPException(404, "dataset not found")
    request_id = new_request_id()
    try:
        with GLOBAL_RW_LOCK.read_lock():
            db.expire_all()
            dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
            mat = data_service.get_materialized(db, user, dataset, name, request_id)
    except data_service.DataServiceError as exc:
        raise _http_error(exc)
    return {
        "name": mat.name,
        "auth_version": mat.auth_version,
        "status": mat.status,
        "result": mat.result,
        "refreshed_at": mat.refreshed_at.isoformat() if mat.refreshed_at else None,
        "request_id": request_id,
    }
