import uuid
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from ..deps import get_db, require_roles

router = APIRouter(prefix="/audit-log", tags=["audit"])


@router.get("")
def list_audit_log(
    client_id: uuid.UUID | None = None,
    action: str | None = None,
    entity_type: str | None = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    # Solo admin/client_admin pueden ver el log de actividad (viewers no,
    # para no exponer de más a un rol de solo-lectura sin necesidad real).
    _user=Depends(require_roles("admin", "client_admin")),
):
    query = """
        SELECT al.id, al.action, al.entity_type, al.entity_id, al.client_id,
               al.metadata, al.created_at,
               u.email AS user_email, u.full_name AS user_full_name,
               c.name AS client_name
        FROM audit_log al
        LEFT JOIN users u ON u.id = al.user_id
        LEFT JOIN clients c ON c.id = al.client_id
        WHERE 1=1
    """
    params: dict = {}
    if client_id:
        query += " AND al.client_id = :client_id"
        params["client_id"] = client_id
    if action:
        query += " AND al.action = :action"
        params["action"] = action
    if entity_type:
        query += " AND al.entity_type = :entity_type"
        params["entity_type"] = entity_type
    query += " ORDER BY al.created_at DESC LIMIT :limit"
    params["limit"] = min(max(limit, 1), 500)

    rows = db.execute(text(query), params).fetchall()
    return [dict(r._mapping) for r in rows]
