import uuid
import json
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from sqlalchemy import text

from .database import SessionLocal, apply_rls_context
from .security import decode_token
from . import models

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


class CurrentUser:
    def __init__(self, id: str, role: str, client_ids: list[str]):
        self.id = id
        self.role = role
        self.client_ids = client_ids  # vacío si admin/viewer_all (acceso global)


def get_current_user(token: str = Depends(oauth2_scheme)) -> CurrentUser:
    try:
        payload = decode_token(token)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido o expirado")
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Tipo de token incorrecto")
    return CurrentUser(id=payload["sub"], role=payload["role"], client_ids=payload.get("client_ids", []))


def get_db(user: CurrentUser = Depends(get_current_user)) -> Session:
    """
    Devuelve una sesión de DB con el contexto RLS ya aplicado según el
    usuario autenticado. Toda query hecha con esta sesión queda filtrada
    automáticamente por Postgres según las policies de db/init.sql.
    """
    db = SessionLocal()
    try:
        apply_rls_context(db, user.role, user.client_ids)
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def require_roles(*roles: str):
    def checker(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="No tiene permisos para esta acción")
        return user
    return checker


def require_write_access_to_client(client_id: uuid.UUID, user: CurrentUser, db: Session):
    """
    admin: acceso total.
    client_admin: solo si el cliente está en su client_ids (con access_level=admin,
    ya filtrado al generar el token).
    viewer_*: nunca tiene escritura.
    """
    if user.role == "admin":
        return
    if user.role == "client_admin" and str(client_id) in user.client_ids:
        return
    raise HTTPException(status_code=403, detail="No tiene permisos de escritura sobre este cliente")


def log_action(db: Session, user: CurrentUser, action: str, entity_type: str,
                entity_id=None, client_id=None, metadata=None):
    # psycopg2 no sabe adaptar un dict de Python directo a JSON -- hay que
    # serializarlo a texto y castear explícitamente a jsonb en el SQL,
    # si no tira "can't adapt type 'dict'".
    meta_json = json.dumps(metadata) if metadata is not None else None
    db.execute(
        text("""INSERT INTO audit_log (user_id, action, entity_type, entity_id, client_id, metadata)
                 VALUES (:uid, :action, :etype, :eid, :cid, CAST(:meta AS jsonb))"""),
        {"uid": user.id, "action": action, "etype": entity_type,
         "eid": str(entity_id) if entity_id else None,
         "cid": str(client_id) if client_id else None,
         "meta": meta_json},
    )
