import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text

from ..deps import get_db, require_roles, log_action, CurrentUser, get_current_user
from ..schemas import UserCreate, UserOut
from ..security import hash_password

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me")
def whoami(db: Session = Depends(get_db), user: CurrentUser = Depends(get_current_user)):
    row = db.execute(text("SELECT email, full_name, role FROM users WHERE id = :id"),
                      {"id": user.id}).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Usuario no encontrado; volvé a iniciar sesión")
    return dict(row._mapping)


@router.get("", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), user: CurrentUser = Depends(require_roles("admin"))):
    rows = db.execute(text("SELECT id, email, full_name, role, active, created_at FROM users ORDER BY created_at")).fetchall()
    return [dict(r._mapping) for r in rows]


@router.post("", response_model=UserOut, status_code=201)
def create_user(payload: UserCreate, db: Session = Depends(get_db),
                 user: CurrentUser = Depends(require_roles("admin"))):
    existing = db.execute(text("SELECT id FROM users WHERE email = :e"), {"e": payload.email}).fetchone()
    if existing:
        raise HTTPException(status_code=409, detail="El email ya está registrado")

    new_id = uuid.uuid4()
    db.execute(
        text("""INSERT INTO users (id, email, password_hash, full_name, role, must_change_password)
                 VALUES (:id, :email, :ph, :fn, :role, TRUE)"""),
        {"id": new_id, "email": payload.email, "ph": hash_password(payload.temporary_password),
         "fn": payload.full_name, "role": payload.role},
    )
    if payload.role in ("client_admin", "viewer_scoped"):
        for access in payload.client_access:
            db.execute(
                text("""INSERT INTO user_client_access (user_id, client_id, access_level)
                         VALUES (:uid, :cid, :lvl)"""),
                {"uid": new_id, "cid": access["client_id"], "lvl": access["access_level"]},
            )
    log_action(db, user, "create", "user", new_id)
    row = db.execute(text("SELECT id, email, full_name, role, active, created_at FROM users WHERE id = :id"),
                      {"id": new_id}).fetchone()
    return dict(row._mapping)


@router.patch("/{user_id}")
def update_user(user_id: uuid.UUID, active: bool | None = None, role: str | None = None,
                 db: Session = Depends(get_db), user: CurrentUser = Depends(require_roles("admin"))):
    if active is not None:
        db.execute(text("UPDATE users SET active = :a WHERE id = :id"), {"a": active, "id": user_id})
    if role is not None:
        db.execute(text("UPDATE users SET role = :r WHERE id = :id"), {"r": role, "id": user_id})
    log_action(db, user, "update", "user", user_id)
    return {"detail": "Usuario actualizado"}


@router.put("/{user_id}/client-access")
def set_client_access(user_id: uuid.UUID, client_id: uuid.UUID, access_level: str,
                       db: Session = Depends(get_db), user: CurrentUser = Depends(require_roles("admin"))):
    db.execute(
        text("""INSERT INTO user_client_access (user_id, client_id, access_level)
                 VALUES (:uid, :cid, :lvl)
                 ON CONFLICT (user_id, client_id) DO UPDATE SET access_level = :lvl"""),
        {"uid": user_id, "cid": client_id, "lvl": access_level},
    )
    log_action(db, user, "grant_access", "user_client_access", user_id, client_id)
    return {"detail": "Acceso actualizado"}
