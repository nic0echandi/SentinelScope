import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text

from ..database import SessionLocal
from ..security import verify_password, hash_password, create_access_token, create_refresh_token, decode_token
from ..schemas import LoginRequest, TokenResponse, ChangePasswordRequest
from ..deps import get_current_user, CurrentUser

router = APIRouter(prefix="/auth", tags=["auth"])


def _client_access_for(db: Session, user_id: str, role: str) -> list[str]:
    if role in ("admin", "viewer_all"):
        return []  # acceso global, no hace falta listar
    rows = db.execute(
        text("SELECT client_id FROM user_client_access WHERE user_id = :uid"),
        {"uid": user_id},
    ).fetchall()
    return [str(r[0]) for r in rows]


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    db = SessionLocal()
    try:
        row = db.execute(
            text("SELECT id, password_hash, role, active, must_change_password FROM users WHERE email = :email"),
            {"email": payload.email},
        ).fetchone()
        if not row or not row.active or not verify_password(payload.password, row.password_hash):
            # Intento fallido: se registra sin user_id (no sabemos si el
            # email existe) pero con el email en metadata, para poder
            # detectar patrones de fuerza bruta desde el panel de auditoría.
            db.execute(
                text("""INSERT INTO audit_log (action, entity_type, metadata)
                         VALUES ('login_failed', 'user', :meta)"""),
                {"meta": json.dumps({"email": payload.email})},
            )
            db.commit()
            raise HTTPException(status_code=401, detail="Credenciales inválidas")

        client_ids = _client_access_for(db, str(row.id), row.role)
        access = create_access_token(str(row.id), row.role, client_ids)
        refresh = create_refresh_token(str(row.id))
        db.execute(text("UPDATE users SET last_login_at = now() WHERE id = :id"), {"id": row.id})
        db.execute(
            text("""INSERT INTO audit_log (user_id, action, entity_type, entity_id)
                     VALUES (:uid, 'login', 'user', :uid)"""),
            {"uid": row.id},
        )
        db.commit()
        return TokenResponse(access_token=access, refresh_token=refresh,
                              must_change_password=row.must_change_password)
    finally:
        db.close()


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(refresh_token: str):
    try:
        payload = decode_token(refresh_token)
    except ValueError:
        raise HTTPException(status_code=401, detail="Refresh token inválido")
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Tipo de token incorrecto")

    db = SessionLocal()
    try:
        row = db.execute(
            text("SELECT id, role, active, must_change_password FROM users WHERE id = :id"),
            {"id": payload["sub"]},
        ).fetchone()
        if not row or not row.active:
            raise HTTPException(status_code=401, detail="Usuario inactivo")
        client_ids = _client_access_for(db, str(row.id), row.role)
        access = create_access_token(str(row.id), row.role, client_ids)
        new_refresh = create_refresh_token(str(row.id))
        return TokenResponse(access_token=access, refresh_token=new_refresh,
                              must_change_password=row.must_change_password)
    finally:
        db.close()


@router.post("/change-password")
def change_password(payload: ChangePasswordRequest, user: CurrentUser = Depends(get_current_user)):
    db = SessionLocal()
    try:
        row = db.execute(text("SELECT password_hash FROM users WHERE id = :id"), {"id": user.id}).fetchone()
        if not row or not verify_password(payload.current_password, row.password_hash):
            raise HTTPException(status_code=400, detail="Contraseña actual incorrecta")
        new_hash = hash_password(payload.new_password)
        db.execute(
            text("UPDATE users SET password_hash = :h, must_change_password = FALSE WHERE id = :id"),
            {"h": new_hash, "id": user.id},
        )
        db.execute(
            text("""INSERT INTO audit_log (user_id, action, entity_type, entity_id)
                     VALUES (:uid, 'change_password', 'user', :uid)"""),
            {"uid": user.id},
        )
        db.commit()
        return {"detail": "Contraseña actualizada correctamente"}
    finally:
        db.close()
