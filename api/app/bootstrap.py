"""
Crea o actualiza el usuario admin inicial al arrancar la API, usando
ADMIN_EMAIL / ADMIN_PASSWORD desde variables de entorno. Es idempotente:
se puede correr en cada arranque sin duplicar ni romper nada.

Esto reemplaza el enfoque anterior de pegar un hash Argon2 a mano en
db/init.sql, que era propenso a errores de copy/paste (padding roto,
truncamientos, etc.).
"""
import logging
from sqlalchemy import text

from .database import SessionLocal
from .security import hash_password
from .config import settings

logger = logging.getLogger("asm.bootstrap")


def ensure_admin_user() -> None:
    if not settings.admin_email or not settings.admin_password:
        logger.warning(
            "ADMIN_EMAIL/ADMIN_PASSWORD no están seteados: se omite la "
            "creación automática del usuario admin. Definilos en .env "
            "o creá el usuario manualmente."
        )
        return

    db = SessionLocal()
    try:
        # Bootstrap corre con permisos administrativos, sin restricción RLS.
        # set_config() en vez de SET: "current_role" es palabra reservada
        # en Postgres y rompe el parser si se usa en una sentencia SET literal.
        db.execute(text("SELECT set_config('app.current_role', 'admin', false)"))
        db.execute(text("SELECT set_config('app.current_client_ids', '', false)"))

        row = db.execute(
            text("SELECT id FROM users WHERE email = :email"),
            {"email": settings.admin_email},
        ).fetchone()

        password_hash = hash_password(settings.admin_password)

        if row:
            db.execute(
                text("""UPDATE users SET password_hash = :ph, role = 'admin',
                                          active = TRUE
                         WHERE id = :id"""),
                {"ph": password_hash, "id": row.id},
            )
            logger.info("Usuario admin '%s' actualizado.", settings.admin_email)
        else:
            db.execute(
                text("""INSERT INTO users (email, password_hash, full_name, role, must_change_password)
                         VALUES (:email, :ph, 'Administrador', 'admin', TRUE)"""),
                {"email": settings.admin_email, "ph": password_hash},
            )
            logger.info("Usuario admin '%s' creado.", settings.admin_email)

        db.commit()
    except Exception:
        db.rollback()
        logger.exception("No se pudo crear/actualizar el usuario admin inicial.")
    finally:
        db.close()
