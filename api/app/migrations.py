"""
Migraciones idempotentes, aplicadas automáticamente al arrancar la API
(ver main.py). Cada migración corre UNA sola vez (se trackea en la tabla
schema_migrations); esto evita tener que resetear la base de datos
(docker compose down -v) cada vez que el esquema cambia un poco.

Para agregar una migración nueva: sumar una tupla (id_único, sql) al
final de la lista MIGRATIONS. El id no debe reutilizarse ni editarse una
vez aplicado en algún ambiente.
"""
import logging
from sqlalchemy import text
from .database import AdminSessionLocal

logger = logging.getLogger("asm.migrations")

MIGRATIONS: list[tuple[str, str]] = [
    (
        "001_audit_log_rls",
        """
        ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

        -- Lectura: filtrada como el resto de las tablas (admin/viewer_all ven
        -- todo; el resto solo lo de sus clientes habilitados). Las filas con
        -- client_id NULL (acciones globales: login, gestión de usuarios) solo
        -- las ve un rol global.
        CREATE POLICY audit_log_select ON audit_log FOR SELECT
            USING (
                current_role_is_global()
                OR (client_id IS NOT NULL AND client_id = ANY (current_client_ids()))
            );

        -- Escritura: sin restricción -- cualquier usuario autenticado debe
        -- poder registrar sus propias acciones (ej: su propio login), incluso
        -- las que no están atadas a ningún cliente (client_id NULL). Si esto
        -- usara la misma policy que SELECT, un client_admin no podría
        -- insertar su propio evento de login (client_id NULL no matchea su
        -- lista de clientes) y rompería el login de cualquiera que no sea admin.
        CREATE POLICY audit_log_insert ON audit_log FOR INSERT
            WITH CHECK (true);
        """,
    ),
]


def run_migrations() -> None:
    # OJO: se usa AdminSessionLocal (rol con privilegios de superusuario/
    # dueño de las tablas) a propósito -- ALTER TABLE y CREATE POLICY
    # requieren esos permisos, que el rol restringido de la app
    # (sentinelscope_app, usado para todo lo demás) no tiene ni debe tener.
    db = AdminSessionLocal()
    try:
        db.execute(text("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                id TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        db.commit()

        for migration_id, sql in MIGRATIONS:
            already_applied = db.execute(
                text("SELECT 1 FROM schema_migrations WHERE id = :id"), {"id": migration_id}
            ).fetchone()
            if already_applied:
                continue
            try:
                db.execute(text(sql))
                db.execute(text("INSERT INTO schema_migrations (id) VALUES (:id)"), {"id": migration_id})
                db.commit()
                logger.info("Migración aplicada: %s", migration_id)
            except Exception:
                db.rollback()
                logger.exception("Falló la migración %s -- la API puede no arrancar correctamente.", migration_id)
                raise
    finally:
        db.close()
