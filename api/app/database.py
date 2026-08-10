from contextlib import contextmanager
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session

from .config import settings

engine = create_engine(settings.database_url, pool_pre_ping=True, pool_size=10, max_overflow=20)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_raw_session() -> Session:
    return SessionLocal()


def apply_rls_context(db: Session, role: str, client_ids: list[str]) -> None:
    """
    Setea las variables de sesión que las políticas RLS de Postgres usan
    para filtrar filas por cliente. Se ejecuta al inicio de cada request
    autenticado, ANTES de correr cualquier query de negocio.

    Usamos set_config() (función normal de Postgres) en vez de la sentencia
    SET, por dos motivos:
      1. SET no admite parámetros bindeados, solo literales.
      2. "current_role" es una palabra reservada en Postgres; como
         sentencia SET literal rompe el parser, pero como argumento de
         texto de una función no hay conflicto.
    """
    ids_csv = ",".join(client_ids) if client_ids else ""
    db.execute(text("SELECT set_config('app.current_role', :role, false)"), {"role": role})
    db.execute(text("SELECT set_config('app.current_client_ids', :ids, false)"), {"ids": ids_csv})


@contextmanager
def db_session():
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
