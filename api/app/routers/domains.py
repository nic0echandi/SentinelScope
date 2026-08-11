import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text

from ..deps import get_db, require_write_access_to_client, log_action, CurrentUser, get_current_user
from ..schemas import DomainCreate, DomainOut

router = APIRouter(prefix="/clients/{client_id}/domains", tags=["domains"])


@router.get("")
def list_domains(client_id: uuid.UUID, db: Session = Depends(get_db)):
    rows = db.execute(
        text("""SELECT d.id, d.client_id, d.name, d.status, d.last_scan_at, d.authorization_reference,
                        (SELECT count(*) FROM subdomains sd WHERE sd.domain_id = d.id) AS subdomain_count
                 FROM domains d WHERE d.client_id = :c ORDER BY d.name"""), {"c": client_id}
    ).fetchall()
    return [dict(r._mapping) for r in rows]


@router.post("", response_model=DomainOut, status_code=201)
def create_domain(client_id: uuid.UUID, payload: DomainCreate, db: Session = Depends(get_db),
                   user: CurrentUser = Depends(get_current_user)):
    require_write_access_to_client(client_id, user, db)
    new_id = uuid.uuid4()
    try:
        db.execute(
            text("""INSERT INTO domains (id, client_id, name, authorization_reference, created_by)
                     VALUES (:id, :c, :n, :ref, :by)"""),
            {"id": new_id, "c": client_id, "n": payload.name,
             "ref": payload.authorization_reference, "by": user.id},
        )
    except Exception:
        raise HTTPException(status_code=409, detail="El dominio ya existe para este cliente")
    log_action(db, user, "create", "domain", new_id, client_id)
    row = db.execute(text("SELECT id, client_id, name, status, last_scan_at FROM domains WHERE id = :id"),
                      {"id": new_id}).fetchone()
    return dict(row._mapping)


@router.delete("/{domain_id}", status_code=204)
def delete_domain(client_id: uuid.UUID, domain_id: uuid.UUID, db: Session = Depends(get_db),
                   user: CurrentUser = Depends(get_current_user)):
    require_write_access_to_client(client_id, user, db)
    db.execute(text("DELETE FROM domains WHERE id = :id AND client_id = :c"), {"id": domain_id, "c": client_id})
    log_action(db, user, "delete", "domain", domain_id, client_id)


# ---- Acciones de escaneo (encolan un job; la ejecución real la hace Celery) ----
from ..tasks.scan_tasks import run_scan_domain, run_full_scan  # noqa: E402


@router.post("/{domain_id}/scan", status_code=202)
def scan_domain(client_id: uuid.UUID, domain_id: uuid.UUID, db: Session = Depends(get_db),
                 user: CurrentUser = Depends(get_current_user)):
    require_write_access_to_client(client_id, user, db)
    job_id = uuid.uuid4()
    db.execute(
        text("""INSERT INTO scan_jobs (id, client_id, type, target_type, target_id, requested_by)
                 VALUES (:id, :c, 'scan_domain', 'domain', :t, :by)"""),
        {"id": job_id, "c": client_id, "t": domain_id, "by": user.id},
    )
    db.execute(text("UPDATE domains SET status = 'queued' WHERE id = :id"), {"id": domain_id})
    log_action(db, user, "trigger_scan_domain", "domain", domain_id, client_id, {"scan_job_id": str(job_id)})
    db.commit()
    task = run_scan_domain.delay(str(job_id), str(client_id), str(domain_id))
    db.execute(text("UPDATE scan_jobs SET celery_task_id = :t WHERE id = :id"), {"t": task.id, "id": job_id})
    return {"scan_job_id": str(job_id), "celery_task_id": task.id}


@router.post("/{domain_id}/full-scan", status_code=202)
def full_scan(client_id: uuid.UUID, domain_id: uuid.UUID, db: Session = Depends(get_db),
              user: CurrentUser = Depends(get_current_user)):
    require_write_access_to_client(client_id, user, db)
    job_id = uuid.uuid4()
    db.execute(
        text("""INSERT INTO scan_jobs (id, client_id, type, target_type, target_id, requested_by)
                 VALUES (:id, :c, 'full_scan', 'domain', :t, :by)"""),
        {"id": job_id, "c": client_id, "t": domain_id, "by": user.id},
    )
    db.execute(text("UPDATE domains SET status = 'queued' WHERE id = :id"), {"id": domain_id})
    log_action(db, user, "trigger_full_scan", "domain", domain_id, client_id, {"scan_job_id": str(job_id)})
    db.commit()
    task = run_full_scan.delay(str(job_id), str(client_id), str(domain_id))
    db.execute(text("UPDATE scan_jobs SET celery_task_id = :t WHERE id = :id"), {"t": task.id, "id": job_id})
    return {"scan_job_id": str(job_id), "celery_task_id": task.id}


# =======================================================================
# Router adicional sin client_id en el path: para la vista "Todos los
# clientes" del dashboard (RLS filtra automáticamente según el usuario).
# =======================================================================
router_all = APIRouter(prefix="/domains", tags=["domains"])


@router_all.get("")
def list_all_domains(db: Session = Depends(get_db)):
    rows = db.execute(
        text("""SELECT d.id, d.client_id, c.name AS client_name, d.name, d.status,
                        d.last_scan_at, d.authorization_reference,
                        (SELECT count(*) FROM subdomains sd WHERE sd.domain_id = d.id) AS subdomain_count
                 FROM domains d JOIN clients c ON c.id = d.client_id
                 ORDER BY c.name, d.name""")
    ).fetchall()
    return [dict(r._mapping) for r in rows]


@router_all.post("", status_code=201)
def create_domain_any_client(payload: dict, db: Session = Depends(get_db),
                              user: CurrentUser = Depends(get_current_user)):
    """
    Variante de creación de dominio que recibe el client_id en el body
    (para el modal "+ Nuevo dominio" con selector de cliente incluido).
    payload: {client_id, name, authorization_reference?}
    """
    client_id = payload.get("client_id")
    name = payload.get("name")
    if not client_id or not name:
        raise HTTPException(status_code=422, detail="client_id y name son requeridos")
    require_write_access_to_client(uuid.UUID(client_id), user, db)
    new_id = uuid.uuid4()
    try:
        db.execute(
            text("""INSERT INTO domains (id, client_id, name, authorization_reference, created_by)
                     VALUES (:id, :c, :n, :ref, :by)"""),
            {"id": new_id, "c": client_id, "n": name,
             "ref": payload.get("authorization_reference"), "by": user.id},
        )
    except Exception:
        raise HTTPException(status_code=409, detail="El dominio ya existe para este cliente")
    log_action(db, user, "create", "domain", new_id, client_id)
    return {"id": str(new_id)}
