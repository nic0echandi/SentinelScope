import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text

from ..deps import get_db, require_write_access_to_client, log_action, CurrentUser, get_current_user
from ..schemas import SubdomainCreate, SubdomainOut
from ..tasks.scan_tasks import run_scan_services

router = APIRouter(prefix="/domains/{domain_id}/subdomains", tags=["subdomains"])


def _client_of_domain(db: Session, domain_id: uuid.UUID) -> uuid.UUID:
    row = db.execute(text("SELECT client_id FROM domains WHERE id = :id"), {"id": domain_id}).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Dominio no encontrado")
    return row[0]


@router.get("")
def list_subdomains(domain_id: uuid.UUID, db: Session = Depends(get_db)):
    # Trae, en una sola query (nada de N+1 por subdominio), el estado del
    # subdominio + los puertos abiertos detectados + el conteo de
    # vulnerabilidades abiertas por severidad de todos sus servicios --
    # así la fila de cada subdominio puede mostrar esto sin que el
    # frontend tenga que pedir el detalle de cada uno por separado.
    rows = db.execute(
        text("""
            SELECT sd.id, sd.domain_id, sd.name, sd.discovery_source, sd.status, sd.last_scan_at,
                   COALESCE(
                       array_agg(DISTINCT s.port) FILTER (WHERE s.id IS NOT NULL),
                       '{}'
                   ) AS ports,
                   COUNT(*) FILTER (WHERE v.severity = 'critical' AND v.status = 'open') AS critical,
                   COUNT(*) FILTER (WHERE v.severity = 'high' AND v.status = 'open') AS high,
                   COUNT(*) FILTER (WHERE v.severity = 'medium' AND v.status = 'open') AS medium,
                   COUNT(*) FILTER (WHERE v.severity = 'low' AND v.status = 'open') AS low,
                   COUNT(*) FILTER (WHERE v.severity = 'info' AND v.status = 'open') AS info
            FROM subdomains sd
            LEFT JOIN hosts h ON h.subdomain_id = sd.id
            LEFT JOIN services s ON s.host_id = h.id
            LEFT JOIN vulnerabilities v ON v.service_id = s.id
            WHERE sd.domain_id = :d
            GROUP BY sd.id
            ORDER BY sd.name
        """), {"d": domain_id}
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r._mapping)
        d["ports"] = sorted(p for p in (d["ports"] or []) if p is not None)
        result.append(d)
    return result


@router.post("", response_model=SubdomainOut, status_code=201)
def create_subdomain_manual(domain_id: uuid.UUID, payload: SubdomainCreate, db: Session = Depends(get_db),
                             user: CurrentUser = Depends(get_current_user)):
    client_id = _client_of_domain(db, domain_id)
    require_write_access_to_client(client_id, user, db)
    new_id = uuid.uuid4()
    db.execute(
        text("""INSERT INTO subdomains (id, domain_id, client_id, name, discovery_source)
                 VALUES (:id, :d, :c, :n, 'manual')"""),
        {"id": new_id, "d": domain_id, "c": client_id, "n": payload.name},
    )
    log_action(db, user, "create", "subdomain", new_id, client_id)
    row = db.execute(
        text("""SELECT id, domain_id, name, discovery_source, status, last_scan_at
                 FROM subdomains WHERE id = :id"""), {"id": new_id}).fetchone()
    return dict(row._mapping)


@router.delete("/{subdomain_id}", status_code=204)
def delete_subdomain(domain_id: uuid.UUID, subdomain_id: uuid.UUID, db: Session = Depends(get_db),
                      user: CurrentUser = Depends(get_current_user)):
    client_id = _client_of_domain(db, domain_id)
    require_write_access_to_client(client_id, user, db)
    db.execute(text("DELETE FROM subdomains WHERE id = :id AND domain_id = :d"),
               {"id": subdomain_id, "d": domain_id})
    log_action(db, user, "delete", "subdomain", subdomain_id, client_id)


@router.get("/{subdomain_id}/services")
def list_services(domain_id: uuid.UUID, subdomain_id: uuid.UUID, db: Session = Depends(get_db)):
    rows = db.execute(
        text("""SELECT s.id, s.host_id, s.port, s.protocol, s.service_name, s.product, s.version,
                        s.banner, s.status,
                        COUNT(*) FILTER (WHERE v.severity = 'critical' AND v.status = 'open') AS critical,
                        COUNT(*) FILTER (WHERE v.severity = 'high' AND v.status = 'open') AS high,
                        COUNT(*) FILTER (WHERE v.severity = 'medium' AND v.status = 'open') AS medium,
                        COUNT(*) FILTER (WHERE v.severity = 'low' AND v.status = 'open') AS low,
                        COUNT(*) FILTER (WHERE v.severity = 'info' AND v.status = 'open') AS info
                 FROM services s
                 JOIN hosts h ON h.id = s.host_id
                 LEFT JOIN vulnerabilities v ON v.service_id = s.id
                 WHERE h.subdomain_id = :sd
                 GROUP BY s.id
                 ORDER BY s.port"""), {"sd": subdomain_id}
    ).fetchall()
    return [dict(r._mapping) for r in rows]


@router.post("/{subdomain_id}/scan-services", status_code=202)
def scan_services(domain_id: uuid.UUID, subdomain_id: uuid.UUID, db: Session = Depends(get_db),
                   user: CurrentUser = Depends(get_current_user)):
    client_id = _client_of_domain(db, domain_id)
    require_write_access_to_client(client_id, user, db)
    job_id = uuid.uuid4()
    db.execute(
        text("""INSERT INTO scan_jobs (id, client_id, type, target_type, target_id, requested_by)
                 VALUES (:id, :c, 'scan_services', 'subdomain', :t, :by)"""),
        {"id": job_id, "c": client_id, "t": subdomain_id, "by": user.id},
    )
    db.execute(text("UPDATE subdomains SET status = 'queued' WHERE id = :id"), {"id": subdomain_id})
    log_action(db, user, "trigger_scan_services", "subdomain", subdomain_id, client_id, {"scan_job_id": str(job_id)})
    db.commit()
    task = run_scan_services.delay(str(job_id), str(client_id), str(subdomain_id))
    db.execute(text("UPDATE scan_jobs SET celery_task_id = :t WHERE id = :id"), {"t": task.id, "id": job_id})
    return {"scan_job_id": str(job_id), "celery_task_id": task.id}
