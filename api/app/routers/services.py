import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text

from ..deps import get_db, require_write_access_to_client, log_action, CurrentUser, get_current_user
from ..schemas import ServiceOut, VulnerabilityOut, VulnStatusUpdate
from ..tasks.scan_tasks import run_scan_vulnerabilities

router = APIRouter(prefix="/services", tags=["services"])


def _client_of_service(db: Session, service_id: uuid.UUID) -> uuid.UUID:
    row = db.execute(text("SELECT client_id FROM services WHERE id = :id"), {"id": service_id}).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Servicio no encontrado")
    return row[0]


@router.get("/{service_id}/detail", response_model=ServiceOut)
def service_detail(service_id: uuid.UUID, db: Session = Depends(get_db)):
    row = db.execute(
        text("""SELECT id, host_id, port, protocol, service_name, product, version, banner, status
                 FROM services WHERE id = :id"""), {"id": service_id}).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Servicio no encontrado")
    return dict(row._mapping)


@router.get("/{service_id}/vulnerabilities", response_model=list[VulnerabilityOut])
def service_vulnerabilities(service_id: uuid.UUID, db: Session = Depends(get_db)):
    rows = db.execute(
        text("""SELECT id, service_id, source, template_id, cve_id, title, severity,
                        cvss_score, reference_url, status
                 FROM vulnerabilities WHERE service_id = :id
                 ORDER BY CASE severity
                    WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3 ELSE 4 END"""), {"id": service_id}
    ).fetchall()
    return [dict(r._mapping) for r in rows]


@router.patch("/vulnerabilities/{vuln_id}")
def update_vuln_status(vuln_id: uuid.UUID, payload: VulnStatusUpdate, db: Session = Depends(get_db),
                        user: CurrentUser = Depends(get_current_user)):
    row = db.execute(text("SELECT client_id FROM vulnerabilities WHERE id = :id"), {"id": vuln_id}).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Hallazgo no encontrado")
    require_write_access_to_client(row[0], user, db)
    resolved = "now()" if payload.status in ("remediated", "false_positive", "accepted_risk") else "NULL"
    db.execute(
        text(f"UPDATE vulnerabilities SET status = :s, resolved_at = {resolved} WHERE id = :id"),
        {"s": payload.status, "id": vuln_id},
    )
    log_action(db, user, "update_status", "vulnerability", vuln_id, row[0], {"status": payload.status})
    return {"detail": "Estado actualizado"}


@router.post("/{service_id}/scan-vulnerabilities", status_code=202)
def scan_vulnerabilities(service_id: uuid.UUID, db: Session = Depends(get_db),
                          user: CurrentUser = Depends(get_current_user)):
    client_id = _client_of_service(db, service_id)
    require_write_access_to_client(client_id, user, db)
    job_id = uuid.uuid4()
    db.execute(
        text("""INSERT INTO scan_jobs (id, client_id, type, target_type, target_id, requested_by)
                 VALUES (:id, :c, 'scan_vulnerabilities', 'service', :t, :by)"""),
        {"id": job_id, "c": client_id, "t": service_id, "by": user.id},
    )
    db.execute(text("UPDATE services SET status = 'queued' WHERE id = :id"), {"id": service_id})
    db.commit()
    task = run_scan_vulnerabilities.delay(str(job_id), str(client_id), str(service_id))
    db.execute(text("UPDATE scan_jobs SET celery_task_id = :t WHERE id = :id"), {"t": task.id, "id": job_id})
    return {"scan_job_id": str(job_id), "celery_task_id": task.id}
