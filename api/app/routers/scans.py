import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text

from ..deps import get_db
from ..schemas import ScanJobOut

router = APIRouter(prefix="/scan-jobs", tags=["scans"])


@router.get("/{job_id}", response_model=ScanJobOut)
def get_scan_job(job_id: uuid.UUID, db: Session = Depends(get_db)):
    row = db.execute(
        text("""SELECT id, client_id, type, target_type, target_id, status, started_at, finished_at
                 FROM scan_jobs WHERE id = :id"""), {"id": job_id}).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Job no encontrado")
    return dict(row._mapping)


@router.get("/{job_id}/tasks")
def get_scan_job_tasks(job_id: uuid.UUID, db: Session = Depends(get_db)):
    rows = db.execute(
        text("""SELECT worker_type, target, status, started_at, finished_at, error_message
                 FROM scan_job_tasks WHERE scan_job_id = :id ORDER BY started_at"""), {"id": job_id}
    ).fetchall()
    return [dict(r._mapping) for r in rows]


_JOBS_QUERY_BASE = """
    SELECT sj.id, sj.type, sj.target_type, sj.status, sj.started_at, sj.finished_at,
           sj.created_at, c.name AS client_name,
           COALESCE(d.name, sd.name, CONCAT(s.port, '/', s.protocol)) AS target_name,
           COALESCE(vc.critical, 0) AS critical, COALESCE(vc.high, 0) AS high,
           COALESCE(vc.medium, 0) AS medium, COALESCE(vc.low, 0) AS low, COALESCE(vc.info, 0) AS info
    FROM scan_jobs sj
    JOIN clients c ON c.id = sj.client_id
    LEFT JOIN domains d ON sj.target_type = 'domain' AND d.id = sj.target_id
    LEFT JOIN subdomains sd ON sj.target_type = 'subdomain' AND sd.id = sj.target_id
    LEFT JOIN services s ON sj.target_type = 'service' AND s.id = sj.target_id
    -- Conteo de hallazgos abiertos por severidad, según el alcance del
    -- target del job: si el job fue sobre un dominio, cuenta todos los
    -- hallazgos de todos sus subdominios/servicios; si fue sobre un
    -- subdominio o un servicio puntual, cuenta solo lo de ese alcance.
    -- No queda perfectamente atado a "lo que este job específico encontró"
    -- (eso requeriría una columna scan_job_id en vulnerabilities), pero da
    -- una respuesta correcta y útil a "¿hay vulnerabilidades acá, y de qué
    -- severidad?" sin necesitar otro cambio de esquema.
    LEFT JOIN LATERAL (
        SELECT
            count(*) FILTER (WHERE v.severity = 'critical') AS critical,
            count(*) FILTER (WHERE v.severity = 'high') AS high,
            count(*) FILTER (WHERE v.severity = 'medium') AS medium,
            count(*) FILTER (WHERE v.severity = 'low') AS low,
            count(*) FILTER (WHERE v.severity = 'info') AS info
        FROM vulnerabilities v
        JOIN services s2 ON s2.id = v.service_id
        JOIN hosts h2 ON h2.id = s2.host_id
        JOIN subdomains sd2 ON sd2.id = h2.subdomain_id
        WHERE v.status = 'open' AND (
            (sj.target_type = 'domain' AND sd2.domain_id = sj.target_id) OR
            (sj.target_type = 'subdomain' AND sd2.id = sj.target_id) OR
            (sj.target_type = 'service' AND s2.id = sj.target_id)
        )
    ) vc ON true
"""


@router.get("")
def list_scan_jobs(client_id: uuid.UUID | None = None, db: Session = Depends(get_db)):
    if client_id:
        query = _JOBS_QUERY_BASE + " WHERE sj.client_id = :c ORDER BY sj.created_at DESC LIMIT 50"
        rows = db.execute(text(query), {"c": client_id}).fetchall()
    else:
        query = _JOBS_QUERY_BASE + " ORDER BY sj.created_at DESC LIMIT 50"
        rows = db.execute(text(query)).fetchall()
    return [dict(r._mapping) for r in rows]
