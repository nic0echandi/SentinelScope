import uuid
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from ..deps import get_db

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.get("")
def list_vulnerabilities(client_id: uuid.UUID | None = None, severity: str | None = None,
                          status: str | None = None, db: Session = Depends(get_db)):
    query = """SELECT v.id, v.title, v.severity, v.status, v.cve_id, v.source,
                      v.discovered_at, v.reference_url,
                      c.id AS client_id, c.name AS client_name,
                      dm.name AS domain_name, sd.name AS subdomain_name,
                      s.id AS service_id, s.port, s.protocol, s.product, s.version
               FROM vulnerabilities v
               JOIN services s ON s.id = v.service_id
               JOIN hosts h ON h.id = s.host_id
               JOIN subdomains sd ON sd.id = h.subdomain_id
               JOIN domains dm ON dm.id = sd.domain_id
               JOIN clients c ON c.id = v.client_id
               WHERE 1=1"""
    params: dict = {}
    if client_id:
        query += " AND v.client_id = :client_id"
        params["client_id"] = client_id
    if severity:
        query += " AND v.severity = :severity"
        params["severity"] = severity
    if status:
        query += " AND v.status = :status"
        params["status"] = status
    query += """ ORDER BY CASE v.severity
                    WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3 ELSE 4 END, v.discovered_at DESC LIMIT 300"""
    rows = db.execute(text(query), params).fetchall()
    return [dict(r._mapping) for r in rows]
