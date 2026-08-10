import uuid
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from ..deps import get_db, require_roles, log_action, CurrentUser
from ..schemas import ClientCreate, ClientOut, DashboardSummary

router = APIRouter(prefix="/clients", tags=["clients"])


@router.get("", response_model=list[ClientOut])
def list_clients(db: Session = Depends(get_db)):
    # RLS ya filtra automáticamente según el usuario de la sesión (ver apply_rls_context)
    rows = db.execute(text("SELECT id, name, description, active FROM clients ORDER BY name")).fetchall()
    return [dict(r._mapping) for r in rows]


@router.post("", response_model=ClientOut, status_code=201)
def create_client(payload: ClientCreate, db: Session = Depends(get_db),
                   user: CurrentUser = Depends(require_roles("admin"))):
    new_id = uuid.uuid4()
    db.execute(text("INSERT INTO clients (id, name, description) VALUES (:id, :n, :d)"),
               {"id": new_id, "n": payload.name, "d": payload.description})
    log_action(db, user, "create", "client", new_id)
    row = db.execute(text("SELECT id, name, description, active FROM clients WHERE id = :id"),
                      {"id": new_id}).fetchone()
    return dict(row._mapping)


@router.get("/{client_id}/dashboard-summary", response_model=DashboardSummary)
def dashboard_summary(client_id: uuid.UUID, db: Session = Depends(get_db)):
    domains = db.execute(text("SELECT count(*) FROM domains WHERE client_id = :c"), {"c": client_id}).scalar()
    subdomains = db.execute(text("SELECT count(*) FROM subdomains WHERE client_id = :c"), {"c": client_id}).scalar()
    hosts = db.execute(text("SELECT count(*) FROM hosts WHERE client_id = :c"), {"c": client_id}).scalar()
    services = db.execute(text("SELECT count(*) FROM services WHERE client_id = :c"), {"c": client_id}).scalar()
    sev_rows = db.execute(
        text("""SELECT severity, count(*) FROM vulnerabilities
                 WHERE client_id = :c AND status = 'open' GROUP BY severity"""),
        {"c": client_id},
    ).fetchall()
    vulns_by_severity = {r[0]: r[1] for r in sev_rows}
    open_vulns = sum(vulns_by_severity.values())
    return DashboardSummary(domains=domains, subdomains=subdomains, hosts=hosts, services=services,
                             vulns_by_severity=vulns_by_severity, open_vulns=open_vulns)
