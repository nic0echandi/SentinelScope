"""
Tareas Celery que orquestan el pipeline de escaneo. Corren en los
contenedores 'worker' (que tienen todas las herramientas instaladas,
ver worker/Dockerfile). Escriben resultados directamente en Postgres.

El worker opera con rol 'admin' a nivel de RLS (bypass total) porque es
un proceso de backend de confianza, no una sesión de usuario; el control
de acceso ya se validó en la API antes de encolar el job.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed

from sqlalchemy import text

from ..celery_app import celery_app
from ..database import SessionLocal, apply_rls_context
from ..config import settings
from ..tools import recon, portscan, vulnscan


def _admin_session():
    db = SessionLocal()
    apply_rls_context(db, "admin", [])
    return db


def _mark_job(db, job_id: str, status: str, error: str | None = None):
    if status == "running":
        db.execute(text("UPDATE scan_jobs SET status = :s, started_at = now() WHERE id = :id"),
                   {"s": status, "id": job_id})
    else:
        db.execute(
            text("UPDATE scan_jobs SET status = :s, finished_at = now(), error_message = :e WHERE id = :id"),
            {"s": status, "e": error, "id": job_id})
    db.commit()


def _record_task(db, job_id: str, worker_type: str, target: str, status: str, error: str | None = None):
    db.execute(
        text("""INSERT INTO scan_job_tasks (scan_job_id, worker_type, target, status, started_at, finished_at, error_message)
                 VALUES (:job, :wt, :tgt, :st, now(), CASE WHEN :st != 'running' THEN now() ELSE NULL END, :err)"""),
        {"job": job_id, "wt": worker_type, "tgt": target, "st": status, "err": error},
    )
    db.commit()


# ---------------------------------------------------------------------
# Recon de subdominios: lógica compartida entre "scan domain" (standalone)
# y la primera etapa de "full scan". Deliberadamente NO marca el scan_job
# como completado -- eso lo decide quien la invoca, según si hay más
# etapas por correr o no.
# ---------------------------------------------------------------------
def _run_domain_recon(db, job_id: str, client_id: str, domain_id: str) -> None:
    row = db.execute(text("SELECT name FROM domains WHERE id = :id"), {"id": domain_id}).fetchone()
    domain_name = row[0]

    resolved = recon.full_passive_and_active_recon(domain_name)
    _record_task(db, job_id, "recon", domain_name, "completed")

    for sub_name, ips in resolved.items():
        sub_row = db.execute(
            text("SELECT id FROM subdomains WHERE domain_id = :d AND name = :n"),
            {"d": domain_id, "n": sub_name}
        ).fetchone()
        if sub_row:
            sub_id = sub_row[0]
            db.execute(text("UPDATE subdomains SET last_scan_at = now(), status = 'scanned' WHERE id = :id"),
                       {"id": sub_id})
        else:
            sub_id = db.execute(
                text("""INSERT INTO subdomains (domain_id, client_id, name, discovery_source, status, last_scan_at)
                         VALUES (:d, :c, :n, 'recon-pipeline', 'scanned', now()) RETURNING id"""),
                {"d": domain_id, "c": client_id, "n": sub_name}
            ).fetchone()[0]

        for ip in ips:
            db.execute(
                text("""INSERT INTO hosts (subdomain_id, client_id, ip_address, last_seen)
                         VALUES (:sd, :c, :ip, now())
                         ON CONFLICT (subdomain_id, ip_address) DO UPDATE SET last_seen = now()"""),
                {"sd": sub_id, "c": client_id, "ip": ip}
            )
        db.commit()

    db.execute(text("UPDATE domains SET status = 'scanned', last_scan_at = now() WHERE id = :id"),
               {"id": domain_id})
    db.commit()


# ---------------------------------------------------------------------
# scan domain (standalone): recon pasivo + activo de subdominios
# ---------------------------------------------------------------------
@celery_app.task(name="scan_domain")
def run_scan_domain(job_id: str, client_id: str, domain_id: str):
    db = _admin_session()
    try:
        _mark_job(db, job_id, "running")
        _run_domain_recon(db, job_id, client_id, domain_id)
        _mark_job(db, job_id, "completed")
    except Exception as e:
        db.execute(text("UPDATE domains SET status = 'error' WHERE id = :id"), {"id": domain_id})
        db.commit()
        _mark_job(db, job_id, "failed", str(e))
        raise
    finally:
        db.close()


# ---------------------------------------------------------------------
# scan services (standalone, un subdominio): naabu + nmap por cada host
# ---------------------------------------------------------------------
def _run_services_for_subdomain(db, job_id: str, client_id: str, subdomain_id: str) -> None:
    hosts = db.execute(text("SELECT id, ip_address FROM hosts WHERE subdomain_id = :sd"),
                        {"sd": subdomain_id}).fetchall()

    for host_id, ip in hosts:
        ip_str = str(ip)
        services = portscan.discover_services_for_host(ip_str)
        _record_task(db, job_id, "service", ip_str, "completed")
        for svc in services:
            db.execute(
                text("""INSERT INTO services (host_id, client_id, port, protocol, service_name,
                                                 product, version, banner, cpe, last_scan_at, status)
                         VALUES (:h, :c, :port, :proto, :sname, :prod, :ver, :banner, :cpe, now(), 'scanned')
                         ON CONFLICT (host_id, port, protocol) DO UPDATE SET
                            service_name = :sname, product = :prod, version = :ver,
                            banner = :banner, cpe = :cpe, last_scan_at = now(), status = 'scanned'"""),
                {"h": host_id, "c": client_id, "port": svc["port"], "proto": svc["protocol"],
                 "sname": svc["service_name"], "prod": svc["product"], "ver": svc["version"],
                 "banner": svc["banner"], "cpe": svc["cpe"]}
            )
        db.commit()

    db.execute(text("UPDATE subdomains SET status = 'scanned', last_scan_at = now() WHERE id = :id"),
               {"id": subdomain_id})
    db.commit()


@celery_app.task(name="scan_services")
def run_scan_services(job_id: str, client_id: str, subdomain_id: str):
    db = _admin_session()
    try:
        _mark_job(db, job_id, "running")
        _run_services_for_subdomain(db, job_id, client_id, subdomain_id)
        _mark_job(db, job_id, "completed")
    except Exception as e:
        db.execute(text("UPDATE subdomains SET status = 'error' WHERE id = :id"), {"id": subdomain_id})
        db.commit()
        _mark_job(db, job_id, "failed", str(e))
        raise
    finally:
        db.close()


# ---------------------------------------------------------------------
# scan vulnerabilities (standalone, un servicio): nuclei + nmap NSE + searchsploit
# ---------------------------------------------------------------------
def _run_vulns_for_service(db, job_id: str, client_id: str, service_id: str) -> None:
    row = db.execute(
        text("""SELECT s.port, s.service_name, s.product, s.version, h.ip_address
                 FROM services s JOIN hosts h ON h.id = s.host_id WHERE s.id = :id"""),
        {"id": service_id}
    ).fetchone()
    port, service_name, product, version, ip = row
    is_http = (service_name or "").lower() in ("http", "https", "http-alt", "http-proxy")

    findings = vulnscan.scan_service_vulnerabilities(
        str(ip), port, service_name, product, version, is_http=is_http
    )
    _record_task(db, job_id, "vuln", f"{ip}:{port}", "completed")

    for f in findings:
        db.execute(
            text("""INSERT INTO vulnerabilities
                        (service_id, client_id, source, template_id, cve_id, title,
                         description, severity, cvss_score, reference_url)
                     VALUES (:sid, :cid, :src, :tpl, :cve, :title, :desc, :sev, :cvss, :ref)
                     ON CONFLICT (service_id, source, template_id, cve_id) DO NOTHING"""),
            {"sid": service_id, "cid": client_id, "src": f["source"], "tpl": f.get("template_id"),
             "cve": f.get("cve_id"), "title": f["title"], "desc": f.get("description"),
             "sev": f["severity"], "cvss": f.get("cvss_score"), "ref": f.get("reference_url")}
        )
    db.execute(text("UPDATE services SET status = 'scanned', last_scan_at = now() WHERE id = :id"),
               {"id": service_id})
    db.commit()


@celery_app.task(name="scan_vulnerabilities")
def run_scan_vulnerabilities(job_id: str, client_id: str, service_id: str):
    db = _admin_session()
    try:
        _mark_job(db, job_id, "running")
        _run_vulns_for_service(db, job_id, client_id, service_id)
        _mark_job(db, job_id, "completed")
    except Exception as e:
        db.execute(text("UPDATE services SET status = 'error' WHERE id = :id"), {"id": service_id})
        db.commit()
        _mark_job(db, job_id, "failed", str(e))
        raise
    finally:
        db.close()


# ---------------------------------------------------------------------
# full scan: subdominios -> servicios -> vulnerabilidades, en ese orden,
# con concurrencia acotada por cliente (settings.max_concurrent_targets_per_job).
# El job del full-scan permanece "running" hasta que las TRES etapas
# terminan -- cada etapa queda registrada en scan_job_tasks (visible en
# el dashboard al expandir el trabajo) para que el progreso sea visible
# en tiempo real, no solo el resultado final.
# ---------------------------------------------------------------------
@celery_app.task(name="full_scan")
def run_full_scan(job_id: str, client_id: str, domain_id: str):
    db = _admin_session()
    try:
        _mark_job(db, job_id, "running")

        # 1) Recon de subdominios (no marca el job como completo: quedan
        #    dos etapas más por correr)
        _run_domain_recon(db, job_id, client_id, domain_id)

        subdomains = db.execute(text("SELECT id FROM subdomains WHERE domain_id = :d"),
                                 {"d": domain_id}).fetchall()

        # 2) Descubrimiento de servicios por subdominio, en paralelo acotado
        with ThreadPoolExecutor(max_workers=settings.max_concurrent_targets_per_job) as pool:
            futures = {
                pool.submit(_service_scan_sync, job_id, client_id, str(sub_id)): sub_id
                for (sub_id,) in subdomains
            }
            for fut in as_completed(futures):
                fut.result()  # propaga excepciones si las hubo

        # 3) Vuln-scan por cada servicio descubierto, en paralelo acotado
        services = db.execute(
            text("""SELECT s.id FROM services s
                     JOIN hosts h ON h.id = s.host_id
                     JOIN subdomains sd ON sd.id = h.subdomain_id
                     WHERE sd.domain_id = :d"""), {"d": domain_id}
        ).fetchall()

        with ThreadPoolExecutor(max_workers=settings.max_concurrent_targets_per_job) as pool:
            futures = {
                pool.submit(_vuln_scan_sync, job_id, client_id, str(svc_id)): svc_id
                for (svc_id,) in services
            }
            for fut in as_completed(futures):
                fut.result()

        _mark_job(db, job_id, "completed")
    except Exception as e:
        _mark_job(db, job_id, "failed", str(e))
        raise
    finally:
        db.close()


def _service_scan_sync(job_id: str, client_id: str, subdomain_id: str):
    # Corre en su propio thread con su propia sesión de DB (SQLAlchemy
    # Session no es thread-safe para compartir entre threads concurrentes).
    db = _admin_session()
    try:
        _run_services_for_subdomain(db, job_id, client_id, subdomain_id)
    except Exception:
        db.execute(text("UPDATE subdomains SET status = 'error' WHERE id = :id"), {"id": subdomain_id})
        db.commit()
        raise
    finally:
        db.close()


def _vuln_scan_sync(job_id: str, client_id: str, service_id: str):
    db = _admin_session()
    try:
        _run_vulns_for_service(db, job_id, client_id, service_id)
    except Exception:
        db.execute(text("UPDATE services SET status = 'error' WHERE id = :id"), {"id": service_id})
        db.commit()
        raise
    finally:
        db.close()
