from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routers import auth, users, clients, domains, subdomains, services, scans, vulnerabilities, audit
from .bootstrap import ensure_admin_user
from .migrations import run_migrations

app = FastAPI(title="SentinelScope API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # restringir en producción al dominio del frontend
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(clients.router)
app.include_router(domains.router)
app.include_router(domains.router_all)
app.include_router(subdomains.router)
app.include_router(services.router)
app.include_router(scans.router)
app.include_router(vulnerabilities.router)
app.include_router(audit.router)


@app.on_event("startup")
def on_startup():
    run_migrations()
    ensure_admin_user()


@app.get("/health")
def health():
    return {"status": "ok"}
