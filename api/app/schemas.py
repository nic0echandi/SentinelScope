import uuid
import datetime as dt
from typing import Optional, List
from pydantic import BaseModel, Field

# NOTA: se usa "str" en vez de "EmailStr" para los campos de email.
# EmailStr (vía la librería email-validator) rechaza dominios de un solo
# label sin TLD como "localhost" (ej: admin@localhost), lo cual es un caso
# de uso válido para una herramienta interna. La unicidad del email ya
# está garantizada por la constraint UNIQUE en la tabla users.


# ---------- Auth ----------
class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    must_change_password: bool


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=10)


# ---------- Users ----------
class UserCreate(BaseModel):
    email: str
    full_name: str
    role: str  # admin | client_admin | viewer_all | viewer_scoped
    temporary_password: str = Field(min_length=10)
    client_access: List[dict] = []  # [{"client_id": "...", "access_level": "admin|viewer"}]


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    role: str
    active: bool
    created_at: dt.datetime

    class Config:
        from_attributes = True


# ---------- Clients ----------
class ClientCreate(BaseModel):
    name: str
    description: Optional[str] = None


class ClientOut(BaseModel):
    id: uuid.UUID
    name: str
    description: Optional[str]
    active: bool

    class Config:
        from_attributes = True


# ---------- Domains ----------
class DomainCreate(BaseModel):
    name: str
    authorization_reference: Optional[str] = None


class DomainOut(BaseModel):
    id: uuid.UUID
    client_id: uuid.UUID
    name: str
    status: str
    last_scan_at: Optional[dt.datetime]

    class Config:
        from_attributes = True


# ---------- Subdomains ----------
class SubdomainCreate(BaseModel):
    name: str


class SubdomainOut(BaseModel):
    id: uuid.UUID
    domain_id: uuid.UUID
    name: str
    discovery_source: Optional[str]
    status: str
    last_scan_at: Optional[dt.datetime]

    class Config:
        from_attributes = True


# ---------- Services ----------
class ServiceOut(BaseModel):
    id: uuid.UUID
    host_id: uuid.UUID
    port: int
    protocol: str
    service_name: Optional[str]
    product: Optional[str]
    version: Optional[str]
    banner: Optional[str]
    status: str

    class Config:
        from_attributes = True


# ---------- Vulnerabilities ----------
class VulnerabilityOut(BaseModel):
    id: uuid.UUID
    service_id: uuid.UUID
    source: str
    template_id: Optional[str]
    cve_id: Optional[str]
    title: str
    severity: str
    cvss_score: Optional[float]
    reference_url: Optional[str]
    status: str

    class Config:
        from_attributes = True


class VulnStatusUpdate(BaseModel):
    status: str  # open | false_positive | remediated | accepted_risk


# ---------- Scan jobs ----------
class ScanJobOut(BaseModel):
    id: uuid.UUID
    client_id: uuid.UUID
    type: str
    target_type: str
    target_id: uuid.UUID
    status: str
    started_at: Optional[dt.datetime]
    finished_at: Optional[dt.datetime]

    class Config:
        from_attributes = True


class DashboardSummary(BaseModel):
    domains: int
    subdomains: int
    hosts: int
    services: int
    vulns_by_severity: dict
    open_vulns: int
