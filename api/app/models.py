import uuid
from sqlalchemy import (
    Column, String, Boolean, DateTime, ForeignKey, Text, Integer,
    Numeric, SmallInteger, Enum, UniqueConstraint, func
)
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def uid():
    return uuid.uuid4()


class Client(Base):
    __tablename__ = "clients"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uid)
    name = Column(String, nullable=False, unique=True)
    description = Column(Text)
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uid)
    email = Column(String, nullable=False, unique=True)
    password_hash = Column(String, nullable=False)
    full_name = Column(String, nullable=False)
    role = Column(Enum("admin", "client_admin", "viewer_all", "viewer_scoped",
                        name="user_role", create_type=False), nullable=False)
    active = Column(Boolean, nullable=False, default=True)
    must_change_password = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login_at = Column(DateTime(timezone=True))


class UserClientAccess(Base):
    __tablename__ = "user_client_access"
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    client_id = Column(UUID(as_uuid=True), ForeignKey("clients.id", ondelete="CASCADE"), primary_key=True)
    access_level = Column(Enum("admin", "viewer", name="access_level", create_type=False), nullable=False)


class Domain(Base):
    __tablename__ = "domains"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uid)
    client_id = Column(UUID(as_uuid=True), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    authorization_reference = Column(Text)
    status = Column(Enum("never_scanned", "queued", "scanning", "scanned", "error",
                          name="scan_status", create_type=False), nullable=False, default="never_scanned")
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_scan_at = Column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint("client_id", "name"),)


class Subdomain(Base):
    __tablename__ = "subdomains"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uid)
    domain_id = Column(UUID(as_uuid=True), ForeignKey("domains.id", ondelete="CASCADE"), nullable=False)
    client_id = Column(UUID(as_uuid=True), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    discovery_source = Column(String)
    status = Column(Enum("never_scanned", "queued", "scanning", "scanned", "error",
                          name="scan_status", create_type=False), nullable=False, default="never_scanned")
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())
    last_scan_at = Column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint("domain_id", "name"),)


class Host(Base):
    __tablename__ = "hosts"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uid)
    subdomain_id = Column(UUID(as_uuid=True), ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=False)
    client_id = Column(UUID(as_uuid=True), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False)
    ip_address = Column(INET, nullable=False)
    ip_version = Column(SmallInteger, nullable=False, default=4)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    __table_args__ = (UniqueConstraint("subdomain_id", "ip_address"),)


class Service(Base):
    __tablename__ = "services"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uid)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    client_id = Column(UUID(as_uuid=True), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String, nullable=False, default="tcp")
    service_name = Column(String)
    product = Column(String)
    version = Column(String)
    banner = Column(Text)
    cpe = Column(String)
    status = Column(Enum("never_scanned", "queued", "scanning", "scanned", "error",
                          name="scan_status", create_type=False), nullable=False, default="never_scanned")
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())
    last_scan_at = Column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint("host_id", "port", "protocol"),)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uid)
    service_id = Column(UUID(as_uuid=True), ForeignKey("services.id", ondelete="CASCADE"), nullable=False)
    client_id = Column(UUID(as_uuid=True), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False)
    source = Column(String, nullable=False)
    template_id = Column(String)
    cve_id = Column(String)
    title = Column(String, nullable=False)
    description = Column(Text)
    severity = Column(Enum("critical", "high", "medium", "low", "info",
                            name="severity_level", create_type=False), nullable=False)
    cvss_score = Column(Numeric(3, 1))
    reference_url = Column(Text)
    raw_output_path = Column(Text)
    status = Column(Enum("open", "false_positive", "remediated", "accepted_risk",
                          name="finding_status", create_type=False), nullable=False, default="open")
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())
    resolved_at = Column(DateTime(timezone=True))


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uid)
    client_id = Column(UUID(as_uuid=True), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False)
    type = Column(Enum("scan_domain", "scan_services", "scan_vulnerabilities", "full_scan",
                        name="job_type", create_type=False), nullable=False)
    target_type = Column(String, nullable=False)
    target_id = Column(UUID(as_uuid=True), nullable=False)
    status = Column(Enum("pending", "running", "completed", "failed", "cancelled",
                          name="job_status", create_type=False), nullable=False, default="pending")
    requested_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    celery_task_id = Column(String)
    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))
    error_message = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ScanJobTask(Base):
    __tablename__ = "scan_job_tasks"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uid)
    scan_job_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    worker_type = Column(String, nullable=False)
    target = Column(String, nullable=False)
    status = Column(Enum("pending", "running", "completed", "failed", "cancelled",
                          name="job_status", create_type=False), nullable=False, default="pending")
    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))
    output_ref = Column(Text)
    error_message = Column(Text)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uid)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    action = Column(String, nullable=False)
    entity_type = Column(String, nullable=False)
    entity_id = Column(UUID(as_uuid=True))
    client_id = Column(UUID(as_uuid=True))
    metadata_ = Column("metadata", JSONB)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
