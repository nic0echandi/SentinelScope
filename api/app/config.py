import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg2://asm:asm@postgres:5432/asm",
    )
    redis_url: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    jwt_secret: str = os.getenv("JWT_SECRET", "change-me-in-prod")
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    storage_dir: str = os.getenv("STORAGE_DIR", "/data/scan-output")
    max_concurrent_targets_per_job: int = int(os.getenv("MAX_CONCURRENT_TARGETS", "5"))

    # Usuario admin inicial, creado/actualizado automáticamente al arrancar
    # la API (ver app/bootstrap.py). Evita tener que generar y pegar un
    # hash Argon2 a mano.
    admin_email: str = os.getenv("ADMIN_EMAIL", "")
    admin_password: str = os.getenv("ADMIN_PASSWORD", "")

    # ------------------------------------------------------------------
    # Evasión de WAF/firewall: parámetros de timing y rate-limit para las
    # herramientas de escaneo. Los valores "waf_*" se usan solo cuando se
    # detecta un WAF/CDN delante del servicio (ver tools/waf.py), para
    # bajar la velocidad y reducir la chance de que el WAF bloquee o
    # devuelva resultados falsos (rate-limiting, challenge pages, etc.)
    # ------------------------------------------------------------------
    nmap_timing: str = os.getenv("NMAP_TIMING", "T3")           # T0(paranoico)..T5(insano)
    nmap_timing_waf: str = os.getenv("NMAP_TIMING_WAF", "T2")
    nmap_use_decoys: bool = os.getenv("NMAP_USE_DECOYS", "false").lower() == "true"
    naabu_rate: int = int(os.getenv("NAABU_RATE", "1000"))       # paquetes/seg
    naabu_rate_waf: int = int(os.getenv("NAABU_RATE_WAF", "150"))
    nuclei_rate_limit: int = int(os.getenv("NUCLEI_RATE_LIMIT", "150"))  # requests/seg
    nuclei_rate_limit_waf: int = int(os.getenv("NUCLEI_RATE_LIMIT_WAF", "20"))
    nuclei_retries: int = int(os.getenv("NUCLEI_RETRIES", "1"))
    nuclei_retries_waf: int = int(os.getenv("NUCLEI_RETRIES_WAF", "3"))
    use_random_user_agent: bool = os.getenv("RANDOM_USER_AGENT", "true").lower() == "true"
    waf_detection_enabled: bool = os.getenv("WAF_DETECTION_ENABLED", "true").lower() == "true"


settings = Settings()
