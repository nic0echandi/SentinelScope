from celery import Celery
from .config import settings

celery_app = Celery(
    "asm_platform",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    worker_prefetch_multiplier=1,
    # Límite de concurrencia global; el throttling fino por cliente se aplica
    # a nivel de orquestación (ver tasks/scan_tasks.py)
    task_soft_time_limit=3600,
    task_time_limit=3900,
)

# Import directo en vez de autodiscover_tasks: autodiscover_tasks(["app.tasks"])
# busca un módulo "app.tasks.tasks" que no existe en nuestra estructura
# (las tareas viven en "app/tasks/scan_tasks.py"). Este import asegura que
# el proceso worker (que solo carga este módulo vía `celery -A app.celery_app...`)
# también registre las tareas, no solo el proceso de la API.
from . import tasks  # noqa: F401,E402
