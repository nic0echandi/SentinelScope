# Importar scan_tasks acá registra sus tareas (@celery_app.task) en la
# instancia de Celery apenas se importa el paquete "app.tasks" — necesario
# para que el proceso worker (que arranca con `celery -A app.celery_app...`
# y solo importa celery_app.py) las vea. Sin este import, el worker
# reporta "Received unregistered task" para scan_domain/scan_services/
# scan_vulnerabilities/full_scan.
from . import scan_tasks  # noqa: F401