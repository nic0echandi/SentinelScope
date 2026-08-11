# SentinelScope — Gestión de Activos y Vulnerabilidades Multi-Cliente

Plataforma para reconocimiento (pasivo + activo), descubrimiento de servicios
y escaneo de vulnerabilidades sobre los dominios de tus clientes, con
aislamiento multi-tenant, RBAC y dashboard tipo "Nuclei Results".

## Contenido del proyecto

```
sentinelscope/
  db/init.sql.template     # Esquema Postgres + Row-Level Security + rol de app
  db/00-init.sh            # Bootstrap: inyecta APP_DB_PASSWORD de forma segura
  api/                     # API FastAPI + tareas Celery (lógica de negocio)
    Dockerfile              # Imagen liviana, sin herramientas de escaneo
    requirements.txt
    app/
      main.py               # Entry point FastAPI
      config.py / database.py / security.py / deps.py / schemas.py / models.py
      celery_app.py
      routers/               # auth, users, clients, domains, subdomains, services, scans
      tasks/scan_tasks.py    # Orquestación: scan_domain, scan_services, scan_vulnerabilities, full_scan
      tools/                 # Wrappers de subfinder/amass/assetfinder/shuffledns/dnsx/httpx/naabu/nmap/nuclei/searchsploit
  worker/Dockerfile        # Imagen PESADA: instala TODAS las herramientas + wordlist
  frontend/index.html      # Dashboard (single-page, vanilla JS + Chart.js por CDN)
  docker-compose.yml
```

## Requisitos

- Docker y Docker Compose v2.
- Conexión a internet en el momento del **build** (el worker descarga e
  instala Go, compila subfinder/amass/assetfinder/shuffledns/dnsx/httpx/
  naabu/nuclei, instala nmap + searchsploit vía apt, y descarga la
  wordlist `n0kovo_subdomains` + resolvers de `trickest/resolvers`).
- La primera build del `worker` puede tardar bastante (compilación de Go +
  descarga de wordlist de ~3M de líneas). Las builds siguientes son rápidas
  gracias al cache de capas de Docker.

## Arranque

```bash
cd sentinelscope
cp .env.example .env   # editar JWT_SECRET
docker compose build   # primera vez: tarda (instala todas las herramientas)
docker compose up -d
```

Servicios expuestos:
- API: http://localhost:18000 (docs interactivas en `/docs`)
- Dashboard: http://localhost:18080
- Postgres: localhost:15432
- Redis: localhost:16379

(Los puertos publicados al host están todos por encima de 10000 a propósito.
Los puertos *internos* entre contenedores — con los que se comunican
api/worker/postgres/redis entre sí dentro de la red de Docker — siguen
siendo los estándar: 5432, 6379, 8000, 80. Solo cambia lo que se expone
hacia tu máquina.)

### Usuario admin inicial

Ya no hace falta generar ni pegar ningún hash a mano. El usuario admin se
crea (o se actualiza, si ya existe) **automáticamente cada vez que arranca
la API**, usando `ADMIN_EMAIL` y `ADMIN_PASSWORD` definidos en `.env`:

```
ADMIN_EMAIL=admin@localhost
ADMIN_PASSWORD=ChangeMe123!
```

Cambiá `ADMIN_PASSWORD` por lo que quieras antes del primer `docker compose up`.
El usuario queda marcado con "debe cambiar contraseña" (`must_change_password`),
así que el dashboard te va a pedir cambiarla en el primer login. Si en algún
momento te quedás afuera (perdiste la contraseña), simplemente cambiá
`ADMIN_PASSWORD` en `.env` y reiniciá el contenedor `api`
(`docker compose restart api`): el bootstrap la va a resetear.

## Flujo de uso

1. Login como `admin` → crear clientes (`POST /clients`).
2. Crear usuarios y asignarles rol + acceso a clientes (`POST /users`,
   `PUT /users/{id}/client-access`).
3. Como `admin` o `client_admin` del cliente: cargar un dominio
   (`POST /clients/{client_id}/domains`).
4. Lanzar `Scan Domain` → dispara recon pasivo (subfinder, amass,
   assetfinder) + activo (shuffledns bruteforce con wordlist n0kovo,
   validado con dnsx/httpx).
5. Por cada subdominio descubierto: `Scan Services` → naabu (barrido
   rápido) + nmap `-sV -sC` (fingerprinting fino, banner incluido).
6. Por cada servicio: `Scan Vulnerabilities` → nuclei + nmap NSE
   (`--script vuln`) + searchsploit (referencia offline a Exploit-DB).
7. `Full Scan` sobre un dominio encadena los tres pasos anteriores para
   todos los subdominios/servicios, con concurrencia acotada
   (`MAX_CONCURRENT_TARGETS`, default 5) para no saturar la red del cliente.
8. Dashboard: resumen por severidad, árbol de activos, hallazgos con
   triage (abierto / falso positivo / remediado / riesgo aceptado).

## Roles

| Rol | Alcance |
|---|---|
| `admin` | Todo: usuarios, clientes, dominios, escaneos |
| `client_admin` | CRUD y escaneos solo de sus clientes asignados |
| `viewer_all` | Solo lectura de todos los clientes |
| `viewer_scoped` | Solo lectura de sus clientes asignados |

El aislamiento entre clientes se refuerza en dos capas: filtrado por
`client_id` en cada endpoint + **Row-Level Security en Postgres**
(`db/init.sql.template`), que impide leer filas de un cliente no
autorizado aunque hubiera un bug en la capa de aplicación.

**Importante**: la API y el worker se conectan a Postgres con un rol
llamado `sentinelscope_app`, creado automáticamente al bootstrapear la
base (`db/init.sql.template` + `db/00-init.sh`), **sin privilegios de
superusuario**. Esto es necesario porque Postgres ignora las políticas de
RLS de forma incondicional para superusuarios y para el dueño de las
tablas (salvo `FORCE ROW LEVEL SECURITY`, que igual no aplica a
superusuarios) — si la app se conectara con el rol de `POSTGRES_USER`
(que sí es superusuario), todo el aislamiento por RLS sería un no-op en
la práctica. El rol de `POSTGRES_USER` (dueño de las tablas) se sigue
usando, pero solo para el bootstrap inicial y para las migraciones de
esquema (`ADMIN_DATABASE_URL`, ver `.env.example`).

## Escalar workers

```bash
docker compose up -d --scale worker=3
```

Cada worker consume tareas de la misma cola Redis/Celery, permitiendo
paralelizar escaneos entre varios clientes sin tocar código.

## Migraciones de esquema

Los cambios de esquema posteriores a la primera versión se aplican como
migraciones idempotentes (`api/app/migrations.py`), automáticamente al
arrancar la API — no hace falta resetear la base de datos
(`docker compose down -v`) para aplicarlas. Corren con el rol de
`ADMIN_DATABASE_URL` (privilegios elevados), ya que operaciones como
`ALTER TABLE` o `CREATE POLICY` requieren ser dueño de la tabla o
superusuario.

## Notas importantes

- **Autorización**: cargá el dominio con `authorization_reference`
  (referencia al contrato/ticket que autoriza el escaneo activo) antes
  de lanzar cualquier escaneo. El sistema asume que solo se cargan
  dominios explícitamente autorizados por el cliente.
- **Throttling**: `MAX_CONCURRENT_TARGETS_PER_JOB` limita cuántos
  subdominios/servicios se escanean en paralelo dentro de un `full_scan`.
  Ajustalo según el impacto que quieras permitir sobre la infraestructura
  del cliente.
- **Wordlist de shuffledns**: si el nombre de archivo de
  `n0kovo_subdomains` cambia en el repo origen, actualizá la URL en
  `worker/Dockerfile`. Alternativas equivalentes: `SecLists`
  (`Discovery/DNS/subdomains-top1million-110000.txt`) o
  `assetnote/best-dns-wordlist.txt` (más grande, más lento).
- **Templates de nuclei**: se actualizan en el build; para mantenerlos al
  día en producción, agregá un cron/job periódico que corra
  `nuclei -update-templates` dentro del contenedor worker.
- **Frontend**: es un MVP funcional (vanilla JS) pensado para validar el
  flujo end-to-end rápido. Para producción conviene migrarlo a React con
  paginación, filtros combinables y manejo de sesión más robusto (refresh
  token automático, etc.), tal como se describe en el documento de
  arquitectura.
