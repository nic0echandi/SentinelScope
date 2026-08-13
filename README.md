# SentinelScope — Gestión de Activos y Vulnerabilidades Multi-Cliente

Plataforma para reconocimiento (pasivo + activo), descubrimiento de servicios
y escaneo de vulnerabilidades sobre los dominios de tus clientes, con
aislamiento multi-tenant, RBAC y un dashboard tipo "Nuclei Results".

## Contenido del proyecto

```
sentinelscope/
  db/
    init.sql.template     # Esquema Postgres + Row-Level Security + rol de app
    00-init.sh             # Bootstrap: inyecta APP_DB_PASSWORD de forma segura
  api/                     # API FastAPI + tareas Celery (lógica de negocio)
    Dockerfile              # Imagen liviana, sin herramientas de escaneo
    requirements.txt
    app/
      main.py               # Entry point FastAPI
      config.py              # Lee todas las variables de entorno
      database.py             # Conexión normal (app) + conexión admin (migraciones)
      migrations.py           # Migraciones de esquema idempotentes, corren al arrancar
      bootstrap.py             # Crea/actualiza el usuario admin al arrancar
      security.py / deps.py / schemas.py / models.py
      celery_app.py
      routers/                # auth, users, clients, domains, subdomains,
                               # services, scans, vulnerabilities, audit
      tasks/scan_tasks.py     # Orquestación: scan_domain, scan_services,
                               # scan_vulnerabilities, full_scan
      tools/                  # Wrappers de subfinder/amass/assetfinder/
                               # shuffledns/dnsx/httpx/naabu/nmap/nuclei/
                               # searchsploit/wafw00f
  worker/Dockerfile        # Imagen PESADA: instala TODAS las herramientas + wordlist
  frontend/
    index.html              # Estructura HTML (liviano)
    style.css               # Todos los estilos
    app.js                  # Toda la lógica de la SPA (vanilla JS, sin build step)
  docker-compose.yml
  .env.example
```

## Requisitos

- Docker y Docker Compose v2.
- Conexión a internet en el momento del **build** (el worker descarga e
  instala Go, compila subfinder/amass/assetfinder/shuffledns/dnsx/httpx/
  naabu/nuclei, instala nmap + searchsploit + wafw00f, y descarga la
  wordlist `n0kovo_subdomains`).
- La primera build del `worker` puede tardar bastante (compilación de Go +
  descarga de wordlist de ~3M de líneas). Las builds siguientes son rápidas
  gracias al cache de capas de Docker.

## Arranque

```bash
cd sentinelscope
cp .env.example .env
# Editá .env -- ver la sección "Variables de entorno explicadas" abajo,
# en particular JWT_SECRET y APP_DB_PASSWORD son OBLIGATORIAS.
docker compose build   # primera vez: tarda (instala todas las herramientas)
docker compose up -d
```

Servicios expuestos:
- Dashboard: http://localhost:18080
- API (docs interactivas en `/docs`): http://localhost:18000
- Postgres: localhost:15432
- Redis: localhost:16379

(Los puertos publicados al host están todos por encima de 10000 a propósito.
Los puertos *internos* entre contenedores siguen siendo los estándar: 5432,
6379, 8000, 80. Solo cambia lo que se expone hacia tu máquina.)

---

## Variables de entorno explicadas (`.env`)

Copiá `.env.example` a `.env` y completá cada una. Acá va el detalle de
**qué es cada una y por qué existe**, porque varias no son obvias:

### `JWT_SECRET`

Es la clave con la que el backend **firma** los tokens de sesión (JWT) que
recibís al loguearte. No es una contraseña que vos elijas para recordar —
tiene que ser una cadena larga, aleatoria e impredecible, y **secreta**
(si alguien la consigue, puede fabricar tokens de sesión válidos para
cualquier usuario). No tiene ningún significado especial más allá de eso.

Generá una propia así:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```
y pegala en `.env`. El valor de ejemplo que puede haber circulado en
conversaciones previas (`dJ-mYDwZMWEkd3DBW6Uj6YENSR5CwOZLgW8m3GOaDQwl1uOcUYiUqlnn5MPhmi2b`)
**no debería usarse en un despliegue real** — es un ejemplo que quedó
expuesto en texto, y todo el sentido de un secreto es que nadie más lo
conozca. Generá el tuyo propio.

### `APP_DB_PASSWORD`

Es la contraseña del rol de Postgres **sin privilegios de superusuario**
(`sentinelscope_app`) que usan la API y el worker para conectarse a la
base de datos. Es obligatoria: si no la definís, el contenedor de
Postgres directamente no arranca (falla rápido y explícito, a propósito,
en vez de arrancar en un estado raro).

¿Por qué un rol separado y no usar directamente el superusuario de
Postgres? Porque **Postgres ignora las políticas de Row-Level Security
(RLS) de forma incondicional para superusuarios**, sin importar
`ENABLE`/`FORCE ROW LEVEL SECURITY`. El aislamiento multi-tenant de
SentinelScope se refuerza en dos capas: filtrado por `client_id` en cada
endpoint + RLS en Postgres como red de seguridad extra. Si la app se
conectara como superusuario, esa segunda capa sería un no-op — todo
dependería únicamente de que ningún endpoint tenga un bug de filtrado.
Por eso se creó `sentinelscope_app`: un rol con permisos mínimos
(`SELECT/INSERT/UPDATE/DELETE`, nada de `ALTER`/`CREATE POLICY`/etc.), para
que RLS se aplique de verdad. El rol `asm` (definido por `POSTGRES_USER`,
que sí es superusuario) se sigue usando, pero solo para el bootstrap
inicial de la base y para las migraciones de esquema (ver
`ADMIN_DATABASE_URL` más abajo, que no hace falta tocar).

Generala así:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(24))"
```

### `ADMIN_EMAIL` / `ADMIN_PASSWORD`

Las credenciales del usuario administrador inicial. Se crean (o se
actualizan, si el usuario ya existe) **automáticamente cada vez que
arranca el contenedor `api`** — no hay que generar ni pegar ningún hash a
mano. El usuario queda marcado con "debe cambiar contraseña", así que el
dashboard te va a pedir cambiarla en el primer login.

> **Nota histórica**: en algún momento del desarrollo, generar el usuario
> admin requería correr un comando como este para generar un hash Argon2
> a mano y pegarlo en el SQL de bootstrap:
> ```bash
> sudo docker run --rm python:3.12-slim bash -c \
>   "pip install passlib[argon2] -q && python -c \"
> from passlib.context import CryptContext
> print(CryptContext(schemes=['argon2']).hash('ChangeMe123!'))
> \""
> ```
> **Ese comando ya NO hace falta correrlo — quedó obsoleto.** Se reemplazó
> por el bootstrap automático descripto arriba (`ADMIN_EMAIL`/`ADMIN_PASSWORD`
> en `.env`, sin ningún paso manual). Si lo tenés guardado de una
> conversación anterior, podés ignorarlo por completo.

Si en algún momento te quedás afuera (perdiste la contraseña), cambiá
`ADMIN_PASSWORD` en `.env` y reiniciá el contenedor `api`
(`docker compose restart api`): el bootstrap la resetea sola.

### `ADMIN_DATABASE_URL`

Conexión con privilegios de superusuario, usada **exclusivamente** por el
sistema de migraciones (`api/app/migrations.py`) al arrancar la API, para
operaciones de esquema (`ALTER TABLE`, `CREATE POLICY`) que el rol
restringido `sentinelscope_app` no puede hacer. Ya viene armada en
`docker-compose.yml` con el rol `asm`/`asm` interno — no hace falta
editarla ni generarle una contraseña propia.

### Concurrencia / consumo de ancho de banda

```
CELERY_CONCURRENCY=2       # cuántos escaneos corren en paralelo (worker)
MAX_CONCURRENT_TARGETS=2   # threads internos de cada full-scan
SHUFFLEDNS_THREADS=500     # resoluciones DNS concurrentes del bruteforce
```

El paralelismo total aproximado de escaneos activos es
`CELERY_CONCURRENCY x MAX_CONCURRENT_TARGETS`. Si notás que un escaneo se
come todo el ancho de banda disponible, bajá estos valores (`1x1` es
bastante más conservador que el default `2x2`). `SHUFFLEDNS_THREADS` es
importante en particular: `shuffledns` sin este flag corre con **10.000**
resoluciones DNS concurrentes por default, lo cual satura casi cualquier
link doméstico/de oficina.

### Evasión de WAF/firewall (opcional)

```
NMAP_TIMING=T3              NMAP_TIMING_WAF=T2
NAABU_RATE=1000              NAABU_RATE_WAF=150
NUCLEI_RATE_LIMIT=150        NUCLEI_RATE_LIMIT_WAF=20
NUCLEI_RETRIES=1             NUCLEI_RETRIES_WAF=3
NMAP_USE_DECOYS=false
RANDOM_USER_AGENT=true
WAF_DETECTION_ENABLED=true
```

Antes de escanear vulnerabilidades de un servicio HTTP, se corre
`wafw00f` para detectar si hay un WAF/CDN delante. Si lo hay: se agrega un
hallazgo informativo ("WAF/CDN detectado: X") y se activan automáticamente
los valores `_WAF` (más lentos, más conservadores) para nuclei y nmap NSE
en ese servicio puntual, para reducir falsos negativos y la chance de que
el WAF bloquee el escaneo directamente.

---

## Flujo de uso

1. Login como `admin` → crear clientes desde la página **Clientes** (podés
   cargarle el dominio principal ahí mismo; te lleva directo a
   **Dominios** con ese cliente ya seleccionado).
2. Crear usuarios y asignarles rol + acceso a clientes (`POST /users`,
   `PUT /users/{id}/client-access`).
3. En **Dominios**: `Scan Domain` dispara recon pasivo (subfinder, amass,
   assetfinder) + activo (shuffledns bruteforce con wordlist n0kovo,
   validado con dnsx/httpx). El panel de subdominios se abre solo y se
   actualiza en vivo mientras corre.
4. Por cada subdominio: `Scan Services` → naabu (barrido rápido) + nmap
   `-sV -sC` (fingerprinting fino, banner incluido).
5. Por cada servicio: `Scan Vulnerabilities` → nuclei + nmap NSE
   (`--script vuln,vulners`, con `-sV`) + searchsploit (referencia offline
   a Exploit-DB).
6. `Full Scan` sobre un dominio encadena los tres pasos anteriores para
   todos los subdominios/servicios descubiertos.
7. **Dashboard**: resumen por severidad con gráfico. **Vulnerabilidades**:
   tabla agregada de todos los hallazgos, filtrable, con triage (abierto /
   falso positivo / remediado / riesgo aceptado). **Actividad**: log de
   operaciones (logins, altas/bajas, escaneos disparados) — solo
   admin/client_admin. **Mi cuenta**: cambio de contraseña.

## Roles

| Rol | Alcance |
|---|---|
| `admin` | Todo: usuarios, clientes, dominios, escaneos |
| `client_admin` | CRUD y escaneos solo de sus clientes asignados |
| `viewer_all` | Solo lectura de todos los clientes |
| `viewer_scoped` | Solo lectura de sus clientes asignados |

El aislamiento entre clientes se refuerza en dos capas: filtrado por
`client_id` en cada endpoint + Row-Level Security en Postgres, aplicada de
verdad porque la app se conecta con un rol sin privilegios de
superusuario (ver `APP_DB_PASSWORD` arriba).

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
(`docker compose down -v`) para aplicarlas.

## Notas importantes

- **Autorización**: cargá el dominio con `authorization_reference`
  (referencia al contrato/ticket que autoriza el escaneo activo) antes de
  lanzar cualquier escaneo. El sistema asume que solo se cargan dominios
  explícitamente autorizados por el cliente.
- **Wordlist de shuffledns**: si el nombre de archivo de `n0kovo_subdomains`
  cambia en el repo origen (SecLists), actualizá la URL en `worker/Dockerfile`.
- **Templates de nuclei**: se actualizan en el build; para mantenerlos al
  día en producción, agregá un cron/job periódico que corra
  `nuclei -update-templates` dentro del contenedor worker.
- **Frontend**: SPA en vanilla JS (sin build step, sin framework),
  separada en `index.html` / `style.css` / `app.js`. Polling cada 4s con
  reconciliación in-place del DOM (no destruye/recrea filas en cada
  refresh, para no perder la posición de scroll ni parpadear). Para un
  crecimiento serio del proyecto, conviene migrarla a un framework con
  manejo de estado propio (React, etc.) y paginación real en las tablas.

## Troubleshooting rápido

Si algo se comporta como si tu fix no hubiera surtido efecto (mismo error
después de un cambio), lo más probable es que falte reconstruir la imagen
correspondiente:

```bash
docker compose build api worker   # cambios de backend
docker compose up -d
```

El `frontend` **no** necesita rebuild (se sirve como volumen montado por
nginx) — alcanza con refrescar el navegador (`Ctrl+Shift+R` para forzar
sin caché).

Si un build falla de forma rara o repite un error ya corregido, probá
limpiar la caché de BuildKit antes de reintentar:
```bash
docker builder prune -af
docker compose build --no-cache
```
