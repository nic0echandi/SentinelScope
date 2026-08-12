# =====================================================================
# Worker: imagen con TODAS las herramientas de reconocimiento y escaneo
# instaladas en build-time. Ejecuta las tareas Celery (app.tasks.scan_tasks).
# =====================================================================
FROM golang:1.25-bookworm AS gobuild

ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
ENV CGO_ENABLED=1
# Si alguna herramienta pide una versión de Go más nueva que la de esta
# imagen, dejamos que "go" descargue automáticamente el toolchain necesario
# en vez de fallar el build (evita tener que perseguir bumps de versión).
ENV GOTOOLCHAIN=auto

RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# ---- Herramientas de ProjectDiscovery ----
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

# ---- assetfinder (Tomnomnom) ----
RUN go install -v github.com/tomnomnom/assetfinder@latest

# ---- amass (OWASP) ----
RUN go install -v github.com/owasp-amass/amass/v4/...@master

# ---- massdns (dependencia de shuffledns para resolución masiva) ----
RUN git clone https://github.com/blechschmidt/massdns.git /opt/massdns \
    && cd /opt/massdns && make \
    && cp bin/massdns /usr/local/bin/massdns


# =====================================================================
# Imagen final
# =====================================================================
FROM python:3.12-slim

# nmap (con NSE incluido) y utilidades de red.
# NOTA: el paquete "exploitdb" NO existe en los repos estándar de Debian
# (solo en Kali), así que instalamos searchsploit clonando el repo oficial.
# libpcap0.8 a veces aparece renombrado (ej: libpcap0.8t64) según la
# versión de Debian; se intenta con fallback para no romper el build.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl git ca-certificates \
    && (apt-get install -y --no-install-recommends libpcap0.8 \
        || apt-get install -y --no-install-recommends libpcap0.8t64) \
    && rm -rf /var/lib/apt/lists/*

# ---- searchsploit / Exploit-DB (clonado directo, no vía apt) ----
# NOTA: el repo de GitHub (offensive-security/exploitdb) quedó como stub
# legacy sin contenido real -- el repo activo se mudó a GitLab.
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && chmod +x /opt/exploitdb/searchsploit \
    && ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && test -x /usr/local/bin/searchsploit \
    && echo "searchsploit instalado OK"

# Binarios Go compilados en la etapa anterior
COPY --from=gobuild /root/go/bin/subfinder   /usr/local/bin/subfinder
COPY --from=gobuild /root/go/bin/dnsx        /usr/local/bin/dnsx
COPY --from=gobuild /root/go/bin/httpx       /usr/local/bin/httpx
COPY --from=gobuild /root/go/bin/naabu       /usr/local/bin/naabu
COPY --from=gobuild /root/go/bin/nuclei      /usr/local/bin/nuclei
COPY --from=gobuild /root/go/bin/shuffledns  /usr/local/bin/shuffledns
COPY --from=gobuild /root/go/bin/assetfinder /usr/local/bin/assetfinder
COPY --from=gobuild /root/go/bin/amass       /usr/local/bin/amass
COPY --from=gobuild /usr/local/bin/massdns   /usr/local/bin/massdns

# naabu necesita capability de raw sockets, se le da al binario en runtime
# vía el usuario root del contenedor (ver docker-compose: cap_add NET_RAW/NET_ADMIN)

# ---------------------------------------------------------------------
# Wordlist y resolvers para shuffledns / dnsx
#   - n0kovo_subdomains: wordlist de referencia (~3M líneas) construida
#     harvesteando SSL certs de todo el espacio IPv4. Es la sugerida por
#     ser de las de mejor relación cobertura/tamaño hoy en día (usada por
#     defecto en reconFTW e incluida en SecLists).
#   - resolvers.txt: a propósito es una lista CHICA de resolutores
#     públicos grandes y confiables (Google, Cloudflare, Quad9, OpenDNS,
#     Verisign), no una lista enorme de miles de resolutores de terceros
#     sin verificar (como trickest/resolvers). Una lista gigante de
#     resolutores desconocidos tiende a incluir bastantes lentos/poco
#     confiables, lo que genera reintentos y tráfico extra. Además, así
#     no depende de una descarga externa en el build.
# ---------------------------------------------------------------------
RUN mkdir -p /opt/wordlists && \
    (curl -fsSL -o /opt/wordlists/n0kovo_subdomains.txt \
      https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/n0kovo_subdomains.txt \
      || curl -fsSL -o /opt/wordlists/n0kovo_subdomains.txt \
      https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_tiny.txt)

RUN printf '%s\n' \
    "8.8.8.8" "8.8.4.4" \
    "1.1.1.1" "1.0.0.1" \
    "9.9.9.9" \
    "208.67.222.222" "208.67.220.220" \
    "64.6.64.6" "64.6.65.6" \
    > /opt/wordlists/resolvers.txt

# nuclei templates (se actualizan también en runtime por cron, ver README)
RUN nuclei -update-templates -silent || true

# searchsploit: refrescar la base local de Exploit-DB
RUN searchsploit -u || true

WORKDIR /srv
# NOTA: este Dockerfile se construye con contexto = raíz del repo
# (ver docker-compose.yml: build.context: . / build.dockerfile: worker/Dockerfile)
COPY api/requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt celery[redis] wafw00f

COPY api/app /srv/app

# ---------------------------------------------------------------------
# Verificación final: si falta cualquier herramienta, el build falla acá
# (con un mensaje claro) en vez de descubrirse recién en medio de un
# escaneo real contra un cliente.
# ---------------------------------------------------------------------
RUN set -e; \
    for tool in subfinder amass assetfinder shuffledns massdns dnsx httpx naabu nuclei nmap searchsploit wafw00f; do \
        if ! command -v "$tool" > /dev/null 2>&1; then \
            echo "ERROR DE BUILD: falta la herramienta '$tool' en el PATH"; exit 1; \
        fi; \
    done; \
    echo "Todas las herramientas verificadas OK: subfinder amass assetfinder shuffledns massdns dnsx httpx naabu nuclei nmap searchsploit wafw00f"

# GODEBUG=cpu.avx2=off: workaround para un bug conocido de bytedance/sonic
# (librería JSON usada por nuclei) que puede crashear con SIGILL en CPUs
# virtualizados donde el hypervisor reporta soporte AVX2 pero no lo
# implementa correctamente. Esto le dice al runtime de Go que trate AVX2
# como no disponible; todas las libs (incluida sonic) caen a un camino
# sin SIMD -- un poco más lento, pero no crashea.
ENV GODEBUG=cpu.avx2=off

# Concurrencia del worker de Celery, configurable vía env var. OJO: el
# ancho de banda/CPU consumido es aproximadamente
# CELERY_CONCURRENCY x MAX_CONCURRENT_TARGETS (este último controla el
# paralelismo interno de cada full-scan, ver api/app/config.py), así que
# hay que ajustar ambos juntos si el escaneo satura la red del cliente.
ENV CELERY_CONCURRENCY=2

# CMD en forma shell (no exec form) para que la variable de entorno se
# expanda correctamente al arrancar el contenedor.
CMD celery -A app.celery_app.celery_app worker --loglevel=INFO --concurrency=${CELERY_CONCURRENCY}
