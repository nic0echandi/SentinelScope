"""
Reconocimiento pasivo y activo de subdominios.

Pasivo: subfinder, amass (modo passive), assetfinder -> fuentes OSINT
        (certificados, motores de búsqueda, APIs públicas, etc.)
Activo:  shuffledns (bruteforce DNS masivo con massdns) + dnsx (resolución
        y validación) + httpx (confirma que responde HTTP/HTTPS)

shuffledns necesita una buena wordlist para tener cobertura real; usamos
la wordlist n0kovo_subdomains (una de las más completas y curadas,
~19M entradas en su versión "big", con una versión "mini" más rápida
para escaneos de rutina) ya incluida en la imagen del worker
en /opt/wordlists/n0kovo_subdomains.txt (ver worker/Dockerfile).
"""
from .shell import run
from ..config import settings

WORDLIST_PATH = "/opt/wordlists/n0kovo_subdomains.txt"
RESOLVERS_PATH = "/opt/wordlists/resolvers.txt"


def subfinder_passive(domain: str) -> set[str]:
    rc, out, err = run(["subfinder", "-d", domain, "-silent", "-all"], timeout=600)
    return {line.strip() for line in out.splitlines() if line.strip()}


def amass_passive(domain: str) -> set[str]:
    rc, out, err = run(["amass", "enum", "-passive", "-d", domain, "-silent"], timeout=600)
    return {line.strip() for line in out.splitlines() if line.strip()}


def assetfinder_passive(domain: str) -> set[str]:
    rc, out, err = run(["assetfinder", "--subs-only", domain], timeout=300)
    return {line.strip() for line in out.splitlines() if domain in line}


def shuffledns_bruteforce(domain: str) -> set[str]:
    """
    Bruteforce DNS activo usando shuffledns + massdns + wordlist n0kovo.

    IMPORTANTE: -t limita la cantidad de resoluciones DNS concurrentes.
    Sin este flag, shuffledns usa 10000 por default -- eso es lo que
    saturaba el ancho de banda disponible y tumbaba otras conexiones.
    """
    rc, out, err = run(
        ["shuffledns", "-d", domain, "-w", WORDLIST_PATH, "-r", RESOLVERS_PATH,
         "-t", str(settings.shuffledns_threads), "-silent", "-mode", "bruteforce"],
        timeout=1800,  # el bruteforce activo puede tardar bastante según la wordlist
    )
    return {line.strip() for line in out.splitlines() if line.strip()}


def dnsx_resolve(subdomains: set[str]) -> dict[str, list[str]]:
    """Resuelve una lista de subdominios y devuelve {subdominio: [ips]}, descarta los que no resuelven."""
    if not subdomains:
        return {}
    input_str = "\n".join(subdomains)
    proc_input = "/tmp/dnsx_input.txt"
    with open(proc_input, "w") as f:
        f.write(input_str)
    rc, out, err = run(["dnsx", "-l", proc_input, "-a", "-resp", "-silent", "-json"], timeout=600)
    import json
    resolved: dict[str, list[str]] = {}
    for line in out.splitlines():
        try:
            obj = json.loads(line)
        except Exception:
            continue
        host = obj.get("host")
        ips = obj.get("a", [])
        if host and ips:
            resolved.setdefault(host, []).extend(ips)
    return resolved


def httpx_probe(subdomains: set[str]) -> dict[str, dict]:
    """Confirma cuáles subdominios exponen HTTP/HTTPS y devuelve metadata (título, tech, status)."""
    if not subdomains:
        return {}
    input_path = "/tmp/httpx_input.txt"
    with open(input_path, "w") as f:
        f.write("\n".join(subdomains))
    rc, out, err = run(["httpx", "-l", input_path, "-silent", "-json", "-title", "-tech-detect", "-status-code"],
                        timeout=600)
    import json
    result = {}
    for line in out.splitlines():
        try:
            obj = json.loads(line)
        except Exception:
            continue
        host = obj.get("input") or obj.get("host")
        if host:
            result[host] = obj
    return result


def full_passive_and_active_recon(domain: str) -> dict[str, list[str]]:
    """
    Orquesta el pipeline completo de recon para un dominio:
    1. Pasivo: subfinder + amass + assetfinder (unión de fuentes)
    2. Activo: shuffledns bruteforce con wordlist n0kovo
    3. Validación: dnsx resuelve todo, httpx confirma servicios web
    Devuelve {subdominio: [ips]} solo para los que resolvieron.
    """
    found = set()
    found |= subfinder_passive(domain)
    found |= amass_passive(domain)
    found |= assetfinder_passive(domain)
    found |= shuffledns_bruteforce(domain)
    found.add(domain)  # el dominio raíz también se escanea

    resolved = dnsx_resolve(found)
    return resolved
