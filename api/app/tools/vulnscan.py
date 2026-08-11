"""
Escaneo de vulnerabilidades por servicio, combinando tres fuentes:
1. nuclei     -> templates por tecnología/CVE (más preciso y con PoC activo)
2. nmap NSE   -> categoría "vuln" de scripts contra el puerto específico
3. searchsploit -> referencia offline a Exploit-DB por producto+versión
                   (informativo: solo lista, no ejecuta exploits)

Antes de correr nuclei/nmap NSE contra un servicio HTTP, se corre wafw00f
para detectar si hay un WAF/CDN filtrando el tráfico (ver tools/waf.py).
Si se detecta uno, se bajan el rate-limit y el timing de las herramientas
siguientes (parámetros "_waf" en config.py) para reducir falsos negativos
y la chance de que el WAF directamente bloquee el escaneo.
"""
import json
import re
from .shell import run
from .waf import detect_waf
from ..config import settings

SEVERITY_MAP = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "info": "info", "informational": "info", "unknown": "info",
}


def nuclei_scan(target: str, tags: list[str] | None = None, waf_mode: bool = False) -> list[dict]:
    rate_limit = settings.nuclei_rate_limit_waf if waf_mode else settings.nuclei_rate_limit
    retries = settings.nuclei_retries_waf if waf_mode else settings.nuclei_retries
    cmd = ["nuclei", "-u", target, "-silent", "-jsonl", "-severity",
           "critical,high,medium,low,info",
           "-rate-limit", str(rate_limit), "-retries", str(retries)]
    if settings.use_random_user_agent:
        # NOTA: "-random-agent" NO es un flag válido en nuclei v3 -- pasarlo
        # hace que el comando entero falle con "flag provided but not
        # defined", sin imprimir ningún resultado (y como solo leemos
        # stdout, ese error quedaba invisible). Un header explícito logra
        # el mismo objetivo (no delatar el User-Agent por defecto de
        # nuclei) sin depender de un flag que no existe.
        cmd += ["-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"]
    if tags:
        cmd += ["-tags", ",".join(tags)]
    rc, out, err = run(cmd, timeout=1200)
    if rc != 0 and not out:
        # nuclei devolvió error y no hay nada que parsear en stdout: esto
        # normalmente indica un problema real (flag inválido, target
        # inalcanzable, templates faltantes). Lo logueamos para que quede
        # visible en los logs del worker en vez de perderse en silencio.
        import logging
        logging.getLogger("asm.tools.vulnscan").warning(
            "nuclei terminó con código %s y sin resultados para %s. stderr: %s",
            rc, target, (err or "")[:500]
        )
    findings = []
    for line in out.splitlines():
        try:
            obj = json.loads(line)
        except Exception:
            continue
        info = obj.get("info", {})
        findings.append({
            "source": "nuclei",
            "template_id": obj.get("template-id"),
            "cve_id": ",".join(info.get("classification", {}).get("cve-id", []) or []) or None,
            "title": info.get("name", obj.get("template-id", "Hallazgo nuclei")),
            "description": info.get("description"),
            "severity": SEVERITY_MAP.get(info.get("severity", "info"), "info"),
            "cvss_score": info.get("classification", {}).get("cvss-score"),
            "reference_url": (info.get("reference") or [None])[0] if isinstance(info.get("reference"), list) else info.get("reference"),
        })
    return findings


def nmap_vuln_scripts(ip: str, port: int, waf_mode: bool = False) -> list[dict]:
    xml_out = "/tmp/nmap_vuln_output.xml"
    timing = settings.nmap_timing_waf if waf_mode else settings.nmap_timing
    # -sV es necesario acá por dos motivos:
    #  1. Muchos scripts NSE de la categoría http-* (http-csrf, http-enum,
    #     http-sql-injection, etc.) solo se activan si nmap reconoció el
    #     puerto como servicio "http" -- eso lo hace la detección de
    #     versión (-sV), no el escaneo de puertos solo.
    #  2. vulners.nse necesita el CPE del producto (que también sale de
    #     -sV) para poder buscar CVEs asociados; sin -sV corre vacío.
    # Sin -sV acá, la enorme mayoría de los scripts NSE de "vuln" para
    # servicios HTTP directamente no se ejecutaban -- coincide con el
    # síntoma de "por consola encuentra un montón, la app no encuentra nada".
    cmd = ["nmap", "-sV", "-Pn", f"-{timing}", "-p", str(port),
           "--script", "vuln,vulners", "-oX", xml_out, ip]
    rc, out, err = run(cmd, timeout=1200)
    import xml.etree.ElementTree as ET
    findings = []
    try:
        tree = ET.parse(xml_out)
    except Exception:
        return findings

    # Marcadores de resultado NEGATIVO explícito (el script corrió y no
    # encontró nada) -- estos NO son hallazgos y hay que descartarlos.
    NEGATIVE_MARKERS = (
        "couldn't find", "not vulnerable", "no vuln", "seems to be not vulnerable",
        "no exploitable", "no results", "0 vulnerabilities",
    )

    for script in tree.getroot().iter("script"):
        script_id = script.get("id")
        output = (script.get("output") or "").strip()
        if not output:
            continue
        lower = output.lower()
        if any(marker in lower for marker in NEGATIVE_MARKERS):
            continue

        cve_match = re.findall(r"CVE-\d{4}-\d{4,7}", output)

        # NOTA: antes se exigía que el output contuviera literalmente la
        # palabra "VULNERABLE" para considerarlo un hallazgo -- eso
        # descartaba la gran mayoría de los scripts reales (http-csrf,
        # http-sql-injection, http-enum, http-trace, vulners, etc. jamás
        # usan esa palabra), dejando pasar solo casos como
        # http-slowloris-check. Ahora se captura cualquier output no-vacío
        # que no sea un negativo explícito, y la severidad se infiere:
        if "vulnerable" in lower:
            severity = "high"
        elif script_id == "vulners" and cve_match:
            severity = "high"  # vulners casi siempre lista CVEs reales del CPE detectado
        else:
            severity = "medium"

        findings.append({
            "source": "nmap_nse",
            "template_id": script_id,
            "cve_id": ",".join(sorted(set(cve_match))) or None,
            "title": f"NSE {script_id}: hallazgo detectado",
            "description": output[:2000],
            "severity": severity,
            "cvss_score": None,
            "reference_url": None,
        })
    return findings


def searchsploit_lookup(product: str, version: str | None) -> list[dict]:
    if not product:
        return []
    query = f"{product} {version}" if version else product
    rc, out, err = run(["searchsploit", "--json", query], timeout=120)
    findings = []
    try:
        data = json.loads(out)
    except Exception:
        return findings
    for entry in data.get("RESULTS_EXPLOIT", []):
        findings.append({
            "source": "searchsploit",
            "template_id": entry.get("EDB-ID"),
            "cve_id": None,
            "title": entry.get("Title", "Exploit público en Exploit-DB"),
            "description": f"Exploit-DB #{entry.get('EDB-ID')} para {query}. Referencia informativa, no se ejecuta automáticamente.",
            "severity": "medium",  # informativo; se debe revisar/confirmar manualmente
            "cvss_score": None,
            "reference_url": f"https://www.exploit-db.com/exploits/{entry.get('EDB-ID')}" if entry.get("EDB-ID") else None,
        })
    return findings


def scan_service_vulnerabilities(ip: str, port: int, service_name: str | None,
                                   product: str | None, version: str | None,
                                   is_http: bool = False) -> list[dict]:
    findings = []
    waf_mode = False

    # nuclei: si es HTTP usamos la URL, si no, igual se puede apuntar host:port
    target = f"http://{ip}:{port}" if is_http else f"{ip}:{port}"

    # Detección de WAF/CDN (solo tiene sentido para servicios HTTP). Si se
    # detecta uno, se agrega un hallazgo informativo y se activa el modo
    # evasivo (rate-limit más bajo, timing más lento, más reintentos) para
    # nuclei y nmap NSE, reduciendo la chance de falsos negativos o bloqueo.
    if is_http and settings.waf_detection_enabled:
        waf_info = detect_waf(target)
        if waf_info:
            waf_mode = True
            findings.append({
                "source": "wafw00f",
                "template_id": "waf-detected",
                "cve_id": None,
                "title": f"WAF/CDN detectado: {waf_info['name']}",
                "description": (
                    f"Se detectó {waf_info['name']}"
                    + (f" ({waf_info['manufacturer']})" if waf_info.get("manufacturer") else "")
                    + " delante de este servicio. Los resultados de nuclei y nmap NSE pueden "
                      "estar incompletos por el filtrado del WAF; se aplicaron parámetros más "
                      "conservadores (rate-limit reducido, timing más lento, más reintentos) "
                      "para este servicio."
                ),
                "severity": "info",
                "cvss_score": None,
                "reference_url": None,
            })

    # NOTA: antes se restringía con "-tags <producto_detectado_por_nmap>"
    # (ej: "-tags apache-httpd"), pero el string de producto que devuelve
    # nmap casi nunca coincide con un tag real de nuclei-templates -- en la
    # práctica eso filtraba casi el 100% de los templates aplicables y
    # dejaba pasar muy pocos o ningún hallazgo. Se corre el set completo de
    # templates (ya acotado por severidad/rate-limit/timeout) para tener
    # cobertura real; "tags" queda disponible como parámetro por si más
    # adelante se integra detección de tecnología vía httpx/wappalyzer
    # (que sí generaría tags confiables).
    findings += nuclei_scan(target, waf_mode=waf_mode)

    # nmap NSE vuln scripts
    findings += nmap_vuln_scripts(ip, port, waf_mode=waf_mode)

    # searchsploit (referencia offline por producto+versión)
    if product:
        findings += searchsploit_lookup(product, version)

    return findings
