"""
Detección de WAF/CDN delante de un servicio HTTP, usando wafw00f
(EnableSecurity). Se corre antes de nuclei/nmap NSE contra servicios web:
si hay un WAF, muchas herramientas de escaneo activo generan falsos
negativos (el WAF bloquea o devuelve una challenge page en vez de la
respuesta real) o directamente terminan bloqueadas. Cuando se detecta un
WAF, el pipeline baja el rate-limit y el timing de las herramientas
siguientes (ver config.py: sufijo "_waf") para reducir esa chance.
"""
import json
import logging
from .shell import run

logger = logging.getLogger("asm.tools.waf")


def detect_waf(url: str) -> dict | None:
    """
    Devuelve {"name": ..., "manufacturer": ...} si se detectó un WAF/CDN,
    o None si no se detectó (o si wafw00f falló/no está disponible).
    """
    output_path = "/tmp/wafw00f_output.json"
    rc, out, err = run(["wafw00f", url, "-a", "-f", "json", "-o", output_path], timeout=120)
    try:
        with open(output_path) as f:
            data = json.load(f)
    except Exception:
        logger.info("wafw00f no devolvió resultado parseable para %s", url)
        return None

    # wafw00f -f json devuelve una lista de detecciones (una por firewall
    # identificado); tomamos la primera si la hay.
    if isinstance(data, list) and data:
        first = data[0]
        if first.get("detected"):
            return {
                "name": first.get("firewall") or "Desconocido",
                "manufacturer": first.get("manufacturer") or "",
            }
    return None
