"""
Descubrimiento de puertos y fingerprinting de servicios.
naabu: barrido rápido inicial de puertos abiertos.
nmap: fingerprinting detallado (-sV -sC) SOLO sobre los puertos que naabu
      encontró abiertos -> evita correr nmap completo contra rangos enteros.

Los parámetros de rate/timing son configurables (ver config.py) para poder
bajar la velocidad cuando hay un WAF/firewall filtrando paquetes.
"""
import json
import xml.etree.ElementTree as ET
from .shell import run
from ..config import settings


def naabu_discover_ports(ip: str, top_ports: int = 1000, waf_mode: bool = False) -> list[int]:
    rate = settings.naabu_rate_waf if waf_mode else settings.naabu_rate
    rc, out, err = run(
        ["naabu", "-host", ip, "-top-ports", str(top_ports), "-rate", str(rate), "-silent", "-json"],
        timeout=600,
    )
    ports = []
    for line in out.splitlines():
        try:
            obj = json.loads(line)
            if "port" in obj:
                ports.append(int(obj["port"]))
        except Exception:
            continue
    return sorted(set(ports))


def nmap_service_scan(ip: str, ports: list[int], waf_mode: bool = False) -> list[dict]:
    """
    Corre nmap -sV -sC contra los puertos indicados y parsea el XML resultante.
    Devuelve lista de dicts: {port, protocol, service_name, product, version, banner, cpe}
    """
    if not ports:
        return []
    port_str = ",".join(str(p) for p in ports)
    xml_out = "/tmp/nmap_output.xml"
    timing = settings.nmap_timing_waf if waf_mode else settings.nmap_timing
    cmd = ["nmap", "-sV", "-sC", "-Pn", f"-{timing}", "-p", port_str, "-oX", xml_out]
    if settings.nmap_use_decoys:
        cmd += ["-D", "RND:5"]
    cmd.append(ip)
    rc, out, err = run(cmd, timeout=1200)
    services = []
    try:
        tree = ET.parse(xml_out)
    except Exception:
        return services

    root = tree.getroot()
    for host in root.findall("host"):
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = int(port_el.get("portid"))
            protocol = port_el.get("protocol")
            service_el = port_el.find("service")
            service_name = product = version = cpe = None
            banner_parts = []
            if service_el is not None:
                service_name = service_el.get("name")
                product = service_el.get("product")
                version = service_el.get("version")
                extrainfo = service_el.get("extrainfo")
                cpe_el = service_el.find("cpe")
                if cpe_el is not None:
                    cpe = cpe_el.text
                banner_parts = [p for p in [product, version, extrainfo] if p]

            # scripts NSE (ej: banner grabbing explícito, ssl-cert, etc.)
            for script in port_el.findall("script"):
                if script.get("id") in ("banner", "http-title"):
                    banner_parts.append(script.get("output", "").strip())

            services.append({
                "port": portid,
                "protocol": protocol,
                "service_name": service_name,
                "product": product,
                "version": version,
                "banner": " | ".join(banner_parts) if banner_parts else None,
                "cpe": cpe,
            })
    return services


def discover_services_for_host(ip: str, waf_mode: bool = False) -> list[dict]:
    open_ports = naabu_discover_ports(ip, waf_mode=waf_mode)
    if not open_ports:
        return []
    return nmap_service_scan(ip, open_ports, waf_mode=waf_mode)
