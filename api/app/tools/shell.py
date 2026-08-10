import subprocess
import json
import logging

logger = logging.getLogger("asm.tools")


def run(cmd: list[str], timeout: int = 900) -> tuple[int, str, str]:
    """Ejecuta un comando externo y devuelve (returncode, stdout, stderr)."""
    logger.info("Ejecutando: %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        logger.warning("Timeout ejecutando %s", " ".join(cmd))
        return -1, "", f"timeout after {timeout}s: {e}"
    except FileNotFoundError as e:
        logger.error("Herramienta no encontrada: %s", cmd[0])
        return -1, "", str(e)


def run_json_lines(cmd: list[str], timeout: int = 900) -> list[dict]:
    """Para herramientas que emiten JSON lines (nuclei -jsonl, httpx -json, etc.)."""
    rc, out, err = run(cmd, timeout)
    results = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results
