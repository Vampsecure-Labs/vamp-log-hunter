# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_integration.py — Tests de integración para vamp-log-hunter.

Crea ficheros de log reales en tmp_path, ejecuta el scanner completo y verifica
que los hallazgos producidos corresponden exactamente a los ataques inyectados.
Mínimo 5 tests de integración.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_log_hunter import LogScanner
from rich.console import Console


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures locales
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def consola_silenciosa():
    """Consola Rich sin salida en terminal para tests."""
    return Console(quiet=True)


@pytest.fixture
def scanner_defecto(consola_silenciosa):
    """Scanner con configuración por defecto."""
    return LogScanner(threshold_brute=5, threshold_scan=10,
                      last_hours=0, console=consola_silenciosa)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Integración: detección de ataques en fichero real
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_deteccion_ataques_conocidos(tmp_path, consola_silenciosa):
    """
    Crear un fichero access.log con ataques conocidos, ejecutar el scanner
    y verificar que detecta exactamente los ataques inyectados.
    """
    contenido = """\
127.0.0.1 - - [01/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
10.0.0.1 - - [01/Oct/2026:10:00:01 +0000] "GET /admin/../etc/passwd HTTP/1.1" 404 0 "-" "curl/7.88"
192.168.1.5 - - [01/Oct/2026:10:00:02 +0000] "GET /search?q='+OR+1=1+-- HTTP/1.1" 200 500 "-" "Mozilla/5.0"
10.0.0.2 - - [01/Oct/2026:10:00:03 +0000] "GET /index.html HTTP/1.1" 200 800 "-" "sqlmap/1.7"
10.0.0.3 - - [01/Oct/2026:10:00:04 +0000] "GET /about.html HTTP/1.1" 200 900 "-" "Firefox/100"
"""
    ruta = tmp_path / "access.log"
    ruta.write_text(contenido, encoding="utf-8")

    scanner = LogScanner(threshold_brute=1, threshold_scan=5,
                         last_hours=0, console=consola_silenciosa)
    scanner.scan_file(str(ruta), "nginx")
    findings = scanner.generate_findings()

    # Deben detectarse al menos: SQLi, LFI y scanner UA
    categorias = {f.category for f in findings}
    assert "sqli" in categorias, "No se detectó SQL injection"
    assert "lfi" in categorias, "No se detectó path traversal"
    assert "scanner_ua" in categorias, "No se detectó User-Agent de sqlmap"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Integración: brute force HTTP (401 masivos)
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_brute_force_http(tmp_path, consola_silenciosa):
    """
    Crear un fichero con 50 líneas de 401 de la misma IP.
    El scanner debe detectar brute_web con la IP correcta.
    """
    lineas = []
    for i in range(50):
        ts = f"01/Oct/2026:10:{i // 60:02d}:{i % 60:02d} +0000"
        lineas.append(
            f'10.0.0.99 - admin [{ts}] "POST /wp-login.php HTTP/1.1" 401 0\n'
        )
    # Peticiones legítimas de otra IP para no contaminar el conteo
    for i in range(5):
        lineas.append(
            f'192.168.1.1 - - [01/Oct/2026:10:01:{i:02d} +0000] "GET / HTTP/1.1" 200 5000\n'
        )

    ruta = tmp_path / "brute.log"
    ruta.write_text("".join(lineas), encoding="utf-8")

    scanner = LogScanner(threshold_brute=10, threshold_scan=20,
                         last_hours=0, console=consola_silenciosa)
    scanner.scan_file(str(ruta), "nginx")
    findings = scanner.generate_findings()

    brute_findings = [f for f in findings if f.category == "brute_web"]
    assert len(brute_findings) > 0, "No se detectó fuerza bruta HTTP"
    assert "10.0.0.99" in brute_findings[0].source_ips
    assert brute_findings[0].event_count >= 10


# ─────────────────────────────────────────────────────────────────────────────
# 3. Integración: detección en auth.log (brute force SSH)
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_brute_force_ssh(tmp_path, consola_silenciosa):
    """
    Crear un auth.log con 30 intentos SSH fallidos y verificar FORA de brute SSH.
    """
    lineas = []
    for i in range(30):
        lineas.append(
            f"Oct  1 10:00:{i:02d} srv sshd[100{i}]: "
            f"Failed password for root from 172.16.0.77 port 12345 ssh2\n"
        )
    ruta = tmp_path / "auth.log"
    ruta.write_text("".join(lineas), encoding="utf-8")

    scanner = LogScanner(threshold_brute=5, threshold_scan=10,
                         last_hours=0, console=consola_silenciosa)
    scanner.scan_file(str(ruta), "auth")
    findings = scanner.generate_findings()

    brute_ssh = [f for f in findings if f.category == "brute_ssh"]
    assert len(brute_ssh) > 0, "No se detectó fuerza bruta SSH"
    assert "172.16.0.77" in brute_ssh[0].source_ips


# ─────────────────────────────────────────────────────────────────────────────
# 4. Integración: webshell y fichero sensible en mismo log
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_webshell_y_fichero_sensible(tmp_path, consola_silenciosa):
    """
    Un log con acceso a shell.php y .env debe generar hallazgos
    webshell y sensitive_files respectivamente.
    """
    contenido = (
        '10.0.0.5 - - [01/Oct/2026:11:00:00 +0000] '
        '"POST /shell.php?cmd=whoami HTTP/1.1" 200 64 "-" "curl/7.88"\n'
        '10.0.0.6 - - [01/Oct/2026:11:00:01 +0000] '
        '"GET /.env HTTP/1.1" 200 256 "-" "python-requests/2.28"\n'
    )
    ruta = tmp_path / "access.log"
    ruta.write_text(contenido, encoding="utf-8")

    scanner = LogScanner(threshold_brute=1, threshold_scan=1,
                         last_hours=0, console=consola_silenciosa)
    scanner.scan_file(str(ruta), "nginx")
    findings = scanner.generate_findings()

    categorias = {f.category for f in findings}
    assert "webshell" in categorias, "No se detectó acceso a webshell"
    assert "sensitive_files" in categorias, "No se detectó acceso a .env"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Integración: tráfico legítimo no genera hallazgos de ataque
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_trafico_legitimo_sin_hallazgos(tmp_path, consola_silenciosa):
    """
    Un log con 50 peticiones completamente normales (sin ataques) no debe
    generar hallazgos de categorías de ataque.
    """
    lineas = [
        f'192.168.0.{i % 10 + 1} - - [01/Oct/2026:09:{i // 60:02d}:{i % 60:02d} +0000] '
        f'"GET /page{i}.html HTTP/1.1" 200 {500 + i} "-" "Mozilla/5.0"\n'
        for i in range(50)
    ]
    ruta = tmp_path / "clean.log"
    ruta.write_text("".join(lineas), encoding="utf-8")

    scanner = LogScanner(threshold_brute=100, threshold_scan=200,
                         last_hours=0, console=consola_silenciosa)
    scanner.scan_file(str(ruta), "nginx")
    findings = scanner.generate_findings()

    categorias_ataque = {"sqli", "xss", "lfi", "webshell"}
    hallazgos_ataque = [f for f in findings if f.category in categorias_ataque]
    assert len(hallazgos_ataque) == 0, (
        f"Se generaron hallazgos inesperados: {[f.category for f in hallazgos_ataque]}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 6. Integración: conteo de líneas escaneadas
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_conteo_lineas_escaneadas(tmp_path, consola_silenciosa):
    """
    El scanner debe contar correctamente el número de líneas procesadas.
    """
    N = 25
    lineas = [
        f'10.0.0.1 - - [01/Oct/2026:10:{i // 60:02d}:{i % 60:02d} +0000] '
        f'"GET /p{i} HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n'
        for i in range(N)
    ]
    ruta = tmp_path / "count.log"
    ruta.write_text("".join(lineas), encoding="utf-8")

    scanner = LogScanner(threshold_brute=100, threshold_scan=100,
                         last_hours=0, console=consola_silenciosa)
    scanner.scan_file(str(ruta), "nginx")

    assert scanner.lines_scanned == N
    assert scanner.files_scanned == 1
