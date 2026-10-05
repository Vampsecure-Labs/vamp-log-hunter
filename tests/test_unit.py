# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_unit.py — Tests unitarios para vamp-log-hunter.

Cubre: parseo de timestamps, detección de IoC por regex, clasificación de
tipos de log, detección de IPs conocidas de escáner, y generación de hallazgos.
Mínimo 12 tests unitarios independientes.
"""

import re
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_log_hunter import (
    _parse_nginx_ts,
    _parse_syslog_ts,
    _detect_log_type,
    _is_known_scanner,
    _RE_SQLI,
    _RE_LFI,
    _RE_XSS,
    _RE_WEBSHELL_PATH,
    _RE_WEBSHELL_QUERY,
    _RE_SSH_FAIL,
    _RE_ACCESS,
    IoCFinding,
    LogScanner,
)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Parseo de timestamp nginx
# ─────────────────────────────────────────────────────────────────────────────

class TestParseoTimestampNginx:
    """Verifica el parseo de timestamps en formato nginx/apache."""

    def test_timestamp_valido_parsea_correctamente(self):
        """Un timestamp bien formado devuelve un datetime con la zona horaria."""
        ts = _parse_nginx_ts("01/Oct/2026:10:30:00 +0000")
        assert ts is not None
        assert ts.year == 2026
        assert ts.month == 10
        assert ts.day == 1
        assert ts.hour == 10
        assert ts.minute == 30

    def test_timestamp_con_offset_negativo(self):
        """Parseo correcto con offset de zona negativo (-0700)."""
        ts = _parse_nginx_ts("15/Jan/2026:03:00:00 -0700")
        assert ts is not None
        assert ts.year == 2026
        assert ts.tzinfo is not None

    def test_timestamp_invalido_devuelve_none(self):
        """Cadena no válida devuelve None sin lanzar excepción."""
        ts = _parse_nginx_ts("no-es-un-timestamp")
        assert ts is None

    def test_timestamp_vacio_devuelve_none(self):
        """Cadena vacía devuelve None."""
        ts = _parse_nginx_ts("")
        assert ts is None


# ─────────────────────────────────────────────────────────────────────────────
# 2. Parseo de timestamp syslog
# ─────────────────────────────────────────────────────────────────────────────

class TestParseoTimestampSyslog:
    """Verifica el parseo de timestamps en formato syslog (BSD)."""

    def test_syslog_timestamp_valido(self):
        """Mes/día/hora bien formados producen un datetime."""
        ts = _parse_syslog_ts("Oct", "1", "10:30:00")
        assert ts is not None
        assert ts.month == 10
        assert ts.day == 1

    def test_syslog_mes_invalido_devuelve_none(self):
        """Mes no reconocido devuelve None."""
        ts = _parse_syslog_ts("Xxx", "1", "10:00:00")
        assert ts is None

    def test_syslog_hora_invalida_devuelve_none(self):
        """Hora con formato incorrecto devuelve None."""
        ts = _parse_syslog_ts("Jan", "1", "99:00:00")
        assert ts is None


# ─────────────────────────────────────────────────────────────────────────────
# 3. Detección de tipo de log por nombre de fichero
# ─────────────────────────────────────────────────────────────────────────────

class TestDeteccionTipoLog:
    """Verifica que _detect_log_type infiere el tipo a partir del nombre."""

    def test_access_log_es_nginx(self):
        assert _detect_log_type("/var/log/nginx/access.log") == "nginx"

    def test_auth_log_es_auth(self):
        assert _detect_log_type("/var/log/auth.log") == "auth"

    def test_syslog_es_syslog(self):
        assert _detect_log_type("/var/log/syslog") == "syslog"

    def test_desconocido_fallback_syslog(self):
        assert _detect_log_type("/var/log/unknown.txt") == "syslog"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Detección de IPs de escáneres conocidos
# ─────────────────────────────────────────────────────────────────────────────

class TestDeteccionEscanerIP:
    """Verifica que _is_known_scanner identifica IPs de escáneres conocidos."""

    def test_ip_shodan_conocida(self):
        """Una IP de Shodan del set embebido se detecta como escáner."""
        assert _is_known_scanner("198.20.69.74") is True

    def test_ip_censys_en_cidr(self):
        """Una IP dentro del CIDR de Censys se detecta como escáner."""
        assert _is_known_scanner("162.142.125.100") is True

    def test_ip_privada_no_es_escaner(self):
        """Una IP de red privada no se considera escáner conocido."""
        assert _is_known_scanner("192.168.1.1") is False

    def test_ip_aleatoria_no_es_escaner(self):
        """Una IP pública aleatoria no marcada no es escáner."""
        assert _is_known_scanner("8.8.8.8") is False

    def test_ip_invalida_no_lanza_excepcion(self):
        """Una cadena que no es IP no lanza excepción."""
        resultado = _is_known_scanner("no-es-ip")
        assert resultado is False


# ─────────────────────────────────────────────────────────────────────────────
# 5. Expresiones regulares de detección de IoC
# ─────────────────────────────────────────────────────────────────────────────

class TestRegexIoC:
    """Verifica los patrones regex para cada categoría de ataque."""

    # SQL Injection
    def test_sqli_union_select(self):
        """UNION SELECT es detectado como SQL injection."""
        assert _RE_SQLI.search("/search?q=1 UNION SELECT user,pass FROM users") is not None

    def test_sqli_or_1_igual_1(self):
        """OR 1=1 clásico es detectado como SQL injection."""
        assert _RE_SQLI.search("/login?user=admin' OR 1=1 --") is not None

    def test_sqli_drop_table(self):
        """DROP TABLE es detectado como SQL injection."""
        assert _RE_SQLI.search("/api?q=DROP TABLE usuarios") is not None

    def test_sqli_url_limpia_no_detecta(self):
        """Una URL limpia no activa el regex de SQLi."""
        assert _RE_SQLI.search("/page/about-us?lang=es") is None

    # Path Traversal / LFI
    def test_lfi_punto_punto_barra(self):
        """La secuencia /../ es detectada como path traversal."""
        assert _RE_LFI.search("/app/../etc/passwd") is not None

    def test_lfi_etc_passwd_directo(self):
        """Acceso directo a /etc/passwd es detectado como LFI."""
        assert _RE_LFI.search("/etc/passwd") is not None

    def test_lfi_encoded_url(self):
        """../  URL-encoded (%2e%2e%2f) es detectado."""
        assert _RE_LFI.search("/path/%2e%2e%2fetc/shadow") is not None

    def test_lfi_ruta_normal_no_detecta(self):
        """Una ruta normal no activa el regex de LFI."""
        assert _RE_LFI.search("/static/images/logo.png") is None

    # XSS
    def test_xss_script_tag(self):
        """Etiqueta <script> es detectada como XSS."""
        assert _RE_XSS.search('/comment?t=<script>alert(1)</script>') is not None

    def test_xss_javascript_protocol(self):
        """Protocolo javascript: es detectado como XSS."""
        assert _RE_XSS.search('/url?redirect=javascript:alert(1)') is not None

    def test_xss_onerror(self):
        """Evento onerror= es detectado como XSS."""
        assert _RE_XSS.search('/img?src=<img onerror=alert(1)>') is not None

    # Webshell
    def test_webshell_ruta_c99(self):
        """Ruta /c99.php es detectada como webshell conocida."""
        assert _RE_WEBSHELL_PATH.search("/c99.php") is not None

    def test_webshell_parametro_cmd(self):
        """Parámetro cmd= en POST activa detección de webshell por query."""
        assert _RE_WEBSHELL_QUERY.search("?cmd=id") is not None

    def test_webshell_ruta_shell_php(self):
        """Ruta /shell.php es detectada como webshell."""
        assert _RE_WEBSHELL_PATH.search("/shell.php") is not None


# ─────────────────────────────────────────────────────────────────────────────
# 6. Parseo de línea de access.log (regex _RE_ACCESS)
# ─────────────────────────────────────────────────────────────────────────────

class TestParseoLineaAccess:
    """Verifica la extracción de campos de una línea Apache/nginx."""

    def test_extrae_ip_metodo_url_status(self):
        """Línea Combined Log Format → extrae IP, método, URL, status y bytes."""
        linea = (
            '10.0.0.1 - - [01/Oct/2026:10:00:00 +0000] '
            '"GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        )
        m = _RE_ACCESS.match(linea)
        assert m is not None
        assert m.group("ip") == "10.0.0.1"
        assert m.group("method") == "GET"
        assert m.group("path") == "/index.html"
        assert m.group("status") == "200"
        assert m.group("bytes") == "1024"

    def test_extrae_user_agent(self):
        """Se extrae el User-Agent de la línea de log."""
        linea = (
            '10.0.0.2 - - [01/Oct/2026:10:00:00 +0000] '
            '"GET / HTTP/1.1" 200 512 "-" "sqlmap/1.7"'
        )
        m = _RE_ACCESS.match(linea)
        assert m is not None
        assert "sqlmap" in m.group("ua")

    def test_linea_invalida_no_coincide(self):
        """Una línea de syslog no coincide con el regex de access.log."""
        linea = "Oct  1 10:00:00 srv sshd[1234]: Failed password for root"
        m = _RE_ACCESS.match(linea)
        assert m is None


# ─────────────────────────────────────────────────────────────────────────────
# 7. Parseo de auth.log — regex _RE_SSH_FAIL
# ─────────────────────────────────────────────────────────────────────────────

class TestParseoAuthLog:
    """Verifica la detección de fallos SSH en auth.log."""

    def test_failed_password_detectado(self):
        """Línea 'Failed password for root' activa el regex de fallo SSH."""
        linea = "Oct  1 10:00:00 srv sshd[1234]: Failed password for root from 172.16.0.99 port 22 ssh2"
        assert _RE_SSH_FAIL.search(linea) is not None

    def test_invalid_user_detectado(self):
        """Línea 'Invalid user' activa el regex de fallo SSH."""
        linea = "Oct  1 10:00:00 srv sshd[1235]: Invalid user hacker from 10.0.0.1 port 12345"
        assert _RE_SSH_FAIL.search(linea) is not None

    def test_login_exitoso_no_detectado(self):
        """Línea de login exitoso NO activa el regex de fallo SSH."""
        linea = "Oct  1 10:00:00 srv sshd[1236]: Accepted publickey for admin from 10.0.0.50 port 22"
        assert _RE_SSH_FAIL.search(linea) is None


# ─────────────────────────────────────────────────────────────────────────────
# 8. Formato de IDs de hallazgos (LOG-NNN)
# ─────────────────────────────────────────────────────────────────────────────

class TestFormatoIDHallazgo:
    """Verifica que el formato de IDs de hallazgo sea LOG-NNN."""

    def test_formato_fora_valido(self):
        """LOG-001 y LOG-999 son formatos válidos."""
        re_id = re.compile(r"^LOG-\d{3}$")
        assert re_id.match("LOG-001") is not None
        assert re_id.match("LOG-999") is not None

    def test_formato_incorrecto_invalido(self):
        """FORA-001 y LOG-01 no son formatos válidos para log-hunter."""
        re_id = re.compile(r"^LOG-\d{3}$")
        assert re_id.match("FORA-001") is None
        assert re_id.match("LOG-01") is None


# ─────────────────────────────────────────────────────────────────────────────
# 9. LogScanner — detección de inyección SQL
# ─────────────────────────────────────────────────────────────────────────────

class TestLogScannerSQLi:
    """Verifica que LogScanner detecta inyección SQL en líneas de acceso web."""

    def test_sqli_genera_hallazgo_critical(self, scanner_basico):
        """Una línea con SQLi genera un hallazgo CRITICAL en la categoría sqli."""
        linea = (
            '192.168.1.5 - - [01/Oct/2026:10:00:02 +0000] '
            '"GET /search?q=1+UNION+SELECT+pass+FROM+users HTTP/1.1" 200 500 "-" "Mozilla/5.0"'
        )
        scanner_basico._scan_access(linea, "access.log")
        findings = scanner_basico.generate_findings()
        sqli_findings = [f for f in findings if f.category == "sqli"]
        assert len(sqli_findings) > 0
        assert sqli_findings[0].severity == "CRITICAL"

    def test_sqli_registra_ip_de_origen(self, scanner_basico):
        """El hallazgo SQLi incluye la IP correcta del atacante."""
        linea = (
            '10.99.99.1 - - [01/Oct/2026:10:00:02 +0000] '
            '"GET /data?x=\'+OR+1=1+-- HTTP/1.1" 200 100 "-" "Mozilla/5.0"'
        )
        scanner_basico._scan_access(linea, "access.log")
        findings = scanner_basico.generate_findings()
        sqli_findings = [f for f in findings if f.category == "sqli"]
        assert "10.99.99.1" in sqli_findings[0].source_ips


# ─────────────────────────────────────────────────────────────────────────────
# 10. LogScanner — detección de path traversal (LFI)
# ─────────────────────────────────────────────────────────────────────────────

class TestLogScannerLFI:
    """Verifica que LogScanner detecta path traversal en acceso web."""

    def test_lfi_genera_hallazgo_high(self, scanner_basico):
        """Una línea con path traversal genera un hallazgo HIGH en lfi."""
        linea = (
            '10.0.0.1 - - [01/Oct/2026:10:00:01 +0000] '
            '"GET /admin/../etc/passwd HTTP/1.1" 404 0 "-" "curl/7.88"'
        )
        scanner_basico._scan_access(linea, "access.log")
        findings = scanner_basico.generate_findings()
        lfi_findings = [f for f in findings if f.category == "lfi"]
        assert len(lfi_findings) > 0
        assert lfi_findings[0].severity == "HIGH"


# ─────────────────────────────────────────────────────────────────────────────
# 11. LogScanner — detección de brute force SSH en auth.log
# ─────────────────────────────────────────────────────────────────────────────

class TestLogScannerBruteSSH:
    """Verifica que LogScanner detecta fuerza bruta SSH."""

    def test_brute_ssh_umbral_superado_genera_hallazgo(self, consola):
        """Superado el umbral, se genera hallazgo de fuerza bruta SSH."""
        scanner = LogScanner(threshold_brute=3, threshold_scan=10,
                             last_hours=0, console=consola)
        # 4 fallos de la misma IP → supera umbral de 3
        for i in range(4):
            linea = (
                f"Oct  1 10:00:{i:02d} srv sshd[100{i}]: "
                f"Failed password for root from 172.16.0.50 port 12345 ssh2"
            )
            scanner._scan_auth(linea, "auth.log")
        findings = scanner.generate_findings()
        brute_ssh = [f for f in findings if f.category == "brute_ssh"]
        assert len(brute_ssh) > 0

    def test_brute_ssh_ip_atacante_en_hallazgo(self, consola):
        """La IP del atacante aparece en source_ips del hallazgo."""
        scanner = LogScanner(threshold_brute=2, threshold_scan=10,
                             last_hours=0, console=consola)
        for i in range(3):
            linea = (
                f"Oct  1 10:00:{i:02d} srv sshd[100{i}]: "
                f"Failed password for admin from 172.16.0.99 port 22 ssh2"
            )
            scanner._scan_auth(linea, "auth.log")
        findings = scanner.generate_findings()
        brute_ssh = [f for f in findings if f.category == "brute_ssh"]
        assert "172.16.0.99" in brute_ssh[0].source_ips


# ─────────────────────────────────────────────────────────────────────────────
# 12. LogScanner — tráfico legítimo no genera hallazgos
# ─────────────────────────────────────────────────────────────────────────────

class TestLogScannerTraficoLegitimo:
    """Verifica que el tráfico normal no produce falsos positivos."""

    def test_lineas_legitimas_no_generan_hallazgos(self, scanner_basico):
        """Varias peticiones GET normales no producen hallazgos."""
        lineas = [
            '192.168.1.1 - - [01/Oct/2026:09:00:00 +0000] "GET / HTTP/1.1" 200 1000 "-" "Mozilla/5.0"',
            '192.168.1.2 - - [01/Oct/2026:09:00:01 +0000] "GET /about HTTP/1.1" 200 800 "-" "Chrome/100"',
            '192.168.1.3 - - [01/Oct/2026:09:00:02 +0000] "GET /contact HTTP/1.1" 200 700 "-" "Firefox/99"',
        ]
        for linea in lineas:
            scanner_basico._scan_access(linea, "access.log")
        findings = scanner_basico.generate_findings()
        # Sin superar umbrales → no hay hallazgos de ataque
        categorias_ataque = {"sqli", "xss", "lfi", "webshell", "brute_web", "dir_scan"}
        hallazgos_ataque = [f for f in findings if f.category in categorias_ataque]
        assert len(hallazgos_ataque) == 0


# ─────────────────────────────────────────────────────────────────────────────
# 13. LogScanner — detector de User-Agent sospechoso
# ─────────────────────────────────────────────────────────────────────────────

class TestLogScannerUserAgent:
    """Verifica la detección de User-Agents de herramientas de escaneo."""

    def test_sqlmap_ua_detectado(self, scanner_basico):
        """User-Agent de sqlmap genera hallazgo scanner_ua."""
        linea = (
            '10.0.0.10 - - [01/Oct/2026:10:00:00 +0000] '
            '"GET / HTTP/1.1" 200 1024 "-" "sqlmap/1.7.8#stable"'
        )
        scanner_basico._scan_access(linea, "access.log")
        findings = scanner_basico.generate_findings()
        ua_findings = [f for f in findings if f.category == "scanner_ua"]
        assert len(ua_findings) > 0

    def test_nikto_ua_detectado(self, scanner_basico):
        """User-Agent de nikto genera hallazgo scanner_ua."""
        linea = (
            '10.0.0.11 - - [01/Oct/2026:10:00:01 +0000] '
            '"GET /index.php HTTP/1.1" 200 512 "-" "Mozilla (nikto/2.1) Foo"'
        )
        scanner_basico._scan_access(linea, "access.log")
        findings = scanner_basico.generate_findings()
        ua_findings = [f for f in findings if f.category == "scanner_ua"]
        assert len(ua_findings) > 0


# ─────────────────────────────────────────────────────────────────────────────
# 14. IoCFinding — dataclass y campos requeridos
# ─────────────────────────────────────────────────────────────────────────────

class TestIoCFindingDataclass:
    """Verifica la creación y atributos de IoCFinding."""

    def test_hallazgo_con_campos_minimos(self):
        """Se puede crear un IoCFinding con los campos obligatorios."""
        hallazgo = IoCFinding(
            id="LOG-001",
            severity="CRITICAL",
            category="sqli",
            title="Inyección SQL detectada",
            description="Patrón UNION SELECT encontrado en URI.",
            source_ips=["10.0.0.1"],
            event_count=5,
            first_seen="2026-10-01 10:00:00",
            last_seen="2026-10-01 10:00:10",
            evidence_lines=["línea de log de muestra"],
            remediation="Aplicar consultas preparadas.",
        )
        assert hallazgo.id == "LOG-001"
        assert hallazgo.severity == "CRITICAL"
        assert hallazgo.event_count == 5

    def test_hallazgo_tags_por_defecto_vacio(self):
        """El campo tags tiene valor por defecto de lista vacía."""
        hallazgo = IoCFinding(
            id="LOG-002", severity="HIGH", category="lfi",
            title="Path traversal", description="../../",
            source_ips=[], event_count=1,
            first_seen=None, last_seen=None,
            evidence_lines=[], remediation="",
        )
        assert hallazgo.tags == []
