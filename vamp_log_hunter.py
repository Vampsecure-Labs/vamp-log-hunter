#!/usr/bin/env python3
"""
vamp-log-hunter — Cazador de IoC en Logs del Sistema
=====================================================
VampSecure Labs · VampSecure Studios Security Research Division

DESCRIPCIÓN
-----------
Herramienta de análisis forense de logs del sistema para la detección de
Indicadores de Compromiso (IoC). Examina logs de nginx, apache, auth.log,
syslog y journald en busca de 14 categorías de ataque:

  LOG-001 · Fuerza bruta SSH
  LOG-002 · Fuerza bruta Web (respuestas 4xx masivas)
  LOG-003 · Escaneo de directorios (paths únicos con 404)
  LOG-004 · Inyección SQL en URI
  LOG-005 · Cross-Site Scripting (XSS) en URI
  LOG-006 · Path Traversal / Local File Inclusion (LFI)
  LOG-007 · Webshell o shell remota
  LOG-008 · Acceso a ficheros sensibles (.env, .git, wp-config, etc.)
  LOG-009 · User-Agent de herramienta de escaneo conocida
  LOG-010 · Escalada de privilegios sudo/su
  LOG-011 · Cron jobs con comandos sospechosos
  LOG-012 · Login SSH directo como root
  LOG-013 · IP perteneciente a escáner conocido (Shodan, Censys, etc.)
  LOG-014 · Actividad nocturna anómala (02:00-05:00)

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.

USO
---
  python3 vamp_log_hunter.py [OPCIONES]

EJEMPLOS
--------
  # Analizar /var/log completo:
  python3 vamp_log_hunter.py

  # Ficheros específicos:
  python3 vamp_log_hunter.py --file /var/log/nginx/access.log \\
                              --file /var/log/auth.log

  # Solo últimas 24 horas, umbral de brute force en 5:
  python3 vamp_log_hunter.py --last-hours 24 --threshold-brute 5

  # Exportar informe JSON y HTML oscuro:
  python3 vamp_log_hunter.py --json informe.json --html informe.html

  # Lectura desde stdin:
  cat /var/log/nginx/access.log | python3 vamp_log_hunter.py --file -
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Importaciones
# ---------------------------------------------------------------------------

# Biblioteca estándar
import argparse
import asyncio
import gzip
import html as _html_module
import ipaddress
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple

# Rich (visualización en terminal)
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box

# Módulo de informes unificado VampSecure Labs
from vampsec_report import (
    Finding as VSLFinding,
    VampSecReport,
    add_report_args,
    meta_from_args,
)

# ---------------------------------------------------------------------------
# Metadatos de la herramienta
# ---------------------------------------------------------------------------

VERSION   = "1.0"
TOOL_NAME = "vamp-log-hunter"
AUTHOR    = "© VampSecure Studios — VampSecure Labs Security Research Division"

# Tipos de log soportados
LOG_TYPES = ("nginx", "apache", "auth", "syslog", "journald", "auto")

# ---------------------------------------------------------------------------
# Inteligencia de amenazas: IPs de escáneres conocidos
# ---------------------------------------------------------------------------

# IPs conocidas de escáneres, crawlers de inteligencia y nodos Tor
# Fuentes: Shodan, Censys, GreyNoise, proyectos públicos de threat intel
_KNOWN_SCANNER_IPS: Set[str] = {
    # Shodan crawlers
    "198.20.69.74",  "198.20.69.98",  "198.20.70.114",
    "198.20.70.166", "198.20.87.98",  "198.20.99.130",
    # Censys IPv4 survey
    "162.142.125.0", "167.94.138.0",  "167.94.145.0",
    "167.94.146.0",  "167.248.133.0", "167.248.133.100",
    # Masscan / escáneres globales
    "5.8.10.202",
    # SecurityTrails / HackerTarget
    "54.36.148.202", "167.99.209.234",
    # Nodos Tor de salida conocidos (muestra)
    "199.249.230.87", "199.249.230.112", "185.220.101.47",
    # GreyNoise mass scanners
    "45.83.65.104",  "185.165.29.1",
    # Escáneres de vulnerabilidades públicos
    "89.248.167.131", "89.248.172.165",
}

# CIDRs de redes de escáneres reconocidos
_KNOWN_SCANNER_CIDRS = [
    ipaddress.ip_network("162.142.125.0/24",  strict=False),
    ipaddress.ip_network("167.94.138.0/24",   strict=False),
    ipaddress.ip_network("167.94.145.0/24",   strict=False),
    ipaddress.ip_network("167.94.146.0/24",   strict=False),
    ipaddress.ip_network("167.248.133.0/24",  strict=False),
    ipaddress.ip_network("198.20.69.0/24",    strict=False),
    ipaddress.ip_network("199.45.154.0/24",   strict=False),
    ipaddress.ip_network("199.45.155.0/24",   strict=False),
    ipaddress.ip_network("185.220.100.0/22",  strict=False),
]

# ---------------------------------------------------------------------------
# Paletas de color
# ---------------------------------------------------------------------------

_SEV_RICH: Dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold cyan",
    "LOW":      "bold blue",
    "INFO":     "dim white",
}

_SEV_BORDER: Dict[str, str] = {
    "CRITICAL": "red",
    "HIGH":     "yellow",
    "MEDIUM":   "cyan",
    "LOW":      "blue",
    "INFO":     "dim",
}

_SEV_CSS: Dict[str, str] = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8c00",
    "MEDIUM":   "#e6c800",
    "LOW":      "#4488ff",
    "INFO":     "#888888",
}

_CVSS_DEFAULT: Dict[str, float] = {
    "CRITICAL": 9.0,
    "HIGH":     7.5,
    "MEDIUM":   5.0,
    "LOW":      3.0,
    "INFO":     1.0,
}

# ---------------------------------------------------------------------------
# Expresiones regulares precompiladas
# ---------------------------------------------------------------------------

# Combined Log Format (nginx / apache):
# IP - user [timestamp] "METHOD /path PROTO" status bytes "referer" "UA"
_RE_ACCESS = re.compile(
    r'^(?P<ip>\S+)\s+-\s+(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+|-)\s+(?P<path>\S+)\s*(?P<proto>[^"]*?)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

# Formato syslog estándar: Month day HH:MM:SS host proc[pid]: msg
_RE_SYSLOG = re.compile(
    r'^(?P<month>[A-Za-z]{3})\s+(?P<day>\s?\d{1,2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<proc>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<msg>.+)$'
)

# Timestamp nginx: "10/Oct/2000:13:55:36 -0700"
_RE_NGINX_TS = re.compile(
    r'(?P<day>\d{2})/(?P<mon>\w{3})/(?P<year>\d{4}):'
    r'(?P<hms>\d{2}:\d{2}:\d{2})\s+(?P<tz>[+-]\d{4})'
)

# ── IoC: Inyección SQL ────────────────────────────────────────────────────
_RE_SQLI = re.compile(
    r'(?:'
    r'UNION[\s%+]+(?:ALL[\s%+]+)?SELECT'
    r'|SELECT[\s%+]+.{0,60}?FROM'
    r"|OR[\s%+]+1[\s%+]*=[\s%+]*1"
    r'|DROP[\s%+]+TABLE'
    r"|'[\s%+]*;[\s%+]*--"
    r'|xp_cmdshell'
    r'|information_schema'
    r'|UNION%20SELECT|UNION\+SELECT'
    r'|0x[0-9a-fA-F]{6,}'
    r'|SLEEP\s*\(\s*\d+'
    r'|BENCHMARK\s*\('
    r'|CHAR\s*\(\s*\d+'
    r')',
    re.IGNORECASE,
)

# ── IoC: XSS ─────────────────────────────────────────────────────────────
_RE_XSS = re.compile(
    r'(?:'
    r'<script[\s>/]'
    r'|javascript:'
    r'|onerror[\s]*='
    r'|onload[\s]*='
    r'|alert\s*\('
    r'|document\.cookie'
    r'|%3[Cc]script'
    r'|<img[^>]{0,60}onerror'
    r'|eval\s*\('
    r'|expression\s*\('
    r'|vbscript:'
    r'|&#x[0-9a-fA-F]+;'
    r')',
    re.IGNORECASE,
)

# ── IoC: Path Traversal / LFI ────────────────────────────────────────────
_RE_LFI = re.compile(
    r'(?:'
    r'\.\.[/\\]'
    r'|\.\.%2[Ff]'
    r'|\.\.%5[Cc]'
    r'|%2e%2e[/%]'
    r'|%252e%252e'
    r'|/etc/passwd'
    r'|/etc/shadow'
    r'|/proc/self'
    r'|php://(?:input|filter|data|fd)'
    r'|file://'
    r'|/windows/win\.ini'
    r'|/winnt/win\.ini'
    r')',
    re.IGNORECASE,
)

# ── IoC: Webshell (rutas conocidas) ──────────────────────────────────────
_RE_WEBSHELL_PATH = re.compile(
    r'(?:'
    r'/c99\.php'
    r'|/r57\.php'
    r'|/shell\.php'
    r'|/cmd\.php'
    r'|/webshell'
    r'|/backdoor\.php'
    r'|/w\.php(?:[?#/]|$)'
    r'|/b374k'
    r'|/antak'
    r'|/indoxploit'
    r'|/alfa\.php'
    r'|/FilesMan\.php'
    r')',
    re.IGNORECASE,
)

# ── IoC: Webshell (parámetros de ejecución remota) ───────────────────────
_RE_WEBSHELL_QUERY = re.compile(
    r'(?:cmd=|exec=|shell=|command=|system=|passthru=|eval=|run=)',
    re.IGNORECASE,
)

# ── IoC: Ficheros sensibles ───────────────────────────────────────────────
_RE_SENSITIVE = re.compile(
    r'(?:'
    r'\.env(?:[/?#\s]|$)'
    r'|\.git/config'
    r'|wp-config\.php'
    r'|config\.php'
    r'|\.htaccess'
    r'|/id_rsa(?:[/?#\s]|$)'
    r'|web\.config'
    r'|phpinfo\.php'
    r'|/\.aws/credentials'
    r'|composer\.json'
    r'|\.htpasswd'
    r'|database\.yml'
    r'|secrets\.yml'
    r'|/etc/passwd'
    r'|\.bash_history'
    r')',
    re.IGNORECASE,
)

# ── IoC: User-Agent de escáner ────────────────────────────────────────────
_RE_SCANNER_UA = re.compile(
    r'(?:'
    r'sqlmap'
    r'|nikto'
    r'|nmap(?:[/\s-]|$)'
    r'|masscan'
    r'|nuclei'
    r'|dirsearch'
    r'|gobuster'
    r'|ffuf'
    r'|wfuzz'
    r'|hydra(?:[/\s]|$)'
    r'|burp(?:suite|\s)'
    r'|zgrab'
    r'|python-requests/[0-9]'
    r'|go-http-client'
    r'|libwww-perl'
    r'|nessus'
    r'|openvas'
    r'|w3af'
    r'|appscan'
    r'|acunetix'
    r'|skipfish'
    r'|zap(?:[/\s]|$)'
    r')',
    re.IGNORECASE,
)

# ── Auth: fallos SSH ──────────────────────────────────────────────────────
_RE_SSH_FAIL = re.compile(
    r'(?:'
    r'Failed password for'
    r'|Invalid user'
    r'|authentication failure'
    r'|Connection closed by.*\[preauth\]'
    r'|maximum authentication attempts exceeded'
    r'|Disconnecting.*\[preauth\]'
    r')',
    re.IGNORECASE,
)

# IP de origen en mensajes SSH
_RE_SSH_SRC_IP = re.compile(
    r'(?:from|rhost=)\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    re.IGNORECASE,
)

# Usuario intentado en SSH
_RE_SSH_USER = re.compile(
    r'(?:for invalid user|for)\s+(\S+)\s+from',
    re.IGNORECASE,
)

# Login root aceptado
_RE_ROOT_LOGIN = re.compile(
    r'Accepted\s+(?:password|publickey)\s+for\s+root\b',
    re.IGNORECASE,
)

# sudo/su: sesión root abierta o comando ejecutado
_RE_SUDO_OPEN = re.compile(
    r'(?:'
    r'sudo\s*:\s*.*session opened for user root'
    r'|su\s*:\s*.*session opened for user root'
    r'|sudo\s*:\s*\S+\s*:.*COMMAND='
    r')',
    re.IGNORECASE,
)

# sudo: fallo de autenticación
_RE_SUDO_FAIL = re.compile(
    r'pam_unix\(sudo:auth\):\s+authentication failure',
    re.IGNORECASE,
)

# Extraer USER= de líneas sudo
_RE_SUDO_USER = re.compile(r'\bUSER=(\S+)', re.IGNORECASE)

# Cron con comandos sospechosos
_RE_CRON_SUSPICIOUS = re.compile(
    r'CRON\b.*CMD\b.*(?:curl\s|wget\s|bash\s|/bin/sh\s|python\d?\s|perl\s|nc\s|ncat\b|netcat\b)',
    re.IGNORECASE,
)

# Meses abreviados para parseo de timestamps syslog
_MONTH_MAP: Dict[str, int] = {
    'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
    'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12,
}

# ---------------------------------------------------------------------------
# Estructuras de datos
# ---------------------------------------------------------------------------

@dataclass
class LogEvent:
    """
    Representa una línea de log que ha coincidido con un patrón IoC.

    Attributes
    ----------
    timestamp       : Fecha/hora del evento (None si no se pudo parsear)
    source_ip       : Dirección IP de origen del evento
    log_file        : Ruta del fichero de log de origen
    raw_line        : Línea original truncada a 400 caracteres
    matched_pattern : Nombre interno del patrón IoC detectado
    """

    timestamp       : Optional[datetime]
    source_ip       : str
    log_file        : str
    raw_line        : str
    matched_pattern : str


@dataclass
class IoCFinding:
    """
    Hallazgo de Indicador de Compromiso detectado en los logs.

    Attributes
    ----------
    id              : Identificador único en formato LOG-NNN
    severity        : CRITICAL | HIGH | MEDIUM | LOW | INFO
    category        : Categoría interna del IoC (brute_ssh, sqli, xss…)
    title           : Título corto del hallazgo (< 100 caracteres)
    description     : Descripción técnica detallada
    source_ips      : Lista de IPs de origen involucradas
    event_count     : Número total de eventos registrados
    first_seen      : Timestamp del primer evento (cadena ISO-8601 o None)
    last_seen       : Timestamp del último evento (cadena ISO-8601 o None)
    evidence_lines  : Hasta 10 líneas de log de muestra como evidencia
    remediation     : Acciones concretas de mitigación recomendadas
    tags            : Etiquetas adicionales (p.ej. "IP conocida de escáner")
    """

    id             : str
    severity       : str
    category       : str
    title          : str
    description    : str
    source_ips     : List[str]
    event_count    : int
    first_seen     : Optional[str]
    last_seen      : Optional[str]
    evidence_lines : List[str]
    remediation    : str
    tags           : List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Funciones auxiliares de parseo
# ---------------------------------------------------------------------------

def _parse_nginx_ts(ts_str: str) -> Optional[datetime]:
    """
    Parsea un timestamp en formato nginx: '10/Oct/2000:13:55:36 -0700'.

    Returns
    -------
    datetime o None si el parseo falla.
    """
    m = _RE_NGINX_TS.match(ts_str)
    if not m:
        return None
    try:
        year  = int(m.group('year'))
        mon   = _MONTH_MAP.get(m.group('mon').lower(), 0)
        day   = int(m.group('day'))
        h, mi, s = map(int, m.group('hms').split(':'))
        tz_str   = m.group('tz')
        sign     = 1 if tz_str[0] == '+' else -1
        tz_off   = timedelta(hours=int(tz_str[1:3]), minutes=int(tz_str[3:5])) * sign
        return datetime(year, mon, day, h, mi, s, tzinfo=timezone(tz_off))
    except (ValueError, KeyError):
        return None


def _parse_syslog_ts(month: str, day: str, time_str: str) -> Optional[datetime]:
    """
    Parsea un timestamp de syslog: 'Jan  1 13:55:36'.

    Asume el año en curso; si el mes es futuro respecto a hoy,
    asume el año anterior.

    Returns
    -------
    datetime sin zona horaria (hora local del sistema) o None.
    """
    try:
        mon   = _MONTH_MAP.get(month[:3].lower(), 0)
        if mon == 0:
            return None
        day_n = int(day.strip())
        h, mi, s = map(int, time_str.split(':'))
        now   = datetime.now()
        year  = now.year if mon <= now.month else now.year - 1
        return datetime(year, mon, day_n, h, mi, s)
    except (ValueError, KeyError):
        return None


def _fmt_ts(ts: Optional[datetime]) -> Optional[str]:
    """Formatea un datetime a cadena ISO-8601 legible, o None."""
    return ts.strftime('%Y-%m-%d %H:%M:%S') if ts else None


def _is_known_scanner(ip: str) -> bool:
    """Comprueba si una IP pertenece a un escáner o red conocida."""
    if ip in _KNOWN_SCANNER_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _KNOWN_SCANNER_CIDRS)
    except ValueError:
        return False


def _detect_log_type(path: str) -> str:
    """
    Detecta el tipo de log a partir del nombre del fichero.

    Returns
    -------
    str : 'nginx', 'apache', 'auth', 'syslog' (fallback)
    """
    name = Path(path).name.lower()
    if name.endswith('.gz'):
        name = name[:-3]

    if any(x in name for x in ('access.log', 'access_log')):
        return 'nginx'
    if 'nginx' in name and 'error' not in name:
        return 'nginx'
    if any(x in name for x in ('apache', 'httpd')) and 'error' not in name:
        return 'apache'
    if any(x in name for x in ('auth.log', 'secure')):
        return 'auth'
    if any(x in name for x in ('syslog', 'messages', 'kern.log')):
        return 'syslog'
    if any(x in name for x in ('journald', 'journal')):
        return 'syslog'
    return 'syslog'


def _discover_log_files(log_dir: str) -> List[Tuple[str, str]]:
    """
    Descubre ficheros de log conocidos en un directorio y sus subdirectorios.

    Returns
    -------
    List[Tuple[str, str]] : Lista de (ruta_absoluta, tipo_detectado)
    """
    results: List[Tuple[str, str]] = []
    seen: Set[str] = set()
    base = Path(log_dir)

    if not base.exists():
        return results

    # Buscar en el directorio base y en subdirectorios habituales
    search_dirs = [base, base / 'nginx', base / 'apache2', base / 'httpd',
                   base / 'auth']

    _KEYWORDS = ('access', 'auth', 'secure', 'syslog', 'messages',
                 'nginx', 'apache', 'httpd')

    for sdir in search_dirs:
        if not sdir.is_dir():
            continue
        for p in sorted(sdir.iterdir()):
            if not p.is_file():
                continue
            if str(p) in seen:
                continue
            name = p.name.lower()
            # Ignorar logs de rotación muy antiguos (.2, .3, ...)
            if re.search(r'\.[2-9]\.gz$|\.[2-9]$', name):
                continue
            for kw in _KEYWORDS:
                if kw in name:
                    seen.add(str(p))
                    results.append((str(p), _detect_log_type(str(p))))
                    break

    return results


# ---------------------------------------------------------------------------
# Motor de análisis de logs
# ---------------------------------------------------------------------------

class LogScanner:
    """
    Motor de escaneo de logs para la detección de IoC.

    Procesa línea a línea (sin cargar el fichero completo en memoria) y
    acumula estado por categoría de ataque. Tras escanear todos los ficheros,
    el método generate_findings() produce la lista final de IoCFinding.
    """

    def __init__(
        self,
        threshold_brute: int,
        threshold_scan:  int,
        last_hours:      int,
        console:         Console,
    ) -> None:
        """
        Parameters
        ----------
        threshold_brute : Número de fallos/4xx para considerar fuerza bruta
        threshold_scan  : Número de rutas únicas para considerar escaneo
        last_hours      : Ventana temporal (0 = sin límite)
        console         : Instancia Rich Console para mensajes de aviso
        """
        self.threshold_brute = threshold_brute
        self.threshold_scan  = threshold_scan
        self.last_hours      = last_hours
        self.console         = console
        self.cutoff: Optional[datetime] = (
            datetime.now() - timedelta(hours=last_hours)
            if last_hours > 0 else None
        )

        # ── Estado acumulado por categoría ────────────────────────────────

        # SSH brute force: ip → {count, first, last, users, lines}
        self._ssh_brute: Dict = defaultdict(lambda: {
            'count': 0, 'first': None, 'last': None,
            'users': set(), 'lines': [],
        })

        # Web brute force: ip → {count, first, last, paths, lines}
        self._web_brute: Dict = defaultdict(lambda: {
            'count': 0, 'first': None, 'last': None,
            'paths': [], 'lines': [],
        })

        # Directory scan: ip → {paths (set), first, last, lines}
        self._dir_scan: Dict = defaultdict(lambda: {
            'paths': set(), 'first': None, 'last': None, 'lines': [],
        })

        # SQL injection: ip → {count, first, last, lines}
        self._sqli: Dict = defaultdict(lambda: {
            'count': 0, 'first': None, 'last': None, 'lines': [],
        })

        # XSS: ip → {count, first, last, lines}
        self._xss: Dict = defaultdict(lambda: {
            'count': 0, 'first': None, 'last': None, 'lines': [],
        })

        # Path traversal / LFI: ip → {count, first, last, lines}
        self._lfi: Dict = defaultdict(lambda: {
            'count': 0, 'first': None, 'last': None, 'lines': [],
        })

        # Webshell: ip → {count, first, last, lines}
        self._webshell: Dict = defaultdict(lambda: {
            'count': 0, 'first': None, 'last': None, 'lines': [],
        })

        # Ficheros sensibles: ip → {count, first, last, files, lines}
        self._sensitive: Dict = defaultdict(lambda: {
            'count': 0, 'first': None, 'last': None,
            'files': set(), 'lines': [],
        })

        # User-Agent escáner: ua_key → {count, first, last, ips, lines}
        self._bad_ua: Dict = defaultdict(lambda: {
            'count': 0, 'first': None, 'last': None,
            'ips': set(), 'lines': [],
        })

        # sudo/su: user → {count_open, count_fail, first, last, lines}
        self._sudo: Dict = defaultdict(lambda: {
            'count_open': 0, 'count_fail': 0,
            'first': None, 'last': None, 'lines': [],
        })

        # Cron sospechoso: lista de {ts, line}
        self._cron: List[Dict] = []

        # Login root: lista de {ts, ip, line}
        self._root: List[Dict] = []

        # Actividad horaria (para anomalía nocturna)
        self._hourly_web:  Dict[int, int] = defaultdict(int)
        self._hourly_ssh:  Dict[int, int] = defaultdict(int)

        # Contadores de escaneo
        self.lines_scanned = 0
        self.files_scanned = 0

    # ── Método público de escaneo ─────────────────────────────────────────

    def scan_file(self, path: str, log_type: str) -> None:
        """
        Escanea un fichero de log en busca de IoC, línea a línea.

        Detecta automáticamente si el fichero está comprimido (.gz).
        Acepta '-' como path para leer desde stdin.

        Parameters
        ----------
        path     : Ruta al fichero (o '-' para stdin)
        log_type : Tipo de log ('nginx', 'apache', 'auth', 'syslog', etc.)
        """
        self.files_scanned += 1

        if path == '-':
            for line in sys.stdin:
                self._process_line(line.rstrip('\n'), path, log_type)
            return

        p = Path(path)
        if not p.exists():
            self.console.print(f"[yellow]⚠  Fichero no encontrado: {path}[/]")
            return

        try:
            if path.endswith('.gz'):
                fh = gzip.open(path, 'rt', encoding='utf-8', errors='replace')
            else:
                fh = open(path, 'r', encoding='utf-8', errors='replace')

            with fh:
                for line in fh:
                    self._process_line(line.rstrip('\n'), path, log_type)

        except (OSError, gzip.BadGzipFile) as exc:
            self.console.print(f"[yellow]⚠  Error leyendo {path}: {exc}[/]")

    # ── Enrutador de líneas ───────────────────────────────────────────────

    def _process_line(self, line: str, source: str, log_type: str) -> None:
        """
        Determina el tipo de línea y llama al analizador correspondiente.
        """
        if not line.strip():
            return
        self.lines_scanned += 1

        if log_type in ('nginx', 'apache'):
            self._scan_access(line, source)
        elif log_type == 'auth':
            self._scan_auth(line, source)
            self._scan_cron(line, source)
        elif log_type in ('syslog', 'journald', 'messages'):
            self._scan_auth(line, source)
            self._scan_cron(line, source)
        else:
            # Tipo desconocido: probar todos los analizadores
            self._scan_access(line, source)
            self._scan_auth(line, source)
            self._scan_cron(line, source)

    # ── Analizador de logs de acceso web ──────────────────────────────────

    def _scan_access(self, line: str, source: str) -> None:
        """
        Analiza una línea de log de acceso nginx/apache (Combined Log Format).

        Detecta: brute web, dir scan, SQLi, XSS, LFI, webshell,
                 ficheros sensibles, User-Agent sospechoso.
        """
        m = _RE_ACCESS.match(line)
        if not m:
            return

        ip     = m.group('ip')
        ts     = _parse_nginx_ts(m.group('ts'))
        path   = m.group('path')
        status = int(m.group('status'))
        ua     = m.group('ua') or ''
        method = m.group('method') or ''

        # Filtrar por ventana temporal
        if self.cutoff and ts and ts.replace(tzinfo=None) < self.cutoff:
            return

        # Conteo horario (para anomalía nocturna)
        if ts:
            self._hourly_web[ts.hour] += 1

        raw = line[:400]

        # ── Brute force web (4xx) ─────────────────────────────────────────
        if status in (401, 403, 404):
            d = self._web_brute[ip]
            d['count'] += 1
            _update_ts(d, ts)
            if len(d['paths']) < 5:
                d['paths'].append(path[:100])
            if len(d['lines']) < 10:
                d['lines'].append(raw)

        # ── Directory scan (404 únicos) ───────────────────────────────────
        if status == 404:
            d = self._dir_scan[ip]
            d['paths'].add(path[:200])
            _update_ts(d, ts)
            if len(d['lines']) < 10:
                d['lines'].append(raw)

        # ── SQL Injection ─────────────────────────────────────────────────
        if _RE_SQLI.search(path):
            d = self._sqli[ip]
            d['count'] += 1
            _update_ts(d, ts)
            if len(d['lines']) < 10:
                d['lines'].append(raw)

        # ── XSS ──────────────────────────────────────────────────────────
        if _RE_XSS.search(path):
            d = self._xss[ip]
            d['count'] += 1
            _update_ts(d, ts)
            if len(d['lines']) < 10:
                d['lines'].append(raw)

        # ── Path Traversal / LFI ──────────────────────────────────────────
        if _RE_LFI.search(path):
            d = self._lfi[ip]
            d['count'] += 1
            _update_ts(d, ts)
            if len(d['lines']) < 10:
                d['lines'].append(raw)

        # ── Webshell ──────────────────────────────────────────────────────
        if _RE_WEBSHELL_PATH.search(path) or (
            method == 'POST' and _RE_WEBSHELL_QUERY.search(path)
        ):
            d = self._webshell[ip]
            d['count'] += 1
            _update_ts(d, ts)
            if len(d['lines']) < 10:
                d['lines'].append(raw)

        # ── Ficheros sensibles ────────────────────────────────────────────
        if _RE_SENSITIVE.search(path):
            d = self._sensitive[ip]
            d['count'] += 1
            _update_ts(d, ts)
            mo = _RE_SENSITIVE.search(path)
            if mo:
                d['files'].add(mo.group(0).strip('/'))
            if len(d['lines']) < 10:
                d['lines'].append(raw)

        # ── User-Agent sospechoso ─────────────────────────────────────────
        if ua:
            mua = _RE_SCANNER_UA.search(ua)
            if mua:
                key = mua.group(0).lower().strip()
                d = self._bad_ua[key]
                d['count'] += 1
                _update_ts(d, ts)
                d['ips'].add(ip)
                if len(d['lines']) < 10:
                    d['lines'].append(raw)

    # ── Analizador de logs de autenticación ───────────────────────────────

    def _scan_auth(self, line: str, source: str) -> None:
        """
        Analiza una línea de auth.log o syslog.

        Detecta: brute SSH, login root, escalada sudo/su.
        """
        m = _RE_SYSLOG.match(line)
        if not m:
            return

        msg = m.group('msg')
        ts  = _parse_syslog_ts(m.group('month'), m.group('day'), m.group('time'))

        if self.cutoff and ts and ts < self.cutoff:
            return

        raw = line[:400]

        # ── Brute force SSH ───────────────────────────────────────────────
        if _RE_SSH_FAIL.search(msg):
            if ts:
                self._hourly_ssh[ts.hour] += 1

            mip  = _RE_SSH_SRC_IP.search(msg)
            ip   = mip.group(1) if mip else 'unknown'
            musr = _RE_SSH_USER.search(msg)
            user = musr.group(1) if musr else 'unknown'

            d = self._ssh_brute[ip]
            d['count'] += 1
            _update_ts(d, ts)
            d['users'].add(user)
            if len(d['lines']) < 10:
                d['lines'].append(raw)

        # ── Login root ────────────────────────────────────────────────────
        if _RE_ROOT_LOGIN.search(msg):
            mip = _RE_SSH_SRC_IP.search(msg)
            self._root.append({
                'ts':   ts,
                'ip':   mip.group(1) if mip else 'unknown',
                'line': raw,
            })

        # ── sudo / su escalación ──────────────────────────────────────────
        if _RE_SUDO_OPEN.search(msg) or _RE_SUDO_FAIL.search(msg):
            musr = _RE_SUDO_USER.search(msg)
            user = musr.group(1) if musr else 'system'

            d = self._sudo[user]
            _update_ts(d, ts)
            if len(d['lines']) < 10:
                d['lines'].append(raw)

            if _RE_SUDO_FAIL.search(msg):
                d['count_fail'] += 1
            else:
                d['count_open'] += 1

    # ── Analizador de cron jobs ───────────────────────────────────────────

    def _scan_cron(self, line: str, source: str) -> None:
        """
        Detecta entradas de cron con comandos de descarga o ejecución remota.
        """
        if not _RE_CRON_SUSPICIOUS.search(line):
            return

        m  = _RE_SYSLOG.match(line)
        ts = _parse_syslog_ts(m.group('month'), m.group('day'), m.group('time')) if m else None

        if self.cutoff and ts and ts < self.cutoff:
            return

        self._cron.append({'ts': ts, 'line': line[:400]})

    # ── Generación de hallazgos ───────────────────────────────────────────

    def generate_findings(self) -> List[IoCFinding]:
        """
        Genera la lista de IoCFinding a partir del estado acumulado.

        Los hallazgos se numeran secuencialmente (LOG-001, LOG-002, …).
        Las IPs pertenecientes a escáneres conocidos reciben la etiqueta
        'IP conocida de escáner' en sus hallazgos.

        Returns
        -------
        List[IoCFinding] ordenada por severidad decreciente.
        """
        findings: List[IoCFinding] = []
        _idx = [1]

        def next_id() -> str:
            fid = f"LOG-{_idx[0]:03d}"
            _idx[0] += 1
            return fid

        def tags_for(ips: List[str]) -> List[str]:
            return ["IP conocida de escáner"] if any(
                _is_known_scanner(ip) for ip in ips
            ) else []

        # ── 1. Fuerza bruta SSH ───────────────────────────────────────────
        for ip, d in sorted(
            self._ssh_brute.items(), key=lambda x: x[1]['count'], reverse=True
        ):
            if d['count'] < self.threshold_brute:
                continue
            users = sorted(d['users'])[:8]
            findings.append(IoCFinding(
                id=next_id(),
                severity="HIGH",
                category="brute_ssh",
                title=f"Fuerza bruta SSH desde {ip} ({d['count']} intentos)",
                description=(
                    f"La IP {ip} ha realizado {d['count']} intentos fallidos de "
                    f"autenticación SSH (umbral configurado: {self.threshold_brute}). "
                    f"Usuarios atacados: {', '.join(users)}. "
                    "Comportamiento consistente con ataques automatizados de diccionario."
                ),
                source_ips=[ip],
                event_count=d['count'],
                first_seen=_fmt_ts(d['first']),
                last_seen=_fmt_ts(d['last']),
                evidence_lines=d['lines'][:10],
                remediation=(
                    "1. Bloquear la IP con: ufw deny from {ip} to any. "
                    "2. Habilitar fail2ban con jail SSH (bantime ≥ 3600s). "
                    "3. Revisar auth.log por logins exitosos de la IP. "
                    "4. Configurar PasswordAuthentication no en sshd_config. "
                    "5. Implementar Port Knocking o acceso SSH solo por VPN."
                ).replace('{ip}', ip),
                tags=tags_for([ip]),
            ))

        # ── 2. Fuerza bruta Web ───────────────────────────────────────────
        for ip, d in sorted(
            self._web_brute.items(), key=lambda x: x[1]['count'], reverse=True
        ):
            if d['count'] < self.threshold_brute:
                continue
            findings.append(IoCFinding(
                id=next_id(),
                severity="HIGH",
                category="brute_web",
                title=f"Fuerza bruta HTTP desde {ip} ({d['count']} respuestas 4xx)",
                description=(
                    f"La IP {ip} ha recibido {d['count']} respuestas de error HTTP "
                    f"4xx (umbral: {self.threshold_brute}). "
                    f"Rutas más frecuentes: {', '.join(d['paths'][:5])}. "
                    "Indica enumeración o ataque de credenciales automatizado."
                ),
                source_ips=[ip],
                event_count=d['count'],
                first_seen=_fmt_ts(d['first']),
                last_seen=_fmt_ts(d['last']),
                evidence_lines=d['lines'][:10],
                remediation=(
                    "1. Configurar rate limiting en nginx: limit_req_zone. "
                    "2. Añadir la IP a la lista de bloqueo del WAF o firewall. "
                    "3. Habilitar fail2ban con jail nginx-http-auth. "
                    "4. Revisar si algún recurso sensible fue accedido con código 200."
                ),
                tags=tags_for([ip]),
            ))

        # ── 3. Escaneo de directorios ─────────────────────────────────────
        for ip, d in sorted(
            self._dir_scan.items(), key=lambda x: len(x[1]['paths']), reverse=True
        ):
            if len(d['paths']) < self.threshold_scan:
                continue
            findings.append(IoCFinding(
                id=next_id(),
                severity="HIGH",
                category="dir_scan",
                title=(
                    f"Escaneo de directorios desde {ip} "
                    f"({len(d['paths'])} rutas únicas con 404)"
                ),
                description=(
                    f"La IP {ip} ha solicitado {len(d['paths'])} rutas únicas "
                    f"que devolvieron 404 (umbral: {self.threshold_scan}). "
                    "Comportamiento consistente con herramientas como dirsearch, "
                    "gobuster, ffuf o wfuzz buscando recursos ocultos."
                ),
                source_ips=[ip],
                event_count=len(d['paths']),
                first_seen=_fmt_ts(d['first']),
                last_seen=_fmt_ts(d['last']),
                evidence_lines=d['lines'][:10],
                remediation=(
                    "1. Implementar rate limiting estricto por IP en nginx/apache. "
                    "2. Bloquear la IP en el firewall. "
                    "3. Auditar qué endpoints devolvieron respuestas 200. "
                    "4. Configurar return 444 para IPs con comportamiento anómalo."
                ),
                tags=tags_for([ip]),
            ))

        # ── 4. Inyección SQL ──────────────────────────────────────────────
        for ip, d in sorted(
            self._sqli.items(), key=lambda x: x[1]['count'], reverse=True
        ):
            findings.append(IoCFinding(
                id=next_id(),
                severity="CRITICAL",
                category="sqli",
                title=f"Inyección SQL desde {ip} ({d['count']} peticiones)",
                description=(
                    f"La IP {ip} ha enviado {d['count']} peticiones con patrones "
                    "de inyección SQL en la URI (UNION SELECT, OR 1=1, DROP TABLE, "
                    "xp_cmdshell, information_schema, etc.). "
                    "Riesgo crítico de exfiltración o corrupción de base de datos."
                ),
                source_ips=[ip],
                event_count=d['count'],
                first_seen=_fmt_ts(d['first']),
                last_seen=_fmt_ts(d['last']),
                evidence_lines=d['lines'][:10],
                remediation=(
                    "1. Bloquear la IP de inmediato en el firewall. "
                    "2. Auditar los logs de la base de datos en el rango temporal. "
                    "3. Revisar el código de la aplicación e implementar "
                    "   prepared statements / consultas parametrizadas. "
                    "4. Desplegar WAF con OWASP Core Rule Set (ModSecurity/Coraza). "
                    "5. Verificar integridad de datos en tablas críticas."
                ),
                tags=tags_for([ip]),
            ))

        # ── 5. XSS ───────────────────────────────────────────────────────
        for ip, d in sorted(
            self._xss.items(), key=lambda x: x[1]['count'], reverse=True
        ):
            findings.append(IoCFinding(
                id=next_id(),
                severity="HIGH",
                category="xss",
                title=f"Intento de XSS desde {ip} ({d['count']} peticiones)",
                description=(
                    f"La IP {ip} ha enviado {d['count']} peticiones con payloads "
                    "de Cross-Site Scripting en la URI (<script>, javascript:, "
                    "onerror=, alert(), document.cookie, etc.). "
                    "Riesgo de robo de sesión, defacement o redirección maliciosa."
                ),
                source_ips=[ip],
                event_count=d['count'],
                first_seen=_fmt_ts(d['first']),
                last_seen=_fmt_ts(d['last']),
                evidence_lines=d['lines'][:10],
                remediation=(
                    "1. Implementar Content-Security-Policy (CSP) estricta. "
                    "2. Sanitizar y escapar toda entrada de usuario en el servidor. "
                    "3. Configurar cabeceras: X-XSS-Protection, X-Content-Type-Options. "
                    "4. Desplegar WAF con reglas anti-XSS del OWASP CRS."
                ),
                tags=tags_for([ip]),
            ))

        # ── 6. Path Traversal / LFI ───────────────────────────────────────
        for ip, d in sorted(
            self._lfi.items(), key=lambda x: x[1]['count'], reverse=True
        ):
            findings.append(IoCFinding(
                id=next_id(),
                severity="HIGH",
                category="lfi",
                title=f"Path Traversal / LFI desde {ip} ({d['count']} peticiones)",
                description=(
                    f"La IP {ip} ha enviado {d['count']} peticiones con patrones "
                    "de path traversal o Local File Inclusion (../../, /etc/passwd, "
                    "php://filter, %252e%252e, etc.). "
                    "Riesgo de lectura de ficheros sensibles del sistema."
                ),
                source_ips=[ip],
                event_count=d['count'],
                first_seen=_fmt_ts(d['first']),
                last_seen=_fmt_ts(d['last']),
                evidence_lines=d['lines'][:10],
                remediation=(
                    "1. Normalizar y validar todas las rutas de fichero. "
                    "2. Implementar open_basedir en PHP y chroot para la app web. "
                    "3. Desactivar allow_url_include y allow_url_fopen en PHP. "
                    "4. Bloquear la IP y desplegar WAF con reglas LFI."
                ),
                tags=tags_for([ip]),
            ))

        # ── 7. Webshell / Shell remota ────────────────────────────────────
        for ip, d in sorted(
            self._webshell.items(), key=lambda x: x[1]['count'], reverse=True
        ):
            findings.append(IoCFinding(
                id=next_id(),
                severity="CRITICAL",
                category="webshell",
                title=f"Posible webshell detectada — acceso desde {ip}",
                description=(
                    f"La IP {ip} ha realizado {d['count']} peticiones a rutas de "
                    "webshell conocidas o con parámetros de ejecución remota "
                    "(cmd=, exec=, /c99.php, /r57.php, /shell.php, etc.). "
                    "Riesgo crítico: posible compromiso total del servidor."
                ),
                source_ips=[ip],
                event_count=d['count'],
                first_seen=_fmt_ts(d['first']),
                last_seen=_fmt_ts(d['last']),
                evidence_lines=d['lines'][:10],
                remediation=(
                    "ACCIÓN INMEDIATA: "
                    "1. Verificar si el fichero existe: "
                    "   find /var/www -name '*.php' -newer /var/www/html/index.php. "
                    "2. Buscar procesos hijos del servidor web: "
                    "   ps -ef | grep www-data. "
                    "3. Aislar el servidor hasta confirmar ausencia de compromiso. "
                    "4. Revisar integridad de ficheros con aide o tripwire. "
                    "5. Auditar logs de base de datos y ficheros creados recientemente."
                ),
                tags=tags_for([ip]),
            ))

        # ── 8. Ficheros sensibles ─────────────────────────────────────────
        for ip, d in sorted(
            self._sensitive.items(), key=lambda x: x[1]['count'], reverse=True
        ):
            files = list(d['files'])[:8]
            findings.append(IoCFinding(
                id=next_id(),
                severity="HIGH",
                category="sensitive_files",
                title=(
                    f"Acceso a ficheros sensibles desde {ip} "
                    f"({d['count']} peticiones)"
                ),
                description=(
                    f"La IP {ip} ha solicitado {d['count']} veces ficheros de "
                    "configuración, credenciales o claves privadas: "
                    f"{', '.join(files)}. "
                    "Riesgo de exposición de contraseñas, tokens o claves SSH."
                ),
                source_ips=[ip],
                event_count=d['count'],
                first_seen=_fmt_ts(d['first']),
                last_seen=_fmt_ts(d['last']),
                evidence_lines=d['lines'][:10],
                remediation=(
                    "1. Verificar que los ficheros NO son accesibles públicamente. "
                    "2. Añadir reglas deny en nginx/apache para .env, .git, etc.: "
                    "   location ~* /\\.(env|git|htaccess) { deny all; }. "
                    "3. Revisar si alguna petición recibió respuesta 200. "
                    "4. Rotar inmediatamente cualquier credencial potencialmente expuesta."
                ),
                tags=tags_for([ip]),
            ))

        # ── 9. User-Agent de escáner ──────────────────────────────────────
        for ua_key, d in sorted(
            self._bad_ua.items(), key=lambda x: x[1]['count'], reverse=True
        ):
            ips = list(d['ips'])[:10]
            findings.append(IoCFinding(
                id=next_id(),
                severity="MEDIUM",
                category="scanner_ua",
                title=f"User-Agent de escáner detectado: {ua_key}",
                description=(
                    f"Se han detectado {d['count']} peticiones con el User-Agent "
                    f"'{ua_key}', asociado a herramientas de escaneo automático. "
                    f"IPs de origen: {', '.join(ips[:5])}."
                ),
                source_ips=ips,
                event_count=d['count'],
                first_seen=_fmt_ts(d['first']),
                last_seen=_fmt_ts(d['last']),
                evidence_lines=d['lines'][:10],
                remediation=(
                    "1. Bloquear las IPs de origen en el firewall. "
                    "2. Configurar filtrado por User-Agent en el servidor web o WAF. "
                    "3. Revisar qué endpoints fueron alcanzados y con qué resultado. "
                    "4. Considerar bloqueo proactivo de rangos ASN de escáneres."
                ),
                tags=tags_for(ips),
            ))

        # ── 10. Escalada sudo/su ──────────────────────────────────────────
        for user, d in sorted(
            self._sudo.items(),
            key=lambda x: x[1]['count_open'] + x[1]['count_fail'],
            reverse=True,
        ):
            total = d['count_open'] + d['count_fail']
            if total <= 5 and d['count_fail'] <= 3:
                continue
            severity = "HIGH" if d['count_fail'] > 3 else "MEDIUM"
            findings.append(IoCFinding(
                id=next_id(),
                severity=severity,
                category="priv_escalation",
                title=(
                    f"Actividad de escalada de privilegios — usuario '{user}'"
                ),
                description=(
                    f"El usuario '{user}' ha abierto {d['count_open']} sesiones "
                    f"sudo/su a root y ha fallado la autenticación {d['count_fail']} veces. "
                    "Volumen por encima del umbral normal de actividad administrativa."
                ),
                source_ips=[],
                event_count=total,
                first_seen=_fmt_ts(d['first']),
                last_seen=_fmt_ts(d['last']),
                evidence_lines=d['lines'][:10],
                remediation=(
                    "1. Verificar legitimidad de las sesiones sudo del usuario. "
                    "2. Auditar el historial de comandos: /home/{user}/.bash_history. "
                    "3. Comprobar que el usuario tenga acceso correcto en /etc/sudoers. "
                    "4. Revisar si se añadieron claves SSH o cuentas durante las sesiones."
                ).replace('{user}', user),
                tags=[],
            ))

        # ── 11. Cron jobs sospechosos ─────────────────────────────────────
        if self._cron:
            lines = [e['line'] for e in self._cron[:10]]
            findings.append(IoCFinding(
                id=next_id(),
                severity="HIGH",
                category="suspicious_cron",
                title=(
                    f"Cron jobs con comandos sospechosos "
                    f"({len(self._cron)} entradas)"
                ),
                description=(
                    f"Se han detectado {len(self._cron)} entradas de cron con "
                    "comandos de descarga o ejecución remota (curl, wget, bash, "
                    "nc, python, perl). Posible mecanismo de persistencia de malware."
                ),
                source_ips=[],
                event_count=len(self._cron),
                first_seen=_fmt_ts(self._cron[0]['ts']),
                last_seen=_fmt_ts(self._cron[-1]['ts']),
                evidence_lines=lines,
                remediation=(
                    "1. Revisar crontabs: crontab -l; cat /etc/crontab; "
                    "   ls -la /etc/cron.*. "
                    "2. Eliminar entradas no autorizadas. "
                    "3. Buscar scripts descargados en /tmp, /dev/shm, /var/tmp. "
                    "4. Auditar procesos iniciados desde el usuario del cron job."
                ),
                tags=[],
            ))

        # ── 12. Login root directo ────────────────────────────────────────
        if self._root:
            ips  = list({e['ip'] for e in self._root})[:10]
            evl  = [e['line'] for e in self._root[:10]]
            findings.append(IoCFinding(
                id=next_id(),
                severity="HIGH",
                category="root_login",
                title=(
                    f"Login SSH directo como root "
                    f"({len(self._root)} veces)"
                ),
                description=(
                    f"Se han detectado {len(self._root)} inicios de sesión SSH "
                    f"directos como root desde: {', '.join(ips)}. "
                    "El acceso directo como root viola el principio de mínimo "
                    "privilegio y dificulta la auditoría de acciones realizadas."
                ),
                source_ips=ips,
                event_count=len(self._root),
                first_seen=_fmt_ts(self._root[0]['ts']),
                last_seen=_fmt_ts(self._root[-1]['ts']),
                evidence_lines=evl,
                remediation=(
                    "1. Deshabilitar login root: PermitRootLogin no en sshd_config. "
                    "2. Usar cuentas personales + sudo para operaciones administrativas. "
                    "3. Verificar legitimidad de las IPs de origen. "
                    "4. Auditar comandos ejecutados durante las sesiones root."
                ),
                tags=tags_for(ips),
            ))

        # ── 13. IPs de escáneres conocidos (sin otro hallazgo previo) ─────
        all_flagged = {ip for f in findings for ip in f.source_ips}
        scanner_ips_new: Set[str] = set()

        for ip in list(self._web_brute) + list(self._dir_scan):
            if _is_known_scanner(ip) and ip not in all_flagged:
                scanner_ips_new.add(ip)

        if scanner_ips_new:
            ip_list = sorted(scanner_ips_new)[:15]
            findings.append(IoCFinding(
                id=next_id(),
                severity="MEDIUM",
                category="known_scanner",
                title=(
                    f"IPs de escáneres conocidos detectadas "
                    f"({len(scanner_ips_new)} IPs)"
                ),
                description=(
                    f"Se han detectado {len(scanner_ips_new)} IPs pertenecientes a "
                    "redes de escáneres públicos (Shodan, Censys, GreyNoise, etc.) "
                    "cuya actividad no superó otros umbrales de alerta: "
                    f"{', '.join(ip_list)}."
                ),
                source_ips=ip_list,
                event_count=len(scanner_ips_new),
                first_seen=None,
                last_seen=None,
                evidence_lines=[],
                remediation=(
                    "1. Considerar bloqueo proactivo de rangos ASN de escáneres. "
                    "2. Revisar política de exposición de servicios públicos. "
                    "3. Configurar robots.txt y ocultar banners de versión."
                ),
                tags=["IP conocida de escáner"],
            ))

        # ── 14. Actividad nocturna anómala ────────────────────────────────
        night_web = sum(self._hourly_web[h] for h in range(2, 6))
        day_web   = sum(self._hourly_web[h] for h in list(range(0, 2)) + list(range(6, 24)))
        avg_day   = day_web / 20 if day_web > 0 else 0

        if night_web > 0 and night_web > max(100, avg_day * 4 * 3):
            findings.append(IoCFinding(
                id=next_id(),
                severity="MEDIUM",
                category="night_anomaly",
                title=(
                    f"Actividad web nocturna anómala (02:00-05:59) "
                    f"— {night_web} peticiones"
                ),
                description=(
                    f"Se han detectado {night_web} peticiones HTTP entre las "
                    f"02:00-05:59, muy por encima de la media horaria diurna "
                    f"({avg_day:.0f}/h). "
                    "La actividad intensa en horas de mínimo uso puede indicar "
                    "ataques automatizados, exfiltración de datos o acceso no autorizado."
                ),
                source_ips=[],
                event_count=night_web,
                first_seen=None,
                last_seen=None,
                evidence_lines=[],
                remediation=(
                    "1. Revisar los logs de acceso de 02:00-05:59 para identificar la IP. "
                    "2. Implementar alertas de monitorización por umbral nocturno. "
                    "3. Considerar rate limiting más estricto fuera del horario laboral."
                ),
                tags=[],
            ))

        night_ssh = sum(self._hourly_ssh[h] for h in range(2, 6))
        day_ssh   = sum(self._hourly_ssh[h] for h in list(range(0, 2)) + list(range(6, 24)))
        avg_ssh   = day_ssh / 20 if day_ssh > 0 else 0

        if night_ssh > 0 and night_ssh > max(20, avg_ssh * 4 * 3):
            findings.append(IoCFinding(
                id=next_id(),
                severity="MEDIUM",
                category="night_anomaly_ssh",
                title=(
                    f"Actividad SSH nocturna anómala (02:00-05:59) "
                    f"— {night_ssh} fallos"
                ),
                description=(
                    f"Se han detectado {night_ssh} fallos de autenticación SSH "
                    f"entre las 02:00-05:59, muy por encima de la media horaria "
                    f"({avg_ssh:.0f}/h). "
                    "Posible ataque de fuerza bruta automatizado en horario de baja vigilancia."
                ),
                source_ips=[],
                event_count=night_ssh,
                first_seen=None,
                last_seen=None,
                evidence_lines=[],
                remediation=(
                    "1. Revisar auth.log de 02:00-05:59 para identificar la IP. "
                    "2. Habilitar fail2ban con jail SSH si no está activo. "
                    "3. Considerar bloqueo temporal de IPs con muchos intentos nocturnos."
                ),
                tags=[],
            ))

        # Ordenar: CRITICAL → HIGH → MEDIUM → LOW → INFO
        _ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda f: _ORDER.get(f.severity, 99))
        return findings


# ---------------------------------------------------------------------------
# Función auxiliar: actualizar first/last timestamp
# ---------------------------------------------------------------------------

def _update_ts(d: dict, ts: Optional[datetime]) -> None:
    """Actualiza los campos 'first' y 'last' de un diccionario de estado."""
    if ts is None:
        return
    if d['first'] is None or ts < d['first']:
        d['first'] = ts
    if d['last'] is None or ts > d['last']:
        d['last'] = ts


# ---------------------------------------------------------------------------
# Funciones de salida en consola (Rich)
# ---------------------------------------------------------------------------

def _print_banner(console: Console) -> None:
    """Muestra el banner de inicio de vamp-log-hunter."""
    console.print()
    console.print(
        "[bold red]╔══╗  ╔═╗ ╔╗╔╗ ╔══╗[/]  "
        "[bold white]LOG HUNTER[/]"
    )
    console.print(
        "[bold red]╚══╗  ╠═╣ ║╚╝║ ╠══╝[/]  "
        f"[dim]v{VERSION} · VampSecure Labs[/]"
    )
    console.print(
        "[bold red]═══╝  ╩ ╩ ╩  ╩ ╩    [/]  "
        "[dim]Cazador de IoC en Logs del Sistema[/]"
    )
    console.print(f"[dim]{AUTHOR}[/]")
    console.print()


def _print_summary(
    console: Console,
    findings: List[IoCFinding],
    scanner: LogScanner,
) -> None:
    """Muestra tabla de estadísticas de escaneo y distribución de hallazgos."""
    console.print(Rule("[bold]Estadísticas de análisis[/]", style="dim"))
    console.print(
        f"  Ficheros analizados : [cyan]{scanner.files_scanned}[/]   "
        f"Líneas procesadas : [cyan]{scanner.lines_scanned:,}[/]   "
        f"Hallazgos totales : [cyan]{len(findings)}[/]"
    )
    console.print()

    if not findings:
        console.print(Panel(
            "[bold green]✓  Sin IoC detectados en los logs analizados.[/]",
            border_style="green",
            padding=(1, 4),
        ))
        return

    # Tabla de distribución por severidad
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    sev_tbl = Table(box=box.ROUNDED, border_style="dim", title="Distribución por Severidad")
    sev_tbl.add_column("Severidad", style="bold")
    sev_tbl.add_column("Hallazgos", justify="right", style="white")

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in counts:
            sev_tbl.add_row(Text(sev, style=_SEV_RICH[sev]), str(counts[sev]))

    console.print(sev_tbl)
    console.print()

    # Top IPs ofensivas
    ip_counts: Dict[str, int] = defaultdict(int)
    for f in findings:
        for ip in f.source_ips:
            ip_counts[ip] += f.event_count

    if ip_counts:
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ip_tbl = Table(box=box.ROUNDED, border_style="dim", title="Top IPs Ofensivas")
        ip_tbl.add_column("IP Origen",          style="cyan")
        ip_tbl.add_column("Eventos totales",     justify="right")
        ip_tbl.add_column("Escáner conocido",    justify="center")

        for ip, cnt in top_ips:
            ip_tbl.add_row(
                ip,
                str(cnt),
                "[bold red]SÍ[/]" if _is_known_scanner(ip) else "[dim]—[/]",
            )

        console.print(ip_tbl)
        console.print()


def _print_findings(console: Console, findings: List[IoCFinding]) -> None:
    """Muestra los hallazgos detallados en paneles Rich."""
    if not findings:
        return

    console.print(Rule("[bold]Hallazgos Detallados[/]", style="dim"))
    console.print()

    for f in findings:
        color  = _SEV_RICH.get(f.severity, "white")
        border = _SEV_BORDER.get(f.severity, "dim")

        lines: List[str] = []
        lines.append(f"[dim]{f.id}[/]  [{color}]{f.severity}[/]  "
                     f"[dim]Categoría: {f.category}[/]")

        if f.tags:
            lines.append(f"[dim]Etiquetas: {', '.join(f.tags)}[/]")

        lines.append("")
        lines.append(f"[white]{f.description}[/]")

        meta: List[str] = []
        if f.source_ips:
            meta.append(f"IPs origen: [cyan]{', '.join(f.source_ips[:5])}[/]")
        meta.append(f"Eventos: [cyan]{f.event_count}[/]")
        if f.first_seen:
            meta.append(f"Primer evento: [cyan]{f.first_seen}[/]")
        if f.last_seen:
            meta.append(f"Último evento: [cyan]{f.last_seen}[/]")

        if meta:
            lines.append("  " + "   ".join(meta))

        if f.evidence_lines:
            lines.append("")
            lines.append("[dim]─── Evidencia (muestra) ───[/]")
            for ev in f.evidence_lines[:5]:
                lines.append(f"[dim]{ev[:200]}[/]")

        lines.append("")
        lines.append(f"[green]Remediación:[/] {f.remediation}")

        console.print(Panel(
            "\n".join(lines),
            title=f"[{color}]{f.title}[/]",
            border_style=border,
            padding=(1, 2),
        ))
        console.print()


# ---------------------------------------------------------------------------
# Exportación JSON
# ---------------------------------------------------------------------------

def _save_json(findings: List[IoCFinding], path: str) -> None:
    """
    Exporta todos los hallazgos en formato JSON estructurado VSL.

    El esquema incluye: schema, herramienta, versión, fecha de generación,
    total de hallazgos y el array completo de findings con todos sus campos.
    """
    data = {
        "schema":         f"{TOOL_NAME}-v{VERSION}",
        "tool":           TOOL_NAME,
        "version":        VERSION,
        "generated":      datetime.now().isoformat(),
        "total_findings": len(findings),
        "findings": [
            {
                "id":             f.id,
                "severity":       f.severity,
                "category":       f.category,
                "title":          f.title,
                "description":    f.description,
                "source_ips":     f.source_ips,
                "event_count":    f.event_count,
                "first_seen":     f.first_seen,
                "last_seen":      f.last_seen,
                "evidence_lines": f.evidence_lines,
                "remediation":    f.remediation,
                "tags":           f.tags,
            }
            for f in findings
        ],
    }
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


# ---------------------------------------------------------------------------
# Exportación HTML (tema oscuro, standalone)
# ---------------------------------------------------------------------------

def _save_html(findings: List[IoCFinding], path: str) -> None:
    """
    Genera un informe HTML con tema oscuro completamente standalone.

    No depende de ningún CDN ni librería externa. Incluye:
    resumen ejecutivo con KPIs, tabla de hallazgos y tarjetas detalladas.
    """
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    def _e(s: str) -> str:
        """Escapa HTML para evitar XSS en las líneas de evidencia."""
        return _html_module.escape(str(s))

    # KPIs HTML
    kpi_html = ""
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in counts:
            css = _SEV_CSS[sev]
            kpi_html += (
                f'<div class="kpi" style="border-top:3px solid {css}">'
                f'<div class="kv" style="color:{css}">{counts[sev]}</div>'
                f'<div class="kl">{sev}</div>'
                f'</div>'
            )

    # Tabla de hallazgos HTML
    rows_html = ""
    for i, f in enumerate(findings, 1):
        css = _SEV_CSS.get(f.severity, "#888")
        ips = ", ".join(f.source_ips[:3]) or "—"
        rows_html += (
            f'<tr>'
            f'<td style="color:#555">{i}</td>'
            f'<td><code>{_e(f.id)}</code></td>'
            f'<td><strong>{_e(f.title[:80])}</strong></td>'
            f'<td><span class="badge" style="background:{css}">{_e(f.severity)}</span></td>'
            f'<td style="color:#888;font-size:.82em">{_e(ips)}</td>'
            f'<td style="color:#888;font-size:.8em">{_e(f.event_count)}</td>'
            f'</tr>\n'
        )
    if not rows_html:
        rows_html = '<tr><td colspan="6" style="text-align:center;color:#555;padding:24px">Sin hallazgos</td></tr>'

    # Tarjetas de hallazgo detallado
    cards_html = ""
    for f in findings:
        css    = _SEV_CSS.get(f.severity, "#888")
        ips_s  = ", ".join(f.source_ips[:5]) or "—"
        tags_s = (
            f'<div class="tags">'
            + "".join(f'<span class="tag">{_e(t)}</span>' for t in f.tags)
            + '</div>'
        ) if f.tags else ""

        ev_html = ""
        if f.evidence_lines:
            ev_lines = "\n".join(_e(l) for l in f.evidence_lines[:5])
            ev_html = f'<div class="ev-block"><pre>{ev_lines}</pre></div>'

        ts_html = ""
        if f.first_seen:
            ts_html += f'<span>Primer evento: <strong>{_e(f.first_seen)}</strong></span> '
        if f.last_seen:
            ts_html += f'<span>Último evento: <strong>{_e(f.last_seen)}</strong></span> '

        cards_html += f"""
<div class="card" style="border-left:4px solid {css}">
  <div class="card-head">
    <span class="card-id">{_e(f.id)}</span>
    <span class="badge" style="background:{css}">{_e(f.severity)}</span>
    <span class="card-title">{_e(f.title)}</span>
  </div>
  {tags_s}
  <div class="card-body">
    <p class="desc">{_e(f.description)}</p>
    <div class="meta">
      {'<span>IPs: <strong>' + _e(ips_s) + '</strong></span>' if f.source_ips else ''}
      <span>Eventos: <strong>{_e(f.event_count)}</strong></span>
      {ts_html}
    </div>
    {ev_html}
    <div class="rem">
      <span class="rem-lbl">Remediación</span>
      <p>{_e(f.remediation)}</p>
    </div>
  </div>
</div>
"""

    total = len(findings)
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{TOOL_NAME} — Informe IoC — {now_str[:10]}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
     background:#0d0d17;color:#c8c8d8;line-height:1.65;font-size:14px}}
a{{color:#7aaef8}}
code{{font-family:'Courier New',monospace;background:#1a1a2e;
     padding:1px 5px;border-radius:3px;font-size:.88em;color:#a0d0f0}}
pre{{background:#111122;border:1px solid #222240;border-radius:4px;
    padding:10px 14px;font-size:.78em;white-space:pre-wrap;word-break:break-all;
    line-height:1.5;font-family:'Courier New',monospace;color:#88aacc;
    max-height:220px;overflow-y:auto}}
.wrap{{max-width:1040px;margin:0 auto;padding:0 0 40px}}

/* Cabecera */
.hdr{{background:linear-gradient(135deg,#0d0d17 0%,#1a0a0a 50%,#2d0000 100%);
     border-bottom:2px solid #c0392b;padding:32px 40px 24px}}
.hdr-brand{{font-size:.72em;letter-spacing:3px;text-transform:uppercase;
           color:#c0392b;margin-bottom:8px}}
.hdr-title{{font-size:1.7em;font-weight:700;color:#fff;margin-bottom:4px}}
.hdr-sub{{font-size:.85em;color:#888}}

/* Secciones */
.sec{{padding:28px 40px;border-bottom:1px solid #1a1a2e}}
.sec:last-child{{border-bottom:none}}
.sec-title{{font-size:.8em;font-weight:700;color:#c0392b;text-transform:uppercase;
           letter-spacing:.8px;margin-bottom:18px;display:flex;align-items:center;gap:10px}}
.sec-title::after{{content:'';flex:1;height:1px;background:#1e1e35}}

/* KPIs */
.kpis{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}}
.kpi{{background:#12121f;border:1px solid #1e1e35;border-radius:6px;
     padding:14px 20px;min-width:108px;text-align:center}}
.kv{{font-size:2em;font-weight:700}}
.kl{{font-size:.68em;color:#666;text-transform:uppercase;letter-spacing:.5px;margin-top:2px}}

/* Badge severidad */
.badge{{display:inline-block;padding:2px 9px;border-radius:3px;
       font-size:.72em;font-weight:700;letter-spacing:.3px;color:#fff}}

/* Tabla */
table{{width:100%;border-collapse:collapse;font-size:.83em}}
th{{background:#111122;color:#555;padding:8px 10px;text-align:left;
   border-bottom:2px solid #1e1e35;font-size:.75em;text-transform:uppercase;
   letter-spacing:.4px;font-weight:700}}
td{{padding:8px 10px;border-bottom:1px solid #131320;vertical-align:top}}
tr:hover td{{background:#0f0f1e}}

/* Tarjetas */
.card{{background:#0f0f1e;border:1px solid #1a1a2e;border-radius:6px;
      margin:14px 0;overflow:hidden}}
.card-head{{padding:11px 16px;background:#0a0a15;display:flex;
           align-items:center;gap:10px;flex-wrap:wrap}}
.card-id{{font-size:.75em;color:#444;font-family:'Courier New',monospace;font-weight:700}}
.card-title{{flex:1;font-weight:700;color:#ddd;font-size:.92em}}
.card-body{{padding:14px 18px}}
.desc{{color:#aaa;margin-bottom:10px;font-size:.88em}}
.meta{{font-size:.78em;color:#555;display:flex;gap:14px;flex-wrap:wrap;margin-bottom:10px}}
.meta strong{{color:#888}}
.tags{{padding:4px 18px;display:flex;gap:6px;flex-wrap:wrap}}
.tag{{background:#1e1e0a;border:1px solid #444400;color:#aaa800;
     font-size:.7em;padding:2px 8px;border-radius:3px}}
.ev-block{{margin:10px 0}}
.rem{{margin-top:12px;background:#0d1a0d;border:1px solid #1a2e1a;
     border-radius:4px;padding:10px 14px}}
.rem-lbl{{font-size:.68em;color:#3d7a3d;text-transform:uppercase;letter-spacing:.5px;
         font-weight:700;display:block;margin-bottom:4px}}
.rem p{{font-size:.82em;color:#7aaa7a;line-height:1.55}}

/* Pie */
.footer{{background:#080810;border-top:1px solid #1a1a2e;padding:14px 40px;
        font-size:.7em;color:#333;display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px}}
</style>
</head>
<body>
<div class="wrap">

<div class="hdr">
  <div class="hdr-brand">&#9679; VampSecure Labs — Security Research Division</div>
  <div class="hdr-title">Informe de Indicadores de Compromiso</div>
  <div class="hdr-sub">
    {_e(TOOL_NAME)} v{_e(VERSION)} &nbsp;·&nbsp;
    Generado: {_e(now_str)} &nbsp;·&nbsp;
    Hallazgos: <strong>{total}</strong>
  </div>
</div>

<div class="sec">
  <div class="sec-title">Resumen ejecutivo</div>
  <div class="kpis">
    <div class="kpi" style="border-top:3px solid #c0392b">
      <div class="kv" style="color:#fff">{total}</div>
      <div class="kl">Total</div>
    </div>
    {kpi_html}
  </div>
</div>

<div class="sec">
  <div class="sec-title">Tabla de hallazgos</div>
  <table>
    <tr>
      <th>#</th><th>ID</th><th>Hallazgo</th>
      <th>Severidad</th><th>IPs origen</th><th>Eventos</th>
    </tr>
    {rows_html}
  </table>
</div>

<div class="sec">
  <div class="sec-title">Hallazgos detallados</div>
  {cards_html if cards_html else '<p style="color:#444;text-align:center;padding:20px">Sin hallazgos detectados.</p>'}
</div>

<div class="footer">
  <span>{_e(AUTHOR)}</span>
  <span>CONFIDENCIAL — Uso exclusivo en entornos autorizados.</span>
</div>

</div>
</body>
</html>"""

    Path(path).write_text(html, encoding="utf-8")


# ---------------------------------------------------------------------------
# Conversión al formato VSL unificado
# ---------------------------------------------------------------------------

def _to_vsl(findings: List[IoCFinding]) -> List[VSLFinding]:
    """
    Convierte los hallazgos internos (IoCFinding) al formato VSLFinding
    del módulo de informes unificado vampsec_report.

    Parameters
    ----------
    findings : Lista de IoCFinding generados por LogScanner

    Returns
    -------
    List[VSLFinding] ordenada por severidad (heredada de findings)
    """
    result: List[VSLFinding] = []

    for f in findings:
        ev_parts: List[str] = []
        if f.first_seen:
            ev_parts.append(f"Primer evento : {f.first_seen}")
        if f.last_seen:
            ev_parts.append(f"Último evento  : {f.last_seen}")
        if f.source_ips:
            ev_parts.append(f"IPs origen     : {', '.join(f.source_ips[:5])}")
        ev_parts.append(f"Eventos totales: {f.event_count}")
        if f.evidence_lines:
            ev_parts.append("")
            ev_parts.extend(f.evidence_lines[:5])

        affected = (
            ", ".join(f.source_ips[:3])
            if f.source_ips
            else f"sistema ({f.category})"
        )

        result.append(VSLFinding(
            id          = f.id,
            title       = f.title,
            severity    = f.severity,
            description = f.description,
            evidence    = "\n".join(ev_parts)[:1500],
            affected    = affected[:120],
            remediation = f.remediation,
            cvss        = _CVSS_DEFAULT.get(f.severity),
            tags        = list(f.tags),
        ))

    return result


# ---------------------------------------------------------------------------
# Punto de entrada principal
# ---------------------------------------------------------------------------

# =============================================================================
# ENRIQUECIMIENTO DE IPs CON FEEDS DE THREAT INTELLIGENCE
# =============================================================================

async def _enrich_single_ip(
    session,
    ip: str,
    abuseipdb_key: str,
    otx_key: str,
) -> dict:
    """
    Consulta AbuseIPDB y OTX AlienVault para una IP concreta.

    Retorna un dict con los campos de enriquecimiento disponibles.
    Errores de red se tragan silenciosamente: la función siempre retorna.
    """
    result: dict = {"ip": ip, "abuseipdb": None, "otx": None}
    UA = f"{TOOL_NAME}/{VERSION}"

    # ── AbuseIPDB v2 ────────────────────────────────────────────────────────
    if abuseipdb_key:
        try:
            headers = {"Key": abuseipdb_key, "Accept": "application/json", "User-Agent": UA}
            params  = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}
            async with session.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers, params=params, timeout=10, ssl=True,
            ) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    d    = data.get("data", {})
                    result["abuseipdb"] = {
                        "score":        d.get("abuseConfidenceScore", 0),
                        "total_reports": d.get("totalReports", 0),
                        "usage_type":   d.get("usageType", ""),
                        "isp":          d.get("isp", ""),
                        "country":      d.get("countryCode", ""),
                        "whitelisted":  d.get("isWhitelisted", False),
                    }
        except Exception:
            pass

    # ── OTX AlienVault ────────────────────────────────────────────────────────
    try:
        headers_otx: dict = {"User-Agent": UA}
        if otx_key:
            headers_otx["X-OTX-API-KEY"] = otx_key
        async with session.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers=headers_otx, timeout=10, ssl=True,
        ) as r:
            if r.status == 200:
                data = await r.json(content_type=None)
                result["otx"] = {
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "reputation":  data.get("reputation", 0),
                }
    except Exception:
        pass

    return result


async def enrich_ip_threat_feeds(
    ips: List[str],
    abuseipdb_key: str,
    otx_key: str,
    console: "Console",
) -> dict:
    """
    Enriquece una lista de IPs con AbuseIPDB y OTX en paralelo.

    Retorna un dict {ip: enrich_dict} con los resultados de cada IP.
    Las consultas se hacen en paralelo con semáforo de 5 slots para no
    saturar las APIs (especialmente AbuseIPDB Free: 1000 peticiones/día).
    """
    import aiohttp as _aiohttp

    if not ips:
        return {}

    sem = asyncio.Semaphore(5)

    async def _guarded(session, ip: str) -> tuple:
        async with sem:
            r = await _enrich_single_ip(session, ip, abuseipdb_key, otx_key)
            return ip, r

    console.print(
        f"\n[bold cyan]  FASE EXTRA — Enriquecimiento TI de {len(ips)} IPs[/]\n"
    )
    enriched: dict = {}

    async with _aiohttp.ClientSession() as session:
        tasks = [asyncio.create_task(_guarded(session, ip)) for ip in ips]
        for coro in asyncio.as_completed(tasks):
            ip, data = await coro
            enriched[ip] = data

            # Mostrar resumen por IP en tiempo real
            abuse = data.get("abuseipdb")
            otx   = data.get("otx")
            parts = []
            if abuse:
                score = abuse["score"]
                color = "red" if score >= 50 else ("yellow" if score >= 20 else "green")
                parts.append(f"[{color}]AbuseIPDB {score}%[/] ({abuse['total_reports']} reports)")
            if otx:
                pulses = otx["pulse_count"]
                color  = "red" if pulses >= 5 else ("yellow" if pulses >= 1 else "green")
                parts.append(f"[{color}]OTX {pulses} pulses[/]")
            if not parts:
                parts.append("[dim]sin datos[/]")
            console.print(f"  {ip} — " + " · ".join(parts))

    return enriched


def _apply_enrichment_to_findings(
    findings: "List[IoCFinding]",
    enriched: dict,
) -> None:
    """
    Añade etiquetas de threat intelligence a los hallazgos que contienen
    IPs enriquecidas. Modifica los hallazgos in-place.
    """
    for finding in findings:
        for ip in finding.source_ips:
            data = enriched.get(ip)
            if not data:
                continue
            abuse = data.get("abuseipdb")
            otx   = data.get("otx")
            if abuse and abuse["score"] >= 50:
                tag = f"AbuseIPDB:{ip}={abuse['score']}%({abuse['total_reports']}rep)"
                if tag not in finding.tags:
                    finding.tags.append(tag)
            if otx and otx["pulse_count"] >= 1:
                tag = f"OTX:{ip}={otx['pulse_count']}pulses"
                if tag not in finding.tags:
                    finding.tags.append(tag)


def main() -> int:
    """
    Punto de entrada principal de vamp-log-hunter.

    Parsea argumentos CLI, descubre o acepta ficheros de log, ejecuta el
    análisis IoC y produce la salida en consola y en los formatos de
    exportación solicitados.

    Returns
    -------
    int
        0 — Sin hallazgos significativos
        1 — Hallazgos HIGH encontrados
        2 — Hallazgos CRITICAL encontrados
    """
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Cazador de IoC en logs del sistema — VampSecure Labs\n"
            "Detecta fuerza bruta, SQLi, XSS, webshells, escalada de privilegios y más."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"  {AUTHOR}",
    )

    # ── Grupo de análisis ─────────────────────────────────────────────────
    ag = parser.add_argument_group("Análisis de logs")
    ag.add_argument(
        "--log-dir", metavar="DIR", default="/var/log",
        help="Directorio a escanear en busca de logs (por defecto: /var/log)",
    )
    ag.add_argument(
        "--file", metavar="FILE", action="append", dest="files",
        help=(
            "Fichero de log específico. Se puede repetir. "
            "Use '-' para leer desde stdin."
        ),
    )
    ag.add_argument(
        "--type", metavar="TYPE", choices=LOG_TYPES, default="auto",
        help=(
            "Tipo de log: nginx|apache|auth|syslog|journald|auto "
            "(por defecto: auto — detección por nombre de fichero)"
        ),
    )
    ag.add_argument(
        "--last-hours", metavar="N", type=int, default=0,
        help="Analizar solo los últimos N horas (0 = sin límite, por defecto: 0)",
    )
    ag.add_argument(
        "--threshold-brute", metavar="INT", type=int, default=10,
        help="Umbral de fallos/4xx para fuerza bruta (por defecto: 10)",
    )
    ag.add_argument(
        "--threshold-scan", metavar="INT", type=int, default=20,
        help="Umbral de rutas únicas con 404 para escaneo de directorios (por defecto: 20)",
    )

    # ── Grupo de enriquecimiento con feeds de amenazas ────────────────────
    ti = parser.add_argument_group("Threat Intelligence (enriquecimiento de IPs)")
    ti.add_argument(
        "--enrich-ips", action="store_true",
        help="Enriquecer las IPs detectadas con AbuseIPDB y OTX AlienVault "
             "(requiere --abuseipdb-key y/o --otx-key)",
    )
    ti.add_argument(
        "--abuseipdb-key", metavar="API_KEY",
        help="Clave API AbuseIPDB v2 (o var ABUSEIPDB_API_KEY) — "
             "consulta la reputación y número de reportes de cada IP",
    )
    ti.add_argument(
        "--otx-key", metavar="API_KEY",
        help="Clave API OTX AlienVault (o var OTX_API_KEY; opcional, "
             "el endpoint público funciona sin clave) — "
             "consulta los pulses de amenaza asociados a cada IP",
    )

    # ── Grupo de exportación ──────────────────────────────────────────────
    eg = parser.add_argument_group("Exportación de resultados")
    eg.add_argument(
        "--json", metavar="FILE",
        help="Guardar informe JSON estructurado",
    )
    eg.add_argument(
        "--html", metavar="FILE",
        help="Guardar informe HTML con tema oscuro (standalone)",
    )

    # ── Grupo de informe VSL ──────────────────────────────────────────────
    add_report_args(parser)

    args = parser.parse_args()

    console = Console()
    _print_banner(console)

    # ── Construcción de la lista de ficheros a analizar ───────────────────
    files_to_scan: List[Tuple[str, str]] = []

    if args.files:
        for f in args.files:
            if f == '-':
                log_type = args.type if args.type != 'auto' else 'syslog'
                files_to_scan.append(('-', log_type))
            else:
                log_type = (
                    args.type
                    if args.type != 'auto'
                    else _detect_log_type(f)
                )
                files_to_scan.append((f, log_type))
    else:
        discovered = _discover_log_files(args.log_dir)
        if not discovered:
            console.print(
                f"[yellow]⚠  No se encontraron logs en {args.log_dir}[/]"
            )
            return 0

        if args.type != 'auto':
            files_to_scan = [(p, args.type) for p, _ in discovered]
        else:
            files_to_scan = discovered

    # ── Escaneo con barra de progreso ─────────────────────────────────────
    scanner = LogScanner(
        threshold_brute = args.threshold_brute,
        threshold_scan  = args.threshold_scan,
        last_hours      = args.last_hours,
        console         = console,
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(
            "Analizando logs…", total=len(files_to_scan)
        )
        for file_path, log_type in files_to_scan:
            name = Path(file_path).name if file_path != '-' else '<stdin>'
            progress.update(task, description=f"[cyan]{name}[/]")
            scanner.scan_file(file_path, log_type)
            progress.advance(task)

    # ── Generación y presentación de hallazgos ───────────────────────────
    findings = scanner.generate_findings()

    # ── Enriquecimiento con Threat Intelligence (--enrich-ips) ───────────
    if getattr(args, "enrich_ips", False):
        abuseipdb_key = getattr(args, "abuseipdb_key", None) or os.environ.get("ABUSEIPDB_API_KEY", "")
        otx_key       = getattr(args, "otx_key", None) or os.environ.get("OTX_API_KEY", "")
        if not abuseipdb_key and not otx_key:
            console.print(
                "[yellow]⚠ --enrich-ips: se necesita --abuseipdb-key o --otx-key "
                "(o las variables de entorno ABUSEIPDB_API_KEY / OTX_API_KEY)[/]"
            )
        else:
            # Recolectar IPs únicas de todos los hallazgos (excluyendo escaners conocidos)
            unique_ips: List[str] = []
            seen_ips: set = set()
            for f in findings:
                for ip in f.source_ips:
                    if ip not in seen_ips and not _is_known_scanner(ip):
                        seen_ips.add(ip)
                        unique_ips.append(ip)
            unique_ips = unique_ips[:50]    # límite para no agotar cuota de APIs gratuitas

            if unique_ips:
                enriched = asyncio.run(
                    enrich_ip_threat_feeds(unique_ips, abuseipdb_key, otx_key, console)
                )
                _apply_enrichment_to_findings(findings, enriched)
            else:
                console.print("[dim]  --enrich-ips: no hay IPs que enriquecer.[/]")

    _print_summary(console, findings, scanner)
    _print_findings(console, findings)

    # ── Exportaciones ─────────────────────────────────────────────────────
    if args.json:
        _save_json(findings, args.json)
        console.print(f"[green]✓[/]  Informe JSON guardado en: {args.json}")

    if args.html:
        _save_html(findings, args.html)
        console.print(f"[green]✓[/]  Informe HTML guardado en: {args.html}")

    # ── Informe VSL unificado ─────────────────────────────────────────────
    meta     = meta_from_args(args, tool=TOOL_NAME, version=VERSION)
    vsl_list = _to_vsl(findings)
    report   = VampSecReport(meta, vsl_list)

    if getattr(args, 'report_html', None):
        report.to_html_client(args.report_html)
        console.print(
            f"[green]✓[/]  Informe VSL HTML guardado en: {args.report_html}"
        )

    if getattr(args, 'report_pdf', None):
        try:
            report.to_pdf(args.report_pdf)
            console.print(
                f"[green]✓[/]  Informe VSL PDF guardado en: {args.report_pdf}"
            )
        except RuntimeError as exc:
            console.print(f"[yellow]⚠  PDF no generado: {exc}[/]")

    # ── Código de salida ──────────────────────────────────────────────────
    if any(f.severity == "CRITICAL" for f in findings):
        return 2
    if any(f.severity == "HIGH" for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
