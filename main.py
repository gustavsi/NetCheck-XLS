import argparse
import concurrent.futures
import csv
import datetime
import hashlib
import html
import http.client
import ipaddress
import json
import os
import posixpath
import queue
import re
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from ftplib import FTP

try:
    import dns.resolver
except ImportError:
    dns = None

try:
    import ntplib
except ImportError:
    ntplib = None

try:
    import paramiko
    # Evita que o paramiko imprima tracebacks no terminal quando uma tentativa de
    # negociacao falha (o fallback trata e reporta o erro de forma resumida).
    import logging

    logging.getLogger("paramiko").setLevel(logging.CRITICAL)
except ImportError:
    paramiko = None

try:
    import telnetlib
except ImportError:
    telnetlib = None

try:
    import tftpy
except ImportError:
    tftpy = None

try:
    from pysnmp.hlapi import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        getCmd,
    )
except ImportError:
    CommunityData = None

try:
    from pythonping import ping as python_ping
except ImportError:
    python_ping = None


DEFAULT_TEMPLATE = "Template_IP.xlsx"
RESULTS_FILE = "connectivity_results.csv"
TRACE_DUMP_FILE = "dump_traces.txt"
TIMEOUT_SECONDS = 5
TRACE_TIMEOUT_SECONDS = 180
TRACE_MAX_HOPS = 20
TRACE_MAX_CONSECUTIVE_NO_REPLY = 5
# Tempo de espera (s) por resposta de cada sonda do traceroute (-w) e numero de sondas por hop (-q).
TRACE_PROBE_WAIT_SECONDS = 3
TRACE_PROBES_PER_HOP = 3
# Mostra no dump_traces.txt o IP de gerencia usado para acessar a origem via SSH,
# alem do IP real (interface da regra). Mude para False para exibir apenas o IP real.
TRACE_DUMP_SHOW_ACCESS_HOST = True
TRACE_PROTOCOLS = ("traceroute", "tracepath")
# Quando o traceroute TCP (-T) ou ICMP (-I) exige root e o usuario nao e root, o fallback
# com sudo fica DESABILITADO por padrao para preservar a garantia estrita de zero escrita
# nas VMs remotas (pois o proprio SO remoto pode registrar auditoria no syslog ou criar o
# arquivo de "lecture" em /var/lib/sudo/lectured). Pode ser habilitado explicitamente na
# CLI com --allow-sudo-fallback.
ALLOW_SUDO_FALLBACK = False
# Se o paramiko nao conseguir negociar com a origem (SSH antigo: ssh-rsa/SHA1, kex
# diffie-hellman-group1/14-sha1, cifras CBC), tenta com o cliente OpenSSH do sistema
# habilitando apenas os algoritmos exigidos pela origem. Tambem e usado sem paramiko.
SSH_OPENSSH_FALLBACK = True
# Verifica a chave publica (host key) das origens no known_hosts local (somente leitura).
SSH_STRICT_HOST_KEY_CHECKING = True

# Classificacoes explicitas de resultado (especialmente para traces de firewall):
CLASSIFICATION_REACHED = "REACHED"
CLASSIFICATION_UNCONFIRMED = "UNCONFIRMED"
CLASSIFICATION_UNREACHABLE = "UNREACHABLE"
CLASSIFICATION_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
CLASSIFICATION_TIMEOUT = "TIMEOUT"
CLASSIFICATION_EXECUTION_ERROR = "EXECUTION_ERROR"
CLASSIFICATION_SSH_ERROR = "SSH_ERROR"
ALL_CLASSIFICATIONS = (
    CLASSIFICATION_REACHED,
    CLASSIFICATION_UNCONFIRMED,
    CLASSIFICATION_UNREACHABLE,
    CLASSIFICATION_INSUFFICIENT_EVIDENCE,
    CLASSIFICATION_TIMEOUT,
    CLASSIFICATION_EXECUTION_ERROR,
    CLASSIFICATION_SSH_ERROR,
)

# Versoes de schema e aplicacao + codigos de saida da CLI:
SCHEMA_VERSION = "1.0"
APP_VERSION = "2.0.0"
DEFAULT_OUTPUT_DIR = "./netcheck-results"
MANIFEST_FILE = "run_manifest.json"
RUN_MANIFEST_FILE = MANIFEST_FILE
RESULTS_JSON_FILE = "results.json"
JSON_RESULTS_FILE = RESULTS_JSON_FILE
HTML_REPORT_FILE = "report.html"

EXIT_OK = 0
EXIT_CONNECTIVITY_FAILURE = 1
EXIT_TEST_FAILURE = EXIT_CONNECTIVITY_FAILURE
EXIT_CONFIG_ERROR = 2
EXIT_INTERNAL_ERROR = 3

# Severidades de preflight:
PREFLIGHT_ERROR = "ERROR"
PREFLIGHT_WARNING = "WARNING"
PREFLIGHT_INFO = "INFO"

# Vereditos compostos de politica de firewall (Policy Verdicts):
POLICY_TRACE_REACHED_TCP_CONNECTED = "TRACE_REACHED_TCP_CONNECTED"
POLICY_TRACE_REACHED_TCP_REFUSED = "TRACE_REACHED_TCP_REFUSED"
POLICY_TRACE_REACHED_TCP_TIMEOUT = "TRACE_REACHED_TCP_TIMEOUT"
POLICY_TRACE_REACHED_UDP_RESPONDED = "TRACE_REACHED_UDP_RESPONDED"
POLICY_TRACE_REACHED_UDP_REFUSED = "TRACE_REACHED_UDP_REFUSED"
POLICY_TRACE_REACHED_UDP_NO_RESPONSE = "TRACE_REACHED_UDP_NO_RESPONSE"
POLICY_TRACE_UNCONFIRMED = "TRACE_UNCONFIRMED"
POLICY_TRACE_UNREACHABLE = "TRACE_UNREACHABLE"
POLICY_SOURCE_EXECUTION_ERROR = "SOURCE_EXECUTION_ERROR"
POLICY_SOURCE_SSH_ERROR = "SOURCE_SSH_ERROR"
POLICY_NOT_APPLICABLE = "NOT_APPLICABLE"

POLICY_VERDICTS = (
    POLICY_TRACE_REACHED_TCP_CONNECTED,
    POLICY_TRACE_REACHED_TCP_REFUSED,
    POLICY_TRACE_REACHED_TCP_TIMEOUT,
    POLICY_TRACE_REACHED_UDP_RESPONDED,
    POLICY_TRACE_REACHED_UDP_REFUSED,
    POLICY_TRACE_REACHED_UDP_NO_RESPONSE,
    POLICY_TRACE_UNCONFIRMED,
    POLICY_TRACE_UNREACHABLE,
    POLICY_SOURCE_EXECUTION_ERROR,
    POLICY_SOURCE_SSH_ERROR,
    POLICY_NOT_APPLICABLE,
)

# Estados de teste de servico (TCP/UDP):
SERVICE_TCP_CONNECTED = "TCP_CONNECTED"
SERVICE_TCP_REFUSED = "TCP_REFUSED"
SERVICE_TCP_TIMEOUT = "TCP_TIMEOUT"
SERVICE_UDP_RESPONDED = "UDP_RESPONDED"
SERVICE_UDP_REFUSED = "UDP_REFUSED"
SERVICE_UDP_NO_RESPONSE = "UDP_NO_RESPONSE"
SERVICE_EXECUTION_ERROR = "EXECUTION_ERROR"
SERVICE_NOT_TESTED = "NOT_TESTED"

# Codigos deterministas de diagnostico operacional:
DIAG_INPUT_INVALID = "INPUT_INVALID"
DIAG_SOURCE_ACCESS_FAILURE = "SOURCE_ACCESS_FAILURE"
DIAG_SOURCE_HOST_KEY_FAILURE = "SOURCE_HOST_KEY_FAILURE"
DIAG_SOURCE_AUTH_FAILURE = "SOURCE_AUTH_FAILURE"
DIAG_SOURCE_CAPABILITY_FAILURE = "SOURCE_CAPABILITY_FAILURE"
DIAG_SOURCE_IP_REAL_INVALID = "SOURCE_IP_REAL_INVALID"
DIAG_SOURCE_ROUTE_OR_BIND_FAILURE = "SOURCE_ROUTE_OR_BIND_FAILURE"
DIAG_PATH_POLICY_DENY = "PATH_POLICY_DENY"
DIAG_PATH_SILENT_DROP_OR_ICMP_FILTER = "PATH_SILENT_DROP_OR_ICMP_FILTER"
DIAG_DESTINATION_REACHED_SERVICE_ACCEPTING = "DESTINATION_REACHED_SERVICE_ACCEPTING"
DIAG_DESTINATION_REACHED_SERVICE_REFUSING = "DESTINATION_REACHED_SERVICE_REFUSING"
DIAG_DESTINATION_REACHED_UDP_INCONCLUSIVE = "DESTINATION_REACHED_UDP_INCONCLUSIVE"
DIAG_TRANSIENT_OR_FLAKY = "TRANSIENT_OR_FLAKY"
DIAG_UNKNOWN_FAILURE = "UNKNOWN_FAILURE"

DIAGNOSIS_CODES = (
    DIAG_INPUT_INVALID,
    DIAG_SOURCE_ACCESS_FAILURE,
    DIAG_SOURCE_HOST_KEY_FAILURE,
    DIAG_SOURCE_AUTH_FAILURE,
    DIAG_SOURCE_CAPABILITY_FAILURE,
    DIAG_SOURCE_IP_REAL_INVALID,
    DIAG_SOURCE_ROUTE_OR_BIND_FAILURE,
    DIAG_PATH_POLICY_DENY,
    DIAG_PATH_SILENT_DROP_OR_ICMP_FILTER,
    DIAG_DESTINATION_REACHED_SERVICE_ACCEPTING,
    DIAG_DESTINATION_REACHED_SERVICE_REFUSING,
    DIAG_DESTINATION_REACHED_UDP_INCONCLUSIVE,
    DIAG_TRANSIENT_OR_FLAKY,
    DIAG_UNKNOWN_FAILURE,
)

DEFAULT_PORTS = {
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "dns": 53,
    "http": 80,
    "pop3": 110,
    "ntp": 123,
    "imap": 143,
    "snmp": 161,
    "https": 443,
    "smb": 445,
    "ldaps": 636,
    "tftp": 69,
    "rdp": 3389,
}

PROTOCOL_ALIASES = {
    "icmp": "icmp",
    "ping": "icmp",
    "tcp": "tcp",
    "udp": "udp",
    "http": "http",
    "https": "https",
    "ssh": "ssh",
    "telnet": "telnet",
    "ftp": "ftp",
    "dns": "dns",
    "ntp": "ntp",
    "snmp": "snmp",
    "tftp": "tftp",
    "smtp": "smtp",
    "pop3": "pop3",
    "imap": "imap",
    "smb": "smb",
    "ldaps": "ldaps",
    "rdp": "rdp",
    "traceroute": "traceroute",
    "tracert": "traceroute",
    "tracepath": "tracepath",
    # Variantes que ja definem o metodo do traceroute.
    "traceroutetcp": "traceroute",
    "tcptraceroute": "traceroute",
    "tcptrace": "traceroute",
    "tracerouteudp": "traceroute",
    "tracerouteicmp": "traceroute",
}

# Metodo (transporte) implicito em alguns aliases de protocolo.
PROTOCOL_TRANSPORT_HINTS = {
    "traceroutetcp": "tcp",
    "tcptraceroute": "tcp",
    "tcptrace": "tcp",
    "tracerouteudp": "udp",
    "tracerouteicmp": "icmp",
}

NS = {"a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"


class SecretResolutionError(ValueError):
    """Falha ao resolver uma referencia de segredo (env: ou keyring:)."""


_KNOWN_SECRETS_LOCK = threading.Lock()
_KNOWN_SECRETS = set()


def register_known_secret(secret_value):
    """Registra um segredo em memoria para que nunca apareca em logs, dumps ou relatorios."""
    if secret_value and isinstance(secret_value, str) and len(secret_value) >= 2:
        with _KNOWN_SECRETS_LOCK:
            _KNOWN_SECRETS.add(secret_value)


def sanitize_text(text, extra_secrets=()):
    """Remove qualquer segredo conhecido ou padroes sensiveis de uma string."""
    if text is None:
        return ""
    out = str(text)
    with _KNOWN_SECRETS_LOCK:
        secrets = sorted(_KNOWN_SECRETS.union(s for s in extra_secrets if s), key=len, reverse=True)
    for secret in secrets:
        if secret and secret in out:
            out = out.replace(secret, "[REDACTED]")
    return out


def _resolve_env_secret(spec):
    var_name = spec.strip()
    if not var_name or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", var_name):
        raise SecretResolutionError(f"Referencia 'env:' invalida: 'env:{spec}'")
    val = os.environ.get(var_name)
    if val is None or val == "":
        raise SecretResolutionError(
            f"Variavel de ambiente '{var_name}' (referenciada por 'env:{var_name}') nao esta definida ou esta vazia"
        )
    return val


def _resolve_keyring_secret(spec):
    if "/" not in spec:
        raise SecretResolutionError(
            f"Referencia 'keyring:' invalida ('keyring:{spec}'); formato esperado: 'keyring:servico/conta'"
        )
    service, account = spec.split("/", 1)
    service = service.strip()
    account = account.strip()
    if not service or not account:
        raise SecretResolutionError(
            f"Referencia 'keyring:' incompleta ('keyring:{spec}'); formato esperado: 'keyring:servico/conta'"
        )
    try:
        import keyring as kr_mod  # type: ignore

        val = kr_mod.get_password(service, account)
        if val:
            return val
    except ImportError:
        pass
    except Exception as exc:
        raise SecretResolutionError(
            f"Erro ao consultar keyring para '{service}/{account}': {type(exc).__name__}"
        ) from exc

    if shutil.which("secret-tool"):
        try:
            completed = subprocess.run(
                ["secret-tool", "lookup", "service", service, "account", account],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if completed.returncode == 0 and completed.stdout:
                return completed.stdout.rstrip("\r\n")
        except (OSError, subprocess.SubprocessError):
            pass

    raise SecretResolutionError(
        f"Segredo 'keyring:{service}/{account}' nao encontrado ou provedor keyring indisponivel"
    )


SECRET_PROVIDERS = {
    "env": _resolve_env_secret,
    "keyring": _resolve_keyring_secret,
}


def register_secret_provider(scheme, resolver_fn):
    """Permite registrar provedores adicionais de segredo (ex.: vault, aws-sm)."""
    SECRET_PROVIDERS[scheme.strip().lower()] = resolver_fn


def resolve_secret_reference(raw_value):
    """Resolve valor da coluna Password.

    Retorna (resolved_secret, credential_source, credential_ref, error_message).
    """
    text = normalize_text(raw_value)
    if not text:
        return "", "ssh_key_or_agent", "", None

    match = re.match(r"^([a-zA-Z][a-zA-Z0-9_-]*):(.*)$", text)
    if match and match.group(1).lower() in SECRET_PROVIDERS:
        scheme = match.group(1).lower()
        spec = match.group(2)
        ref_label = f"{scheme}:{spec}"
        try:
            resolved = SECRET_PROVIDERS[scheme](spec)
            register_known_secret(resolved)
            return resolved, scheme, ref_label, None
        except SecretResolutionError as exc:
            return "", scheme, ref_label, str(exc)
        except Exception as exc:
            return "", scheme, ref_label, f"Falha ao resolver segredo '{ref_label}': {type(exc).__name__}"

    register_known_secret(text)
    return text, "inline", "inline", None


@dataclass
class SSHAuditInfo:
    profile_name: str
    backend: str
    legacy_fallback_used: bool = False
    enabled_legacy_algorithms: dict = field(default_factory=dict)
    sha1_signatures_enabled: bool = False
    fallback_reason: str = ""
    host_key_verified: bool = True
    security_warning: str | dict | None = None

    def to_dict(self):
        if isinstance(self.security_warning, dict):
            sec_warn = dict(self.security_warning)
        elif self.security_warning:
            sec_warn = sanitize_text(str(self.security_warning))
        else:
            sec_warn = ""
        return {
            "profile_name": self.profile_name,
            "backend": self.backend,
            "legacy_fallback_used": self.legacy_fallback_used,
            "enabled_legacy_algorithms": dict(self.enabled_legacy_algorithms),
            "sha1_signatures_enabled": self.sha1_signatures_enabled,
            "fallback_reason": sanitize_text(self.fallback_reason),
            "host_key_verified": self.host_key_verified,
            "security_warning": sec_warn,
        }


@dataclass
class PreflightIssue:
    severity: str
    code: str
    message: str
    row: int | None = None
    origin_number: str | None = None
    target_host: str | None = None
    blocking: bool = False

    @property
    def origin(self):
        return self.origin_number

    @property
    def target(self):
        return self.target_host

    def to_dict(self):
        return {
            "severity": self.severity,
            "code": self.code,
            "message": sanitize_text(self.message),
            "row": self.row,
            "origin_number": self.origin_number,
            "target_host": self.target_host,
            "blocking": self.blocking,
        }


@dataclass
class PreflightReport:
    ok: bool = True
    template_path: str = ""
    issues: list = field(default_factory=list)
    blocked_origins: set = field(default_factory=set)
    blocked_rows: set = field(default_factory=set)
    local_binaries: dict = field(default_factory=dict)
    remote_preflight: dict = field(default_factory=dict)
    fatal_error: str | None = None
    valid_targets: int = 0
    blocked_targets: int = 0

    def add(
        self,
        severity,
        code,
        message,
        row=None,
        origin=None,
        target=None,
        blocking=None,
    ):
        is_blocking = (severity == PREFLIGHT_ERROR) if blocking is None else bool(blocking)
        issue = PreflightIssue(
            severity=severity,
            code=code,
            message=sanitize_text(message),
            row=row,
            origin_number=str(origin) if origin is not None else None,
            target_host=str(target) if target is not None else None,
            blocking=is_blocking,
        )
        self.issues.append(issue)
        if severity == PREFLIGHT_ERROR:
            self.ok = False
            if origin is not None:
                self.blocked_origins.add(str(origin))
            if row is not None:
                self.blocked_rows.add(int(row))
        return issue

    @property
    def has_errors(self):
        return any(i.severity == PREFLIGHT_ERROR for i in self.issues)

    @property
    def error_count(self):
        return sum(1 for i in self.issues if i.severity == PREFLIGHT_ERROR)

    @property
    def warning_count(self):
        return sum(1 for i in self.issues if i.severity == PREFLIGHT_WARNING)

    @property
    def counts(self):
        counts = {PREFLIGHT_ERROR: 0, PREFLIGHT_WARNING: 0, PREFLIGHT_INFO: 0}
        for issue in self.issues:
            counts[issue.severity] = counts.get(issue.severity, 0) + 1
        return counts

    def to_dict(self):
        return {
            "ok": not self.has_errors,
            "template_path": self.template_path,
            "fatal_error": sanitize_text(self.fatal_error) if self.fatal_error else None,
            "counts": self.counts,
            "valid_targets": self.valid_targets,
            "blocked_targets": self.blocked_targets,
            "blocked_origins": sorted(self.blocked_origins),
            "blocked_rows": sorted(self.blocked_rows),
            "local_binaries": self.local_binaries,
            "remote_preflight": self.remote_preflight,
            "issues": [issue.to_dict() for issue in self.issues],
        }


@dataclass
class Origin:
    number: str
    host: str
    port: int
    access_protocol: str
    username: str
    password: str = field(repr=False, default="")
    # IP da interface que deve aparecer na regra de firewall (sinalizacao, bilhetagem...).
    # Quando preenchido, e usado como origem do traceroute (-s) e exibido no TXT.
    real_ip: str = ""
    # Erro de validacao no cadastro da origem (ex.: IP Real, porta ou segredo invalidos).
    error: str | None = None
    row: int | None = None
    credential_source: str = ""
    credential_ref: str = ""
    ssh_audit: dict | None = None
    remote_preflight: dict | None = None

    def __post_init__(self):
        if self.password:
            register_known_secret(self.password)
        if not self.credential_source:
            self.credential_source = "inline" if self.password else "ssh_key_or_agent"
        if self.ssh_audit is None:
            self.ssh_audit = {}
        if self.remote_preflight is None:
            self.remote_preflight = {}

    @property
    def display_ip(self):
        return self.real_ip or self.host

    def to_sanitized_dict(self):
        return {
            "number": self.number,
            "row": self.row,
            "management_host": self.host,
            "real_ip": self.real_ip or None,
            "display_ip": self.display_ip,
            "port": self.port,
            "access_protocol": self.access_protocol,
            "username": self.username,
            "credential_source": self.credential_source,
            "credential_ref": self.credential_ref if self.credential_source != "inline" else "inline",
            "error": sanitize_text(self.error) if self.error else None,
            "ssh_audit": self.ssh_audit,
            "remote_preflight": self.remote_preflight,
        }

    to_dict = to_sanitized_dict


@dataclass
class TestTarget:
    row: int
    origin_number: str
    host: str
    port: int | None
    protocol: str
    description: str
    # "tcp", "udp" ou "icmp" quando informado (ex.: "5060/udp" ou protocolo "traceroute-tcp").
    transport: str | None = None
    # Erro de leitura da linha (ex.: porta invalida); o teste falha sem ser executado.
    error: str | None = None
    resolved_ips: dict = field(default_factory=dict)
    effective_ip: str = ""
    original_host: str = ""

    def __post_init__(self):
        if not self.original_host:
            self.original_host = self.host
        if not self.effective_ip and valid_ip(self.host):
            self.effective_ip = valid_ip(self.host)

    def to_dict(self):
        return {
            "row": self.row,
            "origin_number": self.origin_number or None,
            "host": self.host,
            "original_host": self.original_host or self.host,
            "effective_ip": self.effective_ip or (valid_ip(self.host) or None),
            "resolved_ips": self.resolved_ips or {"ipv4": [], "ipv6": []},
            "port": self.port,
            "protocol": self.protocol,
            "transport": self.transport,
            "description": self.description,
            "error": sanitize_text(self.error) if self.error else None,
        }


def default_composite_for_result(result):
    """Constroi o objeto de politica composta padrao quando nenhum teste de servico extra rodou."""
    target = result.target
    cls = result.classification
    trace_cls = getattr(result, "trace_classification", "") or cls
    if target.protocol in TRACE_PROTOCOLS:
        if trace_cls == CLASSIFICATION_SSH_ERROR or cls == CLASSIFICATION_SSH_ERROR:
            return {
                "policy_verdict": POLICY_SOURCE_SSH_ERROR,
                "trace_result": CLASSIFICATION_SSH_ERROR,
                "service_result": SERVICE_NOT_TESTED,
                "service_detail": "",
                "service_elapsed_ms": 0,
                "firewall_request_eligible": False,
            }
        if trace_cls == CLASSIFICATION_EXECUTION_ERROR or cls == CLASSIFICATION_EXECUTION_ERROR:
            return {
                "policy_verdict": POLICY_SOURCE_EXECUTION_ERROR,
                "trace_result": CLASSIFICATION_EXECUTION_ERROR,
                "service_result": SERVICE_NOT_TESTED,
                "service_detail": "",
                "service_elapsed_ms": 0,
                "firewall_request_eligible": False,
            }
        if target.port is None or target.transport == "icmp":
            if trace_cls == CLASSIFICATION_REACHED:
                verdict = POLICY_NOT_APPLICABLE
                eligible = bool(result.ok)
            elif trace_cls == CLASSIFICATION_UNREACHABLE:
                verdict = POLICY_TRACE_UNREACHABLE
                eligible = False
            else:
                verdict = POLICY_TRACE_UNCONFIRMED
                eligible = False
            return {
                "policy_verdict": verdict,
                "trace_result": trace_cls,
                "service_result": SERVICE_NOT_TESTED,
                "service_detail": "",
                "service_elapsed_ms": 0,
                "firewall_request_eligible": eligible,
            }
        if trace_cls == CLASSIFICATION_UNREACHABLE:
            return {
                "policy_verdict": POLICY_TRACE_UNREACHABLE,
                "trace_result": trace_cls,
                "service_result": SERVICE_NOT_TESTED,
                "service_detail": "",
                "service_elapsed_ms": 0,
                "firewall_request_eligible": False,
            }
        if trace_cls != CLASSIFICATION_REACHED:
            return {
                "policy_verdict": POLICY_TRACE_UNCONFIRMED,
                "trace_result": trace_cls,
                "service_result": SERVICE_NOT_TESTED,
                "service_detail": "",
                "service_elapsed_ms": 0,
                "firewall_request_eligible": False,
            }
        return {
            "policy_verdict": POLICY_NOT_APPLICABLE,
            "trace_result": trace_cls,
            "service_result": SERVICE_NOT_TESTED,
            "service_detail": "",
            "service_elapsed_ms": 0,
            "firewall_request_eligible": bool(result.ok),
        }

    detail_lower = (result.detail or "").lower()
    if target.protocol == "tcp":
        if result.ok:
            svc_res = SERVICE_TCP_CONNECTED
        elif "refused" in detail_lower or "recusado" in detail_lower:
            svc_res = SERVICE_TCP_REFUSED
        else:
            svc_res = SERVICE_TCP_TIMEOUT
    elif target.protocol == "udp":
        if result.ok:
            svc_res = SERVICE_UDP_RESPONDED
        elif "refused" in detail_lower or "recusado" in detail_lower:
            svc_res = SERVICE_UDP_REFUSED
        elif "sem resposta" in detail_lower or "inconclusivo" in detail_lower or "udp_no_response" in detail_lower:
            svc_res = SERVICE_UDP_NO_RESPONSE
        else:
            svc_res = SERVICE_EXECUTION_ERROR
    else:
        svc_res = "OK" if result.ok else "FAILED"

    return {
        "policy_verdict": POLICY_NOT_APPLICABLE,
        "trace_result": "NOT_APPLICABLE",
        "service_result": svc_res,
        "service_detail": sanitize_text(result.detail),
        "service_elapsed_ms": result.elapsed_ms,
        "firewall_request_eligible": bool(result.ok),
    }


def compute_diagnosis(result):
    """Motor deterministico de diagnostico operacional (sem intervencao humana)."""
    target = result.target
    origin = result.origin
    cls = result.classification
    trace_cls = (
        getattr(result, "trace_classification", "")
        or (result.composite.get("trace_result", "") if result.composite else "")
        or cls
    )
    detail_lower = (result.detail or "").lower()
    summary_lower = (result.summary or "").lower()
    notes_lower = " ".join(result.notes or ()).lower()
    combined = f"{detail_lower} {summary_lower} {notes_lower}"
    pv = result.composite.get("policy_verdict", POLICY_NOT_APPLICABLE) if result.composite else POLICY_NOT_APPLICABLE
    svc = result.composite.get("service_result", SERVICE_NOT_TESTED) if result.composite else SERVICE_NOT_TESTED

    def build(code, category, reasons, state, eligible, retest, description):
        return {
            "diagnosis_code": code,
            "diagnosis_category": category,
            "machine_reason_codes": list(reasons),
            "automation_state": state,
            "firewall_request_eligible": bool(eligible),
            "retest_recommended": bool(retest),
            "description": description,
        }

    if result.flaky:
        return build(
            DIAG_TRANSIENT_OR_FLAKY,
            "STABILITY",
            ["DIVERGENT_ATTEMPTS", cls],
            "COMPLETED_FLAKY",
            False,
            True,
            "Resultados divergiram entre tentativas consecutivas (comportamento intermitente/flaky).",
        )

    if origin and origin.error:
        err_l = origin.error.lower()
        if "ip real invalido" in err_l or "nao esta configurado nesta origem" in err_l:
            return build(
                DIAG_SOURCE_IP_REAL_INVALID,
                "SOURCE_CONFIGURATION",
                ["ORIGIN_REAL_IP_INVALID"],
                "BLOCKED_BY_PREFLIGHT",
                False,
                False,
                "IP Real da origem e invalido na planilha ou nao pertence a VM de origem.",
            )
        if any(k in err_l for k in ("env:", "keyring:", "segredo", "variavel de ambiente")):
            return build(
                DIAG_SOURCE_AUTH_FAILURE,
                "SOURCE_AUTH",
                ["SECRET_RESOLUTION_FAILED"],
                "BLOCKED_BY_PREFLIGHT",
                False,
                False,
                "Referencia de segredo da origem nao pode ser resolvida.",
            )
        return build(
            DIAG_INPUT_INVALID,
            "CONFIGURATION",
            ["ORIGIN_CONFIG_INVALID"],
            "BLOCKED_BY_PREFLIGHT",
            False,
            False,
            "Configuracao da origem invalida na planilha.",
        )

    if (
        target.error
        or "nao encontrada na tabela de origens" in combined
        or "porta invalida na planilha" in combined
        or "porta ssh invalida" in combined
        or "configurada para telnet" in combined
        or "sem usuario na planilha" in combined
        or "precisa de uma porta" in combined
        or "incompatibilidade de familia ip" in combined
    ):
        return build(
            DIAG_INPUT_INVALID,
            "CONFIGURATION",
            ["PREFLIGHT_INPUT_INVALID"],
            "BLOCKED_BY_PREFLIGHT",
            False,
            False,
            "Parametros de entrada invalidos na planilha.",
        )

    if (
        "ip real invalido" in combined
        or "cannot assign requested address" in combined
        or "nao esta configurado nesta origem" in combined
    ):
        return build(
            DIAG_SOURCE_IP_REAL_INVALID,
            "SOURCE_CONFIGURATION",
            ["SOURCE_IP_REAL_NOT_ASSIGNED"],
            "COMPLETED_WITH_FAILURE",
            False,
            False,
            "IP Real informado nao esta atribuido a nenhuma interface na VM de origem.",
        )

    if cls == CLASSIFICATION_SSH_ERROR:
        if any(m in combined for m in ("hostkeyverificationerror", "host key", "known_hosts")):
            return build(
                DIAG_SOURCE_HOST_KEY_FAILURE,
                "SOURCE_SECURITY",
                ["SSH_HOST_KEY_VERIFICATION_FAILED"],
                "COMPLETED_WITH_FAILURE",
                False,
                False,
                "Verificacao de host key SSH falhou contra o known_hosts.",
            )
        if any(
            m in combined
            for m in (
                "authentication",
                "autenticacao",
                "permission denied",
                "badauthenticationtype",
                "nenhuma chave ssh",
                "permissionerror",
            )
        ):
            return build(
                DIAG_SOURCE_AUTH_FAILURE,
                "SOURCE_AUTH",
                ["SSH_AUTHENTICATION_FAILED"],
                "COMPLETED_WITH_FAILURE",
                False,
                False,
                "Falha de autenticacao SSH na VM de origem.",
            )
        return build(
            DIAG_SOURCE_ACCESS_FAILURE,
            "SOURCE_CONNECTIVITY",
            ["SSH_CONNECTION_FAILED"],
            "COMPLETED_WITH_FAILURE",
            False,
            True,
            "Nao foi possivel estabelecer conexao TCP/SSH com o IP de gerencia da origem.",
        )

    if cls == CLASSIFICATION_EXECUTION_ERROR:
        if any(
            m in combined
            for m in (
                "enough privileges",
                "operation not permitted",
                "permission denied",
                "cap_net_raw",
                "exige root",
                "exige privilegio",
                "sudo falhou",
                "comando nao encontrado",
                "not found",
                "nao esta disponivel nativamente",
            )
        ):
            return build(
                DIAG_SOURCE_CAPABILITY_FAILURE,
                "SOURCE_ENVIRONMENT",
                ["SOURCE_PRIVILEGE_OR_BINARY_MISSING"],
                "COMPLETED_WITH_FAILURE",
                False,
                False,
                "Falta de permissao (root/sudo/CAP_NET_RAW) ou binario ausente na origem.",
            )
        if any(
            m in combined
            for m in (
                "network is unreachable",
                "no route to host",
                "send failed",
                "write error",
                "bind:",
                "socket:",
            )
        ):
            return build(
                DIAG_SOURCE_ROUTE_OR_BIND_FAILURE,
                "SOURCE_NETWORK",
                ["SOURCE_SOCKET_OR_ROUTE_ERROR"],
                "COMPLETED_WITH_FAILURE",
                False,
                False,
                "Falha de rota local ou bind de socket na VM de origem.",
            )

    if pv in (POLICY_TRACE_REACHED_TCP_REFUSED, POLICY_TRACE_REACHED_UDP_REFUSED) or (
        svc in (SERVICE_TCP_REFUSED, SERVICE_UDP_REFUSED)
    ):
        return build(
            DIAG_DESTINATION_REACHED_SERVICE_REFUSING,
            "DESTINATION_SERVICE",
            ["TRACE_REACHED" if trace_cls == CLASSIFICATION_REACHED else cls, svc],
            "COMPLETED_WITH_FAILURE",
            False,
            False,
            "Rede alcancou o host de destino, mas a porta do servico recusou a conexao (RST/ICMP port unreachable).",
        )

    if pv == POLICY_TRACE_REACHED_UDP_NO_RESPONSE or svc == SERVICE_UDP_NO_RESPONSE:
        reasons = (
            ["TRACE_REACHED", "UDP_NO_RESPONSE"]
            if trace_cls == CLASSIFICATION_REACHED
            else [cls, "UDP_NO_RESPONSE"]
        )
        return build(
            DIAG_DESTINATION_REACHED_UDP_INCONCLUSIVE,
            "DESTINATION_SERVICE",
            reasons,
            "COMPLETED_INCONCLUSIVE",
            False,
            True,
            "Pacote UDP enviado sem resposta da aplicacao; conectividade de servico UDP inconclusiva.",
        )

    if result.ok and cls == CLASSIFICATION_REACHED:
        reasons = ["TRACE_REACHED"] if target.protocol in TRACE_PROTOCOLS else ["SERVICE_OK"]
        if pv not in (POLICY_NOT_APPLICABLE, ""):
            reasons.append(pv)
        return build(
            DIAG_DESTINATION_REACHED_SERVICE_ACCEPTING,
            "CONNECTIVITY_OK",
            reasons,
            "COMPLETED_OK",
            True,
            False,
            "Destino alcancado e conectividade confirmada.",
        )

    if cls == CLASSIFICATION_UNREACHABLE or pv == POLICY_TRACE_UNREACHABLE:
        reasons = ["TRACE_UNREACHABLE"]
        unreach_match = UNREACHABLE_RE.search(result.summary or "") or UNREACHABLE_RE.search(result.detail or "")
        if unreach_match:
            reasons.append(f"ICMP_BANG_{unreach_match.group(1)}")
        return build(
            DIAG_PATH_POLICY_DENY,
            "NETWORK_POLICY",
            reasons,
            "COMPLETED_WITH_FAILURE",
            False,
            False,
            "Bloqueio explicito de politica/roteamento no caminho (ICMP unreachable/prohibited).",
        )

    if cls in (CLASSIFICATION_UNCONFIRMED, CLASSIFICATION_TIMEOUT, CLASSIFICATION_INSUFFICIENT_EVIDENCE):
        reasons = [f"TRACE_{trace_cls}" if target.protocol in TRACE_PROTOCOLS else cls]
        if pv == POLICY_TRACE_REACHED_TCP_TIMEOUT or svc == SERVICE_TCP_TIMEOUT:
            reasons.append("TCP_TIMEOUT")
        elif "consecutivos sem resposta" in summary_lower:
            reasons.append("FIVE_CONSECUTIVE_NO_REPLY")
        elif "limite de " in summary_lower and "hops" in summary_lower:
            reasons.append("MAX_HOPS_REACHED")
        elif cls == CLASSIFICATION_TIMEOUT:
            reasons.append("TRACE_TIMEOUT")
        elif cls == CLASSIFICATION_INSUFFICIENT_EVIDENCE:
            reasons.append("INSUFFICIENT_TRACE_EVIDENCE")
        return build(
            DIAG_PATH_SILENT_DROP_OR_ICMP_FILTER,
            "NETWORK_PATH",
            reasons,
            "COMPLETED_WITH_FAILURE",
            False,
            True,
            "Trace encerrou sem confirmacao do destino (descarte silencioso de firewall ou filtro ICMP).",
        )

    return build(
        DIAG_UNKNOWN_FAILURE,
        "UNKNOWN",
        [cls or "UNKNOWN"],
        "COMPLETED_WITH_FAILURE",
        False,
        True,
        "Falha de conectividade ou execucao nao classificada especificamente.",
    )


@dataclass
class TestResult:
    target: TestTarget
    origin: Origin | None
    ok: bool
    status: str
    detail: str
    elapsed_ms: int
    # Campos usados pelos traces e diagnostico estruturado.
    summary: str = ""
    method: str = ""
    command: str = ""
    notes: list = field(default_factory=list)
    classification: str = ""
    trace_classification: str = ""
    hops: list = field(default_factory=list)
    composite: dict | None = None
    diagnosis: dict | None = None
    attempts: list = field(default_factory=list)
    baseline_diff: dict | None = None
    flaky: bool = False
    ssh_audit: dict | None = None
    run_id: str = ""

    def __post_init__(self):
        if not self.classification:
            self.classification = (
                CLASSIFICATION_REACHED if self.ok else CLASSIFICATION_EXECUTION_ERROR
            )
        if not self.trace_classification:
            if (
                self.composite
                and self.composite.get("trace_result")
                and self.composite.get("trace_result") != "NOT_APPLICABLE"
            ):
                self.trace_classification = self.composite["trace_result"]
            elif self.target.protocol in TRACE_PROTOCOLS:
                self.trace_classification = self.classification
            else:
                self.trace_classification = "NOT_APPLICABLE"
        self.detail = sanitize_text(self.detail)
        self.summary = sanitize_text(self.summary)
        self.command = sanitize_text(self.command)
        self.notes = [sanitize_text(n) for n in self.notes]
        if self.origin and self.ssh_audit is None and self.origin.ssh_audit is not None:
            self.ssh_audit = self.origin.ssh_audit
        if self.composite is None:
            self.composite = default_composite_for_result(self)
        elif (
            self.target.protocol in TRACE_PROTOCOLS
            and self.trace_classification
            and self.trace_classification != "NOT_APPLICABLE"
        ):
            self.composite.setdefault("trace_result", self.trace_classification)
        if self.diagnosis is None:
            self.diagnosis = compute_diagnosis(self)

    @property
    def service_result(self):
        if self.composite and "service_result" in self.composite:
            return self.composite["service_result"]
        return SERVICE_NOT_TESTED

    @property
    def policy_verdict(self):
        if self.composite and "policy_verdict" in self.composite:
            return self.composite["policy_verdict"]
        return POLICY_NOT_APPLICABLE

    @property
    def diagnosis_code(self):
        if self.diagnosis and "diagnosis_code" in self.diagnosis:
            return self.diagnosis["diagnosis_code"]
        return DIAG_UNKNOWN_FAILURE

    def comparison_key(self):
        origin_num = self.origin.number if self.origin else (self.target.origin_number or "local")
        real_ip = self.origin.real_ip if self.origin else ""
        host_key = self.target.original_host or self.target.host
        eff_ip = self.target.effective_ip if self.target.original_host != self.target.host else ""
        port_str = str(self.target.port) if self.target.port is not None else ""
        transport_str = self.target.transport or ""
        return f"{origin_num}|{real_ip}|{host_key}|{eff_ip}|{port_str}|{self.target.protocol}|{transport_str}"

    def to_dict(self):
        return {
            "run_id": self.run_id or None,
            "row": self.target.row,
            "comparison_key": self.comparison_key(),
            "ok": self.ok,
            "status": self.status,
            "classification": self.classification,
            "trace_classification": self.trace_classification,
            "summary": sanitize_text(self.summary),
            "method": self.method or None,
            "command": sanitize_text(self.command) or None,
            "elapsed_ms": self.elapsed_ms,
            "flaky": self.flaky,
            "notes": [sanitize_text(n) for n in self.notes],
            "target": self.target.to_dict(),
            "origin": self.origin.to_sanitized_dict() if self.origin else None,
            "ssh_audit": self.ssh_audit or (self.origin.ssh_audit if self.origin else None),
            "hops": self.hops,
            "composite": self.composite,
            "diagnosis": self.diagnosis,
            "attempts": self.attempts,
            "baseline_diff": self.baseline_diff,
            "evidence": {
                "raw_output": sanitize_text(self.detail),
            },
        }


def clear_terminal():
    os.system("cls" if os.name == "nt" else "clear")


def menu():
    clear_terminal()
    print(
        """
    \033[96m==============================================================\033[0m
    \033[92m   VALIDADOR DE CONECTIVIDADE - ICMP / TCP / UDP\033[0m
    \033[96m==============================================================\033[0m

    \033[97m   Este programa realiza validacoes de rede a partir
    de um template Excel contendo IPs e portas.\033[0m

    \033[93m   Acesso restrito a: Gustavo e pessoas autorizadas\033[0m
    \033[96m==============================================================\033[0m
    """
    )

    print("\033[96m==== MENU PRINCIPAL ====\033[0m")
    print("\033[92m[1]\033[0m Iniciar o script")
    print("\033[91m[0]\033[0m Fechar o programa")
    print("\033[96m========================\033[0m")

    while True:
        choice = input("Digite a sua escolha: ").strip()
        if choice in ["0", "1"]:
            break
        print("Opcao invalida, tente novamente.\n")

    if choice == "0":
        clear_terminal()
        print("Sure, bye bye")
        return None

    clear_terminal()
    while True:
        print("Selecione a planilha.")
        print(f"\033[92m[0]\033[0m Utilizar diretorio raiz ({DEFAULT_TEMPLATE})")
        print("\033[91m[1]\033[0m Digitar diretorio manualmente")
        choice = input("\nDigite sua escolha: ").strip()
        if choice == "0":
            return DEFAULT_TEMPLATE
        if choice == "1":
            # Remove aspas que aparecem ao arrastar/colar o caminho do arquivo no terminal.
            return input("Digite o diretorio e nome de arquivo manualmente: ").strip().strip("'\"")
        clear_terminal()
        print("Opcao invalida, tente novamente.\n")


def normalize_text(value):
    if value is None:
        return ""
    text = str(value).strip()
    # Celulas numericas do Excel podem vir como "22.0"; so remove o ".0" de numeros puros
    # para nao corromper senhas, descricoes ou hostnames (ex.: "Senha@1.0").
    if re.fullmatch(r"-?\d+\.0+", text):
        text = text.split(".", 1)[0]
    return text


def normalize_header(value):
    return re.sub(r"[^a-z0-9]+", "", normalize_text(value).lower())


def parse_port(value, default=None):
    text = normalize_text(value)
    if not text:
        return default
    try:
        return int(float(text))
    except ValueError:
        return default


PORT_TOKEN_RE = re.compile(r"^(?:(tcp|udp)/)?(\d{1,5})(?:/(tcp|udp))?$", re.IGNORECASE)


def parse_port_specs(value):
    """Le a coluna de portas.

    Aceita uma ou varias portas separadas por virgula, ponto e virgula ou espaco,
    opcionalmente com o transporte: "443", "443/tcp", "5060/udp", "22, 443".
    Retorna (lista de (porta, transporte), lista de tokens invalidos).
    """
    text = normalize_text(value)
    if not text:
        return [(None, None)], []
    specs, invalid = [], []
    for token in re.split(r"[,;\s]+", text):
        if not token:
            continue
        match = PORT_TOKEN_RE.match(token)
        if not match:
            invalid.append(token)
            continue
        port = int(match.group(2))
        if not 1 <= port <= 65535:
            invalid.append(token)
            continue
        transport = (match.group(1) or match.group(3) or "").lower() or None
        specs.append((port, transport))
    if not specs and not invalid:
        specs.append((None, None))
    return specs, invalid


def protocol_key(protocol):
    return re.sub(r"[^a-z0-9]+", "", normalize_text(protocol).lower())


def normalize_protocol(protocol, port=None):
    text = protocol_key(protocol)
    if text in PROTOCOL_ALIASES:
        return PROTOCOL_ALIASES[text]
    if not text and port:
        return "tcp"
    return text or "icmp"


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(normalize_text(value).strip("[]")))
    except ValueError:
        return None


def ip_family(value):
    """Retorna 4 ou 6 se `value` for um literal IP valido (IPv4 ou IPv6), ou None caso contrario."""
    ip_str = valid_ip(value)
    if not ip_str:
        return None
    return ipaddress.ip_address(ip_str).version


def target_ip_family(target, origin=None):
    """Determina a familia IP (4, 6 ou None) efetiva de um TestTarget."""
    if target is None:
        return None
    direct = ip_family(target.host) or ip_family(target.effective_ip)
    if direct in (4, 6):
        return direct
    resolved = target.resolved_ips or {}
    v4 = resolved.get("ipv4") or []
    v6 = resolved.get("ipv6") or []
    if v6 and not v4:
        return 6
    if v4 and not v6:
        return 4
    if v4 and v6 and origin and origin.real_ip:
        orig_fam = ip_family(origin.real_ip)
        if orig_fam in (4, 6):
            return orig_fam
    return None


def default_port_for(protocol):
    return DEFAULT_PORTS.get(protocol)


def column_index(cell_ref):
    letters = re.match(r"([A-Z]+)", cell_ref).group(1)
    index = 0
    for char in letters:
        index = index * 26 + ord(char) - ord("A") + 1
    return index


def first_sheet_path(workbook):
    """Descobre o XML da primeira aba (nem sempre e sheet1.xml)."""
    default = "xl/worksheets/sheet1.xml"
    try:
        wb_root = ET.fromstring(workbook.read("xl/workbook.xml"))
        sheet = wb_root.find("a:sheets/a:sheet", NS)
        rel_id = sheet.attrib.get(f"{{{REL_NS}}}id") if sheet is not None else None
        rels_root = ET.fromstring(workbook.read("xl/_rels/workbook.xml.rels"))
        for rel in rels_root.findall(f"{{{PKG_REL_NS}}}Relationship"):
            if rel.attrib.get("Id") == rel_id:
                target = rel.attrib["Target"]
                if target.startswith("/"):
                    path = target.lstrip("/")
                else:
                    path = posixpath.normpath(posixpath.join("xl", target))
                if path in workbook.namelist():
                    return path
    except (KeyError, ET.ParseError):
        pass
    return default


def read_first_sheet(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Planilha nao encontrada: {path}")

    with zipfile.ZipFile(path) as workbook:
        shared_strings = []
        if "xl/sharedStrings.xml" in workbook.namelist():
            root = ET.fromstring(workbook.read("xl/sharedStrings.xml"))
            for item in root.findall("a:si", NS):
                # Ignora textos foneticos (rPh), que nao fazem parte do valor da celula.
                parts = [node.text or "" for node in item.findall("a:t", NS)]
                parts += [node.text or "" for node in item.findall("a:r/a:t", NS)]
                shared_strings.append("".join(parts))

        root = ET.fromstring(workbook.read(first_sheet_path(workbook)))
        rows = {}
        for row in root.findall(".//a:sheetData/a:row", NS):
            row_number = int(row.attrib["r"])
            values = {}
            for cell in row.findall("a:c", NS):
                ref = cell.attrib["r"]
                value_node = cell.find("a:v", NS)
                inline_node = cell.find("a:is", NS)
                value = ""
                if value_node is not None:
                    value = value_node.text or ""
                    if cell.attrib.get("t") == "s":
                        value = shared_strings[int(value)]
                elif inline_node is not None:
                    value = "".join(node.text or "" for node in inline_node.iter(f"{{{NS['a']}}}t"))
                values[column_index(ref)] = normalize_text(value)
            rows[row_number] = values
        return rows


def find_header_cell(rows, accepted_headers):
    accepted = {normalize_header(header) for header in accepted_headers}
    for row_number, columns in rows.items():
        for col_number, value in columns.items():
            if normalize_header(value) in accepted:
                return row_number, col_number
    raise ValueError(f"Nao encontrei o cabecalho: {', '.join(accepted_headers)}")


def read_table(rows, header_row, start_col, headers, optional_headers=None):
    optional_headers = optional_headers or {}
    header_map = {}
    normalized_expected = {
        key: {normalize_header(alias) for alias in aliases}
        for key, aliases in {**headers, **optional_headers}.items()
    }

    for col_number, value in sorted(rows.get(header_row, {}).items()):
        if col_number < start_col:
            continue
        normalized = normalize_header(value)
        for key, aliases in normalized_expected.items():
            # O primeiro cabecalho encontrado vence; evita que uma coluna homonima
            # de outra tabela na mesma linha sobrescreva o mapeamento.
            if normalized in aliases and key not in header_map:
                header_map[key] = col_number
                break

    missing = [key for key in headers if key not in header_map]
    if missing:
        raise ValueError(f"Colunas obrigatorias nao encontradas: {', '.join(missing)}")

    records = []
    for row_number in sorted(row for row in rows if row > header_row):
        row = rows[row_number]
        values = {key: row.get(header_map.get(key), "") for key in headers}
        values.update({key: row.get(header_map.get(key), "") for key in optional_headers})
        if not any(normalize_text(value) for value in values.values()):
            continue
        records.append((row_number, values))
    return records


def resolve_target_ips(host):
    """Resolve registros A (IPv4) e AAAA (IPv6) de forma auditavel e deterministica."""
    ip_lit = valid_ip(host)
    if ip_lit:
        ver = ipaddress.ip_address(ip_lit).version
        return {
            "ipv4": [ip_lit] if ver == 4 else [],
            "ipv6": [ip_lit] if ver == 6 else [],
            "all": [ip_lit],
            "is_ip": True,
        }
    ipv4, ipv6, all_ips = [], [], []
    try:
        infos = socket.getaddrinfo(host, None)
        for family, _, _, _, sockaddr in infos:
            addr = valid_ip(sockaddr[0])
            if not addr:
                continue
            if family == socket.AF_INET and addr not in ipv4:
                ipv4.append(addr)
            elif family == socket.AF_INET6 and addr not in ipv6:
                ipv6.append(addr)
            if addr not in all_ips:
                all_ips.append(addr)
    except (socket.gaierror, UnicodeError, OSError):
        pass
    return {"ipv4": ipv4, "ipv6": ipv6, "all": all_ips, "is_ip": False}


def expand_targets_by_dns(targets, resolver_fn=resolve_target_ips, origins=None):
    """Expande destinos que sao hostnames com multiplos IPs A/AAAA em um teste por IP.

    Para hostnames dual-stack (com registros A e AAAA), quando a origem possui `IP Real`
    configurado, filtra os enderecos expandidos para a familia IP correspondente ao `IP Real`.
    """
    expanded = []
    for target in targets:
        if target.error or valid_ip(target.host):
            if valid_ip(target.host) and not target.resolved_ips:
                info = resolver_fn(target.host)
                target.resolved_ips = {"ipv4": info["ipv4"], "ipv6": info["ipv6"]}
                target.effective_ip = valid_ip(target.host)
            expanded.append(target)
            continue

        info = resolver_fn(target.host)
        existing_v4 = (target.resolved_ips or {}).get("ipv4") or []
        existing_v6 = (target.resolved_ips or {}).get("ipv6") or []
        v4_list = info["ipv4"] or list(existing_v4)
        v6_list = info["ipv6"] or list(existing_v6)
        resolved_dict = {"ipv4": v4_list, "ipv6": v6_list}
        all_ips = list(info["all"] or (v4_list + [ip for ip in v6_list if ip not in v4_list]))

        origin = (origins or {}).get(target.origin_number) if target.origin_number else None
        orig_fam = ip_family(origin.real_ip) if (origin and origin.real_ip) else None
        candidate_ips = all_ips
        if orig_fam == 4 and v4_list and v6_list:
            candidate_ips = list(v4_list)
        elif orig_fam == 6 and v4_list and v6_list:
            candidate_ips = list(v6_list)

        if len(all_ips) <= 1 and len(candidate_ips) <= 1:
            target.resolved_ips = resolved_dict
            if candidate_ips:
                target.effective_ip = candidate_ips[0]
            expanded.append(target)
        else:
            for ip in candidate_ips:
                desc = target.description
                suffix = f"[DNS {target.host} -> {ip}]"
                new_desc = f"{desc} {suffix}".strip() if desc else suffix
                expanded.append(
                    TestTarget(
                        row=target.row,
                        origin_number=target.origin_number,
                        host=ip,
                        port=target.port,
                        protocol=target.protocol,
                        description=new_desc,
                        transport=target.transport,
                        error=target.error,
                        resolved_ips=resolved_dict,
                        effective_ip=ip,
                        original_host=target.original_host or target.host,
                    )
                )
    return expanded


def load_template(path, expand_dns=False):
    rows = read_first_sheet(path)

    target_header_row, target_start_col = find_header_cell(
        rows, ["Origem(Número)", "Origem(Numero)", "Origem"]
    )
    origin_header_row, origin_start_col = find_header_cell(
        rows, ["Número origem", "Numero origem"]
    )

    target_rows = read_table(
        rows,
        target_header_row,
        target_start_col,
        {
            "origin_number": ["Origem(Número)", "Origem(Numero)", "Origem"],
            "host": ["Hostname/IP", "Host", "IP"],
            "port": ["Portas (Opcional)", "Porta", "Portas"],
            "protocol": ["Protocolos (Opcional)", "Protocolo", "Protocolos"],
            "description": ["Descrição (Opcional)", "Descricao (Opcional)", "Descricao"],
        },
    )
    origin_rows = read_table(
        rows,
        origin_header_row,
        origin_start_col,
        {
            "number": ["Número origem", "Numero origem"],
            "host": ["Hostname/IP", "Host", "IP"],
            "port": ["Porta (Opcional)", "Porta", "Portas"],
        },
        {
            "username": ["Usuario", "Usuário", "User", "Username"],
            "password": ["Senha", "Password"],
            "real_ip": [
                "IP Real (Opcional)",
                "IP Real",
                "IP Origem Real",
                "IP Regra",
                "IP Regra (Opcional)",
                "IP Sinalizacao",
                "IP Interface",
            ],
        },
    )

    origins = {}
    for row_number, values in origin_rows:
        number = normalize_text(values["number"])
        host = normalize_text(values["host"])
        if not number or not host:
            continue
        origin_errors = []
        raw_port = normalize_text(values["port"])
        if not raw_port:
            port = 22
        else:
            parsed_port = parse_port(raw_port, default=None)
            if parsed_port is None or not (1 <= parsed_port <= 65535):
                origin_errors.append(
                    f"Origem {number} (linha {row_number}): porta SSH invalida na planilha: '{raw_port}'"
                )
                port = 22
            else:
                port = parsed_port
        access_protocol = "telnet" if port in (21, 23) else "ssh"
        real_ip_text = normalize_text(values.get("real_ip"))
        real_ip = valid_ip(real_ip_text) if real_ip_text else ""
        if real_ip_text and not real_ip:
            msg = (
                f"Origem {number} (linha {row_number}): "
                f"IP Real invalido na planilha: '{real_ip_text}'"
            )
            print(f"\033[93m[AVISO]\033[0m {msg}")
            origin_errors.append(msg)

        raw_password = values.get("password")
        resolved_pw, cred_source, cred_ref, secret_err = resolve_secret_reference(raw_password)
        if secret_err:
            msg = f"Origem {number} (linha {row_number}): {secret_err}"
            origin_errors.append(msg)

        if number in origins:
            print(
                f"\033[93m[AVISO]\033[0m Numero de origem {number} duplicado "
                f"(linha {row_number}); a ultima ocorrencia sera usada."
            )
        origins[number] = Origin(
            number,
            host,
            port,
            access_protocol,
            normalize_text(values.get("username")),
            resolved_pw,
            real_ip,
            error=" | ".join(origin_errors) if origin_errors else None,
            row=row_number,
            credential_source=cred_source,
            credential_ref=cred_ref,
        )

    targets = []
    for row_number, values in target_rows:
        host = normalize_text(values["host"])
        if not host:
            continue
        raw_protocol = values["protocol"]
        hinted_transport = PROTOCOL_TRANSPORT_HINTS.get(protocol_key(raw_protocol))
        port_specs, invalid_ports = parse_port_specs(values["port"])
        ip_lit = valid_ip(host)
        initial_resolved = (
            {
                "ipv4": [ip_lit] if ipaddress.ip_address(ip_lit).version == 4 else [],
                "ipv6": [ip_lit] if ipaddress.ip_address(ip_lit).version == 6 else [],
            }
            if ip_lit
            else {}
        )
        common = {
            "row": row_number,
            "origin_number": normalize_text(values["origin_number"]),
            "host": host,
            "description": normalize_text(values["description"]),
            "resolved_ips": initial_resolved,
            "effective_ip": ip_lit or "",
            "original_host": host,
        }
        for token in invalid_ports:
            targets.append(
                TestTarget(
                    port=None,
                    protocol=normalize_protocol(raw_protocol),
                    error=f"Porta invalida na planilha: '{token}'",
                    **common,
                )
            )
        for port, transport in port_specs:
            protocol = normalize_protocol(raw_protocol, port)
            if not protocol_key(raw_protocol) and transport == "udp":
                protocol = "udp"
            if port is None:
                port = default_port_for(protocol)
            targets.append(
                TestTarget(
                    port=port,
                    protocol=protocol,
                    transport=transport or hinted_transport,
                    **common,
                )
            )
    if expand_dns:
        targets = expand_targets_by_dns(targets, origins=origins)
    return targets, origins


def test_tcp(host, port, timeout=TIMEOUT_SECONDS):
    if port is None:
        return False, "TCP precisa de uma porta"
    with socket.create_connection((host, port), timeout=timeout):
        return True, f"TCP conectado na porta {port}"


def test_udp(host, port, timeout=TIMEOUT_SECONDS):
    """Testa conectividade UDP com semantica conservadora:

    - UDP_RESPONDED (recebeu pacote de resposta): True
    - UDP_REFUSED (ICMP port unreachable / ConnectionRefusedError): False
    - UDP_NO_RESPONSE (timeout sem resposta): False (inconclusivo, nunca sucesso confirmado)
    """
    if port is None:
        return False, "UDP precisa de uma porta"
    family = socket.AF_INET6 if (valid_ip(host) and ipaddress.ip_address(valid_ip(host)).version == 6) else socket.AF_INET
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
        if infos:
            family = infos[0][0]
    except OSError:
        pass
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(b"connectivity-test")
        try:
            data = sock.recv(1024)
            return True, f"UDP_RESPONDED: UDP recebeu resposta ({len(data)} bytes)"
        except socket.timeout:
            return False, "UDP_NO_RESPONSE: UDP enviado; sem resposta, resultado inconclusivo"
        except ConnectionRefusedError:
            return False, "UDP_REFUSED: UDP recusado pelo destino"


def test_icmp(host, _port=None, timeout=TIMEOUT_SECONDS):
    clean_host = valid_ip(host) or host
    is_ipv6 = ip_family(clean_host) == 6
    if python_ping and not is_ipv6:
        try:
            response = python_ping(clean_host, count=2, timeout=timeout, verbose=False)
            return response.success(), str(response)
        except (PermissionError, OSError):
            # pythonping precisa de root (raw socket); sem permissao usa o ping do sistema.
            pass

    if os.name == "nt":
        command = (
            ["ping", "-6", "-n", "2", "-w", str(timeout * 1000), clean_host]
            if is_ipv6
            else ["ping", "-n", "2", "-w", str(timeout * 1000), clean_host]
        )
    else:
        command = (
            ["ping", "-6", "-c", "2", "-W", str(timeout), clean_host]
            if is_ipv6
            else ["ping", "-c", "2", "-W", str(timeout), clean_host]
        )
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout * 2 + 5,
        check=False,
    )
    detail = completed.stdout.strip() or completed.stderr.strip()
    ok = completed.returncode == 0
    if os.name == "nt":
        # No Windows o ping retorna 0 ate com "Destination host unreachable";
        # so ha resposta real quando aparece TTL= na saida.
        ok = ok and ("ttl=" in completed.stdout.lower() or is_ipv6)
    return ok, detail.splitlines()[-1] if detail else "sem saida"


def test_http(host, port=None, timeout=TIMEOUT_SECONDS, use_tls=False):
    port = port or (443 if use_tls else 80)
    connection_class = http.client.HTTPSConnection if use_tls else http.client.HTTPConnection
    connection = connection_class(host, port, timeout=timeout)
    try:
        connection.request("HEAD", "/")
        response = connection.getresponse()
        return 100 <= response.status < 500, f"HTTP status {response.status}"
    finally:
        connection.close()


def test_ssh(host, port=None, timeout=TIMEOUT_SECONDS):
    port = port or DEFAULT_PORTS["ssh"]
    if paramiko:
        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            transport = paramiko.Transport(sock)
            transport.start_client(timeout=timeout)
            banner = transport.remote_version
            return True, f"SSH respondeu: {banner}"
        finally:
            try:
                transport.close()
            except Exception:
                pass
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        banner = sock.recv(128).decode(errors="replace").strip()
        return banner.startswith("SSH"), banner or "porta aberta, sem banner SSH"


def test_telnet(host, port=None, timeout=TIMEOUT_SECONDS):
    port = port or DEFAULT_PORTS["telnet"]
    if telnetlib:
        conn = telnetlib.Telnet(host, port, timeout)
        conn.close()
        return True, f"Telnet conectado na porta {port}"
    return test_tcp(host, port, timeout)


def test_ftp(host, port=None, timeout=TIMEOUT_SECONDS):
    port = port or DEFAULT_PORTS["ftp"]
    ftp = FTP()
    try:
        banner = ftp.connect(host, port, timeout=timeout)
        return True, banner
    finally:
        try:
            ftp.close()
        except Exception:
            pass


def test_dns(host, port=None, timeout=TIMEOUT_SECONDS):
    port = port or DEFAULT_PORTS["dns"]
    if dns:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [host]
        resolver.port = port
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answer = resolver.resolve("google.com", "A")
        return bool(answer), f"DNS respondeu {len(answer)} registro(s)"

    query = (
        b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x06google\x03com\x00\x00\x01\x00\x01"
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query, (host, port))
        data, _ = sock.recvfrom(512)
        return len(data) > 12, f"DNS respondeu {len(data)} bytes"


def test_ntp(host, port=None, timeout=TIMEOUT_SECONDS):
    port = port or DEFAULT_PORTS["ntp"]
    if ntplib:
        response = ntplib.NTPClient().request(host, port=port, version=3, timeout=timeout)
        return True, f"NTP offset {response.offset:.3f}s"

    packet = b"\x1b" + 47 * b"\0"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (host, port))
        data, _ = sock.recvfrom(48)
        if len(data) < 48:
            return False, "resposta NTP incompleta"
        timestamp = struct.unpack("!12I", data)[10] - 2208988800
        return True, f"NTP respondeu em {time.ctime(timestamp)}"


def test_snmp(host, port=None, timeout=TIMEOUT_SECONDS):
    port = port or DEFAULT_PORTS["snmp"]
    if CommunityData:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData("public", mpModel=0),
            UdpTransportTarget((host, port), timeout=timeout, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
        )
        error_indication, error_status, _, var_binds = next(iterator)
        if error_indication:
            return False, str(error_indication)
        if error_status:
            return False, str(error_status)
        return True, str(var_binds[0])
    return test_udp(host, port, timeout)


def test_tftp(host, port=None, timeout=TIMEOUT_SECONDS):
    port = port or DEFAULT_PORTS["tftp"]
    if tftpy:
        client = tftpy.TftpClient(host, port)
        try:
            client.context = None
            return test_udp(host, port, timeout)
        except Exception as exc:
            return False, str(exc)
    return test_udp(host, port, timeout)


# ---------------------------------------------------------------------------
# Traces (traceroute / tracert / tracepath)
#
# Importante: traceroute e tracepath retornam codigo 0 mesmo quando NAO chegam ao
# destino. Por isso o resultado e decidido analisando a saida hop a hop
# (TraceAnalyzer), e nao pelo codigo de saida do comando.
# ---------------------------------------------------------------------------

HOP_LINE_RE = re.compile(r"^\s*(\d+)\??:?\s+(\S.*)$")
TRACEROUTE_HEADER_RE = re.compile(r"^traceroute\s+to\s+\S+\s+\(([^)]+)\)", re.IGNORECASE)
TRACEPATH_RESUME_REACHED_RE = re.compile(r"Resume:.*\bhops\s+\d+", re.IGNORECASE)
UNREACHABLE_RE = re.compile(r"(?<!\S)!([A-Z]|F-?\d*|<\d+>)(?!\S)")

UNREACHABLE_CODES = {
    "H": "host inalcancavel",
    "N": "rede inalcancavel",
    "P": "protocolo inalcancavel",
    "S": "falha de source route",
    "F": "fragmentacao necessaria",
    "X": "comunicacao administrativamente proibida (filtro/ACL)",
    "A": "comunicacao com a rede proibida",
    "Z": "comunicacao com o host proibida",
    "V": "violacao de precedencia",
    "C": "corte de precedencia",
}

PRIVILEGE_ERROR_MARKERS = (
    "enough privileges",
    "operation not permitted",
    "you must be root",
    "requires root",
    "permission denied",
    "cap_net_raw",
)
HOP_ERROR_MARKERS = (
    "send failed",
    "write error",
    "socket:",
    "bind:",
    "cannot assign requested address",
    "network is unreachable",
    "no route to host",
)


def extract_ips(text):
    """Retorna os IPs (v4/v6) presentes em um trecho de saida de trace."""
    ips = []
    for token in re.split(r"[\s\[\]()]+", text):
        ip = valid_ip(token.rstrip(",:"))
        if ip and ip not in ips:
            ips.append(ip)
    return ips


def describe_unreachable(code):
    key = code[0] if code else ""
    return f"!{code} ({UNREACHABLE_CODES.get(key, 'destino inalcancavel')})"


class TraceAnalyzer:
    """Acompanha a saida de um trace linha a linha e decide se o destino foi alcancado."""

    def __init__(self, tool, host, extra_dest_ips=()):
        self.tool = tool
        self.host = host
        self.dest_ips = set(extra_dest_ips)
        if valid_ip(host):
            self.dest_ips.add(valid_ip(host))
        self.lines = []
        self.hops = {}  # hop -> lista de IPs que responderam
        self.max_hop = 0
        self.reached_hop = None
        self.reached_ip = None
        self.reached_annotation = None
        self.resume_reached = False
        self.too_many_hops = False
        self.unreachable = None  # (hop, ip, codigo)
        self.stop_reason = None
        self.needs_privilege = False
        self.errors = []
        self.exit_code = None
        self.stopped_early = False
        self.classification = None
        self.header_ip = None

    @property
    def has_hops(self):
        return bool(self.hops)

    def normalized_hops(self):
        """Retorna sequencia normalizada de hops (sem RTT/timestamps) para comparacao deterministica."""
        result = []
        for hop in sorted(self.hops.keys()):
            ips = list(self.hops[hop])
            result.append(
                {
                    "hop": hop,
                    "ips": ips,
                    "replied": bool(ips),
                }
            )
        return result

    def consecutive_no_reply(self):
        count = 0
        for hop in range(self.max_hop, 0, -1):
            if hop not in self.hops or self.hops[hop]:
                break
            count += 1
        return count

    def last_replied_hop(self):
        for hop in range(self.max_hop, 0, -1):
            if self.hops.get(hop):
                return hop, self.hops[hop][-1]
        return None

    def _parse_info_line(self, line):
        lowered = line.lower()
        stripped = line.strip()
        header = TRACEROUTE_HEADER_RE.match(stripped)
        if header and valid_ip(header.group(1)):
            ip = valid_ip(header.group(1))
            self.dest_ips.add(ip)
            self.header_ip = ip
        elif self.tool == "tracert" and not self.hops:
            # Cabecalho do tracert: "Tracing route to nome [1.2.3.4]" (ou em portugues).
            extracted = extract_ips(line)
            self.dest_ips.update(extracted)
            if extracted and not self.header_ip:
                self.header_ip = extracted[0]
        if TRACEPATH_RESUME_REACHED_RE.search(line):
            self.resume_reached = True
        if "too many hops" in lowered:
            self.too_many_hops = True
        if any(marker in lowered for marker in PRIVILEGE_ERROR_MARKERS):
            self.needs_privilege = True
        is_benign_info = (
            not stripped
            or bool(header)
            or lowered.lstrip().startswith(
                (
                    "tracing route",
                    "rastreando",
                    "over a maximum",
                    "com no m",
                    "trace complete",
                    "rastreamento conclu",
                    "resume:",
                )
            )
        )
        if not is_benign_info:
            self.errors.append(stripped)

    def feed(self, raw_line):
        """Processa uma linha. Retorna True quando o trace deve ser interrompido."""
        line = raw_line.rstrip("\r\n")
        match = HOP_LINE_RE.match(line)
        if not match:
            self.lines.append(line)
            self._parse_info_line(line)
            return False

        hop = int(match.group(1))
        if hop > TRACE_MAX_HOPS:
            # tracepath nao recebe limite de hops por parametro (compatibilidade com
            # versoes antigas); o limite e aplicado aqui.
            self.stop_reason = "max_hops"
            self.stopped_early = True
            return True

        self.lines.append(line)
        rest = match.group(2)
        rest_lower = rest.lower()
        if "[localhost]" in rest_lower:
            return False

        if any(marker in rest_lower for marker in PRIVILEGE_ERROR_MARKERS):
            self.needs_privilege = True
            self.errors.append(line.strip())
            return False

        if any(marker in rest_lower for marker in HOP_ERROR_MARKERS):
            self.errors.append(line.strip())
            return False

        ips = extract_ips(rest)
        replied = self.hops.setdefault(hop, [])
        for ip in ips:
            if ip not in replied:
                replied.append(ip)
        self.max_hop = max(self.max_hop, hop)

        annotation = UNREACHABLE_RE.search(rest)
        code = annotation.group(1) if annotation else None
        if not code and "net error" in rest_lower:
            code = "H"

        if self.tool == "tracepath":
            # No tracepath uma linha com o IP do destino pode ser apenas "pmtu N" antes de
            # "no reply" ou "!A". So confirma chegada quando a linha traz "reached" (ou
            # registra falha se trouxer anotacao de inalcancavel como !A, !H, !N, !P).
            matches_dest = not self.dest_ips or bool(self.dest_ips.intersection(ips))
            if code and ips:
                if matches_dest and (self.reached_hop is None or self.reached_hop == hop):
                    self.reached_hop = hop
                    matching = [ip for ip in ips if ip in self.dest_ips]
                    self.reached_ip = matching[0] if matching else ips[-1]
                    self.reached_annotation = code
                elif self.unreachable is None:
                    self.unreachable = (hop, ips[-1], code)
            elif bool(ips) and re.search(r"\breached\b", rest_lower) and matches_dest:
                if self.reached_hop is None:
                    self.reached_hop = hop
                    matching = [ip for ip in ips if ip in self.dest_ips]
                    self.reached_ip = matching[0] if matching else ips[-1]
        else:
            is_destination = bool(ips) and bool(self.dest_ips.intersection(ips))
            if is_destination:
                if self.reached_hop is None:
                    self.reached_hop = hop
                    matching = [ip for ip in ips if ip in self.dest_ips]
                    self.reached_ip = matching[0] if matching else ips[-1]
                if code and not self.reached_annotation:
                    self.reached_annotation = code
            elif code and ips and self.unreachable is None:
                self.unreachable = (hop, ips[-1], code)

        if self.reached_hop is None and self.consecutive_no_reply() >= TRACE_MAX_CONSECUTIVE_NO_REPLY:
            self.stop_reason = "no_reply"
            self.stopped_early = True
            return True
        return False

    def finish(self, timed_out=False, execution_error=None, exit_code=None, stopped_early=None):
        """Classifica o trace e retorna (ok, resumo legivel)."""
        if exit_code is None:
            exit_code = self.exit_code
        if stopped_early is None:
            stopped_early = self.stopped_early

        last = self.last_replied_hop()
        last_text = f" | ultimo hop que respondeu: {last[0]} ({last[1]})" if last else ""

        if execution_error:
            self.classification = CLASSIFICATION_EXECUTION_ERROR
            return False, f"Erro ao executar o trace: {execution_error}"

        if self.reached_hop is not None:
            hop = self.reached_hop
            ip = self.reached_ip or self.host
            if self.reached_annotation:
                self.classification = CLASSIFICATION_UNREACHABLE
                return False, (
                    f"Destino {ip} respondeu no hop {hop} com "
                    f"{describe_unreachable(self.reached_annotation)}"
                )
            self.classification = CLASSIFICATION_REACHED
            return True, f"Destino {ip} alcancado no hop {hop}"

        if self.unreachable:
            hop, ip, code = self.unreachable
            self.classification = CLASSIFICATION_UNREACHABLE
            return False, (
                f"Destino NAO alcancado: hop {hop} ({ip}) retornou "
                f"{describe_unreachable(code)}{last_text}"
            )

        if self.resume_reached:
            # tracepath imprimiu "Resume: ... hops N", mas nenhuma linha de hop
            # confirmou "reached" para o destino.
            if last and self.dest_ips and last[1] in self.dest_ips and not self.errors:
                self.classification = CLASSIFICATION_REACHED
                return True, f"Destino {last[1]} alcancado no hop {last[0]}"
            if last and self.dest_ips and last[1] not in self.dest_ips:
                self.classification = CLASSIFICATION_UNCONFIRMED
                return False, (
                    f"Destino NAO alcancado (nao confirmado): tracepath encerrou no hop "
                    f"{last[0]} ({last[1]}), diferente do destino esperado{last_text}"
                )
            self.classification = CLASSIFICATION_INSUFFICIENT_EVIDENCE
            return False, (
                f"Destino NAO alcancado (evidencia insuficiente): tracepath exibiu resumo "
                f"sem confirmacao de chegada no IP de destino{last_text}"
            )

        if not self.has_hops:
            self.classification = CLASSIFICATION_EXECUTION_ERROR
            reason = " | ".join(self.errors[-2:]) if self.errors else "nenhum hop foi retornado"
            return False, f"Trace nao executado: {reason}"

        if self.errors and (
            exit_code not in (None, 0)
            or any(
                any(marker in err.lower() for marker in HOP_ERROR_MARKERS + PRIVILEGE_ERROR_MARKERS)
                for err in self.errors
            )
        ):
            self.classification = CLASSIFICATION_EXECUTION_ERROR
            reason = " | ".join(self.errors[-2:])
            return False, f"Erro ao executar o trace: {reason}{last_text}"

        if self.stop_reason == "no_reply":
            self.classification = CLASSIFICATION_UNCONFIRMED
            return False, (
                f"Destino NAO alcancado (nao confirmado): {TRACE_MAX_CONSECUTIVE_NO_REPLY} hops consecutivos "
                f"sem resposta (interrompido no hop {self.max_hop}){last_text}"
            )
        if timed_out:
            self.classification = CLASSIFICATION_TIMEOUT
            return False, (
                f"Destino NAO alcancado (timeout): trace interrompido apos {TRACE_TIMEOUT_SECONDS}s "
                f"(limite de seguranca){last_text}"
            )
        if self.stop_reason == "max_hops" or self.too_many_hops or self.max_hop >= TRACE_MAX_HOPS:
            self.classification = CLASSIFICATION_UNCONFIRMED
            return False, (
                f"Destino NAO alcancado (nao confirmado): limite de {TRACE_MAX_HOPS} hops atingido{last_text}"
            )
        if self.tool in ("traceroute", "tracert") and not self.dest_ips:
            self.classification = CLASSIFICATION_INSUFFICIENT_EVIDENCE
            return False, (
                f"Destino NAO alcancado (evidencia insuficiente): IP do destino nao identificado "
                f"na saida do {self.tool}{last_text}"
            )
        if exit_code not in (None, 0) and not stopped_early:
            self.classification = CLASSIFICATION_EXECUTION_ERROR
            err_suffix = f" ({self.errors[-1]})" if self.errors else ""
            return False, (
                f"Erro ao executar o trace: comando encerrou com codigo {exit_code}{err_suffix}{last_text}"
            )
        self.classification = CLASSIFICATION_UNCONFIRMED
        return False, f"Destino NAO alcancado (nao confirmado): trace terminou sem resposta do destino{last_text}"


@dataclass
class TraceSpec:
    tool: str
    argv: list
    method: str
    privileged: bool = False
    notes: list = field(default_factory=list)
    error: str | None = None


def build_trace_spec(target, source_ip=None, windows=False):
    """Monta o comando de trace de acordo com protocolo, porta, transporte, familia IP e IP de origem."""
    host = valid_ip(target.host) or target.host
    port = target.port
    transport = target.transport
    notes = []

    src_fam = ip_family(source_ip) if source_ip else None
    dst_fam = target_ip_family(target)
    if dst_fam is None and src_fam in (4, 6):
        resolved = target.resolved_ips or {}
        if src_fam == 6 and resolved.get("ipv6"):
            dst_fam = 6
        elif src_fam == 4 and resolved.get("ipv4"):
            dst_fam = 4

    if src_fam in (4, 6) and dst_fam in (4, 6) and src_fam != dst_fam:
        return TraceSpec(
            target.protocol,
            [],
            "",
            error=(
                f"Incompatibilidade de familia IP: IP Real de origem ({source_ip}, IPv{src_fam}) "
                f"e destino ({target.effective_ip or target.host}, IPv{dst_fam})"
            ),
        )

    is_ipv6 = dst_fam == 6

    if target.protocol == "tracepath":
        if windows:
            return TraceSpec(
                "tracepath", [], "", error="tracepath nao esta disponivel nativamente no Windows; use traceroute/tracert"
            )
        argv = ["tracepath", "-6", "-n"] if is_ipv6 else ["tracepath", "-n"]
        if port:
            argv += ["-p", str(port)]
            method = f"UDP{'v6' if is_ipv6 else ''} porta inicial {port}"
        else:
            method = f"UDP{'v6' if is_ipv6 else ''} (portas padrao do tracepath)"
        if transport in ("tcp", "icmp"):
            notes.append(
                f"tracepath so suporta UDP; o metodo {transport.upper()} foi ignorado "
                "(use 'traceroute' para TCP/ICMP)."
            )
        if source_ip:
            notes.append(
                f"tracepath nao permite escolher o IP de origem; o trace saiu pela rota padrao "
                f"(use 'traceroute' para sair pelo IP {source_ip})."
            )
        argv.append(host)
        return TraceSpec("tracepath", argv, method, notes=notes)

    if windows:
        argv = ["tracert"]
        if is_ipv6:
            argv.append("-6")
        argv += ["-d", "-h", str(TRACE_MAX_HOPS), "-w", str(TRACE_PROBE_WAIT_SECONDS * 1000), host]
        if port or transport:
            notes.append("tracert do Windows so usa ICMP; porta/metodo informados foram ignorados.")
        return TraceSpec("tracert", argv, "ICMPv6 (tracert)" if is_ipv6 else "ICMP (tracert)", notes=notes)

    argv = ["traceroute"]
    if is_ipv6:
        argv.append("-6")
    argv += [
        "-n",
        "-m", str(TRACE_MAX_HOPS),
        "-w", str(TRACE_PROBE_WAIT_SECONDS),
        "-q", str(TRACE_PROBES_PER_HOP),
    ]
    if source_ip:
        argv += ["-s", valid_ip(source_ip) or source_ip]

    # Com porta preenchida o padrao e TCP SYN (igual a regra de firewall).
    if transport is None and port:
        transport = "tcp"

    privileged = False
    if transport == "tcp":
        argv += ["-T"]
        if port:
            argv += ["-p", str(port)]
            method = f"TCP SYN porta {port}"
        else:
            method = "TCP SYN porta 80 (padrao do traceroute)"
        privileged = True
    elif transport == "udp":
        if port:
            argv += ["-U", "-p", str(port)]
            method = f"UDP porta {port}"
        else:
            method = "UDP (portas altas, padrao do traceroute)"
    elif transport == "icmp":
        argv += ["-I"]
        method = "ICMPv6 echo" if is_ipv6 else "ICMP echo"
        privileged = True
        if port:
            notes.append("Metodo ICMP nao usa porta; a porta informada foi ignorada.")
    else:
        method = "UDP (portas altas, padrao do traceroute)"

    argv.append(host)
    return TraceSpec("traceroute", argv, method, privileged=privileged, notes=notes)


def _drain_lines(chunks, analyzer, deadline):
    """Consome blocos de bytes/str de `chunks`, alimentando o analisador linha a linha.

    `chunks` e um gerador que devolve texto, None (sem dados ainda) ou "" (fim).
    Retorna (interrompido_pelo_analisador, estourou_timeout).
    """
    buffer = ""
    for chunk in chunks:
        if chunk is None:
            if time.monotonic() > deadline:
                if buffer:
                    analyzer.feed(buffer)
                return False, True
            continue
        if chunk == "":
            break
        buffer += chunk
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            if analyzer.feed(line):
                return True, False
        if time.monotonic() > deadline:
            return False, True
    if buffer.strip():
        analyzer.feed(buffer)
    return False, False


def stream_process(argv, env=None, stdin_data=None, new_session=False, status_holder=None):
    """Executa um processo local e devolve sua saida (stdout+stderr) como gerador.

    Gera texto, None (sem dados no momento) ou "" (fim). Ao fechar o gerador
    (gen.close()), o processo e encerrado. Se `status_holder` (dict) for informado,
    preenche `status_holder["exit_code"]` ao finalizar.
    """
    try:
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            text=True,
            errors="replace",
            bufsize=1,
            env=env,
            start_new_session=new_session and os.name != "nt",
        )
    except FileNotFoundError:
        if status_holder is not None:
            status_holder["exit_code"] = 127
        yield f"Comando nao encontrado: {argv[0]}\n"
        yield ""
        return

    if stdin_data is not None:
        try:
            process.stdin.write(stdin_data)
            process.stdin.close()
        except OSError:
            pass

    lines = queue.Queue()

    def reader():
        for line in process.stdout:
            lines.put(line)
        lines.put("")

    threading.Thread(target=reader, daemon=True).start()
    try:
        while True:
            try:
                chunk = lines.get(timeout=0.5)
            except queue.Empty:
                yield None
                continue
            yield chunk
            if chunk == "":
                return
    finally:
        if process.poll() is None:
            if new_session and os.name != "nt":
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    process.kill()
            else:
                process.kill()
        rc = process.wait()
        if process.stdout is not None:
            try:
                process.stdout.close()
            except Exception:
                pass
        if status_holder is not None:
            status_holder["exit_code"] = rc


def _consume_stream(chunks, analyzer):
    try:
        stopped_early, timed_out = _drain_lines(
            chunks, analyzer, time.monotonic() + TRACE_TIMEOUT_SECONDS
        )
        analyzer.stopped_early = stopped_early
    finally:
        chunks.close()
    return timed_out, None


def run_local_trace(spec, analyzer, use_sudo=False):
    argv = (["sudo", "-n"] + spec.argv) if use_sudo else spec.argv
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    status_holder = {}
    timed_out, error = _consume_stream(
        stream_process(argv, env=env, new_session=True, status_holder=status_holder),
        analyzer,
    )
    analyzer.exit_code = status_holder.get("exit_code")
    return timed_out, error


def run_remote_trace(spec, analyzer, session, sudo_password=None, use_sudo=False):
    if not hasattr(session, "stream") and hasattr(session, "get_transport"):
        session = ParamikoSession(session.get_transport(), SSH_PARAMIKO_DEFAULT)
    command = shlex.join(spec.argv)
    stdin_data = None
    if use_sudo:
        # -k: nao usa nem atualiza o cache de credenciais do sudo.
        if sudo_password:
            command = f"LC_ALL=C LANG=C sudo -k -S -p '' {command}"
            stdin_data = sudo_password + "\n"
        else:
            command = f"LC_ALL=C LANG=C sudo -n {command}"
    else:
        command = f"LC_ALL=C LANG=C {command}"
    ensure_remote_command_is_read_only(command)
    timed_out, error = _consume_stream(session.stream(command, stdin_data), analyzer)
    analyzer.exit_code = getattr(session, "last_exit_code", None)
    return timed_out, error


def resolve_local_ips(host):
    try:
        return {info[4][0] for info in socket.getaddrinfo(host, None)}
    except (socket.gaierror, UnicodeError):
        return set()


def probe_tcp_service(host, port, origin=None, session=None, timeout=TIMEOUT_SECONDS):
    """Executa probe de conexao TCP (local ou remoto) e classifica o estado do servico."""
    start = time.monotonic()
    probe_timeout = max(1, min(int(timeout), 5))
    clean_host = valid_ip(host) or host
    is_ipv6 = ip_family(clean_host) == 6
    try:
        if origin is None:
            with socket.create_connection((clean_host, port), timeout=probe_timeout):
                ms = int((time.monotonic() - start) * 1000)
                return True, SERVICE_TCP_CONNECTED, f"TCP conectado na porta {port}", ms
        if session is None or not hasattr(session, "run"):
            return False, SERVICE_NOT_TESTED, "Sessao SSH sem suporte a execucao sincrona", 0

        q_host = quote(clean_host)
        if is_ipv6:
            cmd = f"LC_ALL=C LANG=C nc -6 -nvz -w {probe_timeout} {q_host} {int(port)}"
        else:
            cmd = (
                f"LC_ALL=C LANG=C nc -nvz -w {probe_timeout} {q_host} {int(port)} "
                f"|| timeout {probe_timeout} bash -c 'cat < /dev/null > /dev/tcp/$1/$2' _ {q_host} {int(port)}"
            )
        ensure_remote_command_is_read_only(cmd)
        code, stdout, stderr = session.run(cmd, probe_timeout * 2 + 3)
        ms = int((time.monotonic() - start) * 1000)
        detail = "\n".join(p for p in (stdout.strip(), stderr.strip()) if p)
        lower = detail.lower()
        if code == 0:
            return True, SERVICE_TCP_CONNECTED, detail or f"TCP conectado na porta {port}", ms
        if "refused" in lower or "recusado" in lower:
            return False, SERVICE_TCP_REFUSED, detail or f"TCP recusado na porta {port}", ms
        return False, SERVICE_TCP_TIMEOUT, detail or f"TCP sem resposta na porta {port} (codigo {code})", ms
    except ConnectionRefusedError as exc:
        ms = int((time.monotonic() - start) * 1000)
        return False, SERVICE_TCP_REFUSED, f"TCP recusado na porta {port}: {exc}", ms
    except (socket.timeout, TimeoutError) as exc:
        ms = int((time.monotonic() - start) * 1000)
        return False, SERVICE_TCP_TIMEOUT, f"TCP timeout na porta {port}: {exc}", ms
    except Exception as exc:
        ms = int((time.monotonic() - start) * 1000)
        return False, SERVICE_EXECUTION_ERROR, f"Erro no probe TCP: {type(exc).__name__}: {exc}", ms


def probe_udp_service(host, port, origin=None, session=None, timeout=TIMEOUT_SECONDS):
    """Executa probe UDP com semantica conservadora (ausencia de resposta != sucesso)."""
    start = time.monotonic()
    probe_timeout = max(1, min(int(timeout), 3))
    clean_host = valid_ip(host) or host
    is_ipv6 = ip_family(clean_host) == 6
    try:
        if origin is None:
            ok, detail = test_udp(clean_host, port, timeout=probe_timeout)
            ms = int((time.monotonic() - start) * 1000)
            lower = detail.lower()
            if ok:
                return True, SERVICE_UDP_RESPONDED, detail, ms
            if "udp_refused" in lower or "recusado" in lower:
                return False, SERVICE_UDP_REFUSED, detail, ms
            if "udp_no_response" in lower or "sem resposta" in lower:
                return False, SERVICE_UDP_NO_RESPONSE, detail, ms
            return False, SERVICE_EXECUTION_ERROR, detail, ms

        if session is None or not hasattr(session, "run"):
            return False, SERVICE_NOT_TESTED, "Sessao SSH sem suporte a execucao sincrona", 0

        q_host = quote(clean_host)
        nc_flags = "-6 -uz" if is_ipv6 else "-uz"
        cmd = f"LC_ALL=C LANG=C nc {nc_flags} -w {probe_timeout} {q_host} {int(port)}"
        ensure_remote_command_is_read_only(cmd)
        code, stdout, stderr = session.run(cmd, probe_timeout * 2 + 3)
        ms = int((time.monotonic() - start) * 1000)
        detail = "\n".join(p for p in (stdout.strip(), stderr.strip()) if p)
        lower = detail.lower()
        if code == 0 and ("udp_responded" in lower or "recebeu resposta" in lower):
            return True, SERVICE_UDP_RESPONDED, detail, ms
        if "refused" in lower or "recusado" in lower or "udp_refused" in lower:
            return False, SERVICE_UDP_REFUSED, detail or f"UDP_REFUSED na porta {port}", ms
        if code == 0 or "udp_no_response" in lower or "timed out" in lower or "timeout" in lower:
            return (
                False,
                SERVICE_UDP_NO_RESPONSE,
                "UDP_NO_RESPONSE: UDP enviado; sem resposta confirmada da aplicacao (inconclusivo)",
                ms,
            )
        return False, SERVICE_EXECUTION_ERROR, detail or f"UDP falhou com codigo {code}", ms
    except Exception as exc:
        ms = int((time.monotonic() - start) * 1000)
        return False, SERVICE_EXECUTION_ERROR, f"Erro no probe UDP: {type(exc).__name__}: {exc}", ms


def evaluate_composite_policy(target, origin, session, trace_cls):
    """Avalia o teste de politica composto para traces com porta de destino."""
    if trace_cls == CLASSIFICATION_SSH_ERROR:
        return {
            "policy_verdict": POLICY_SOURCE_SSH_ERROR,
            "trace_result": trace_cls,
            "service_result": SERVICE_NOT_TESTED,
            "service_detail": "",
            "service_elapsed_ms": 0,
            "firewall_request_eligible": False,
        }
    if trace_cls == CLASSIFICATION_EXECUTION_ERROR:
        return {
            "policy_verdict": POLICY_SOURCE_EXECUTION_ERROR,
            "trace_result": trace_cls,
            "service_result": SERVICE_NOT_TESTED,
            "service_detail": "",
            "service_elapsed_ms": 0,
            "firewall_request_eligible": False,
        }
    if target.port is None or target.transport == "icmp":
        if trace_cls == CLASSIFICATION_REACHED:
            verdict = POLICY_NOT_APPLICABLE
            eligible = True
        elif trace_cls == CLASSIFICATION_UNREACHABLE:
            verdict = POLICY_TRACE_UNREACHABLE
            eligible = False
        else:
            verdict = POLICY_TRACE_UNCONFIRMED
            eligible = False
        return {
            "policy_verdict": verdict,
            "trace_result": trace_cls,
            "service_result": SERVICE_NOT_TESTED,
            "service_detail": "",
            "service_elapsed_ms": 0,
            "firewall_request_eligible": eligible,
        }

    transport = "udp" if (target.protocol == "tracepath" or target.transport == "udp") else "tcp"
    probe_host = (
        target.effective_ip
        if (target.effective_ip and ip_family(target.effective_ip) == 6)
        else (valid_ip(target.host) or target.host)
    )
    if origin is not None and (session is None or not hasattr(session, "run")):
        svc_res = SERVICE_NOT_TESTED
        svc_detail = ""
        svc_ms = 0
    elif transport == "tcp":
        _, svc_res, svc_detail, svc_ms = probe_tcp_service(probe_host, target.port, origin, session)
    else:
        _, svc_res, svc_detail, svc_ms = probe_udp_service(probe_host, target.port, origin, session)

    if trace_cls == CLASSIFICATION_REACHED:
        if transport == "tcp":
            if svc_res == SERVICE_TCP_CONNECTED:
                verdict = POLICY_TRACE_REACHED_TCP_CONNECTED
                eligible = True
            elif svc_res == SERVICE_TCP_REFUSED:
                verdict = POLICY_TRACE_REACHED_TCP_REFUSED
                eligible = False
            elif svc_res == SERVICE_NOT_TESTED:
                verdict = POLICY_TRACE_REACHED_TCP_CONNECTED
                eligible = True
            else:
                verdict = POLICY_TRACE_REACHED_TCP_TIMEOUT
                eligible = False
        else:
            if svc_res == SERVICE_UDP_RESPONDED:
                verdict = POLICY_TRACE_REACHED_UDP_RESPONDED
                eligible = True
            elif svc_res == SERVICE_UDP_REFUSED:
                verdict = POLICY_TRACE_REACHED_UDP_REFUSED
                eligible = False
            else:
                verdict = POLICY_TRACE_REACHED_UDP_NO_RESPONSE
                eligible = False
    elif trace_cls == CLASSIFICATION_UNREACHABLE:
        verdict = POLICY_TRACE_UNREACHABLE
        eligible = False
    else:
        verdict = POLICY_TRACE_UNCONFIRMED
        eligible = False

    return {
        "policy_verdict": verdict,
        "trace_result": trace_cls,
        "service_result": svc_res,
        "service_detail": sanitize_text(svc_detail),
        "service_elapsed_ms": svc_ms,
        "firewall_request_eligible": eligible,
    }


def run_trace(target, origin=None, ssh_pool=None):
    """Executa o trace (local ou na origem via SSH) e devolve um TestResult."""
    start = time.monotonic()
    source_ip = origin.real_ip if origin else ""
    windows = origin is None and os.name == "nt"
    spec = build_trace_spec(target, source_ip or None, windows=windows)

    def result(
        ok,
        summary,
        detail,
        notes=(),
        classification="",
        trace_classification="",
        hops=None,
        composite=None,
    ):
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return TestResult(
            target,
            origin,
            ok,
            "OK" if ok else "FALHA",
            detail,
            elapsed_ms,
            summary=summary,
            method=spec.method,
            command=shlex.join(spec.argv) if spec.argv else "",
            notes=list(spec.notes) + list(notes),
            classification=classification,
            trace_classification=trace_classification or classification,
            hops=hops or [],
            composite=composite,
        )

    if origin and origin.error:
        return result(
            False,
            origin.error,
            origin.error,
            classification=CLASSIFICATION_EXECUTION_ERROR,
            trace_classification=CLASSIFICATION_EXECUTION_ERROR,
        )

    if spec.error:
        return result(
            False,
            spec.error,
            spec.error,
            classification=CLASSIFICATION_EXECUTION_ERROR,
            trace_classification=CLASSIFICATION_EXECUTION_ERROR,
        )

    ssh_connected = origin is None
    client = None
    try:
        if origin:
            client = (ssh_pool or SSHPool()).get(origin)
            ssh_connected = True

            def execute(use_sudo):
                analyzer = TraceAnalyzer(spec.tool, target.host)
                timed_out, error = run_remote_trace(
                    spec, analyzer, client, origin.password, use_sudo=use_sudo
                )
                return analyzer, timed_out, error
        else:
            extra_ips = resolve_local_ips(target.host)
            if not target.resolved_ips:
                resolved_info = resolve_target_ips(target.host)
                target.resolved_ips = {
                    "ipv4": resolved_info["ipv4"],
                    "ipv6": resolved_info["ipv6"],
                }

            def execute(use_sudo):
                analyzer = TraceAnalyzer(spec.tool, target.host, extra_ips)
                timed_out, error = run_local_trace(spec, analyzer, use_sudo=use_sudo)
                return analyzer, timed_out, error

        extra_notes = []
        analyzer, timed_out, error = execute(False)
        if not analyzer.has_hops and analyzer.needs_privilege and not windows and ALLOW_SUDO_FALLBACK:
            # TCP SYN (-T) e ICMP (-I) exigem root: tenta novamente com sudo.
            extra_notes.append(
                f"{spec.method} exige root; executado novamente com sudo "
                "(--allow-sudo-fallback ativo: o SO remoto pode registrar auditoria em syslog/lecture)."
            )
            first_output = "\n".join(analyzer.lines)
            analyzer, timed_out, error = execute(True)
            if not analyzer.has_hops:
                analyzer.lines = [first_output, "[sudo]"] + analyzer.lines
                extra_notes.append(
                    "sudo falhou: verifique se o usuario tem sudo e se a senha da planilha "
                    "e a mesma do sudo (ou execute como root)."
                )
        elif not analyzer.has_hops and analyzer.needs_privilege and not windows:
            extra_notes.append(
                f"{spec.method} exige privilegio (root/CAP_NET_RAW) e o fallback com sudo esta "
                "desabilitado por padrao para preservar zero escrita remota "
                "(use --allow-sudo-fallback se desejar permitir sudo)."
            )

        if (
            any("cannot assign requested address" in line.lower() for line in analyzer.lines)
            or (origin and origin.remote_preflight.get("real_ip_present") is False)
        ) and source_ip:
            extra_notes.append(
                f"O IP real {source_ip} nao esta configurado nesta origem (verifique a coluna IP Real)."
            )

        ok, summary = analyzer.finish(
            timed_out,
            error,
            exit_code=analyzer.exit_code,
            stopped_early=analyzer.stopped_early,
        )
        trace_cls = analyzer.classification or CLASSIFICATION_EXECUTION_ERROR
        # Regra inviolavel: trace so pode ser OK se a classificacao do trace for REACHED.
        if trace_cls != CLASSIFICATION_REACHED:
            ok = False

        if analyzer.reached_ip:
            target.effective_ip = analyzer.reached_ip
        elif analyzer.header_ip and not target.effective_ip:
            target.effective_ip = analyzer.header_ip

        composite = evaluate_composite_policy(
            target, origin, client, trace_cls
        )
        global_cls = trace_cls
        if trace_cls == CLASSIFICATION_REACHED:
            pv = composite.get("policy_verdict", POLICY_NOT_APPLICABLE)
            svc_res = composite.get("service_result", SERVICE_NOT_TESTED)
            if pv == POLICY_TRACE_REACHED_UDP_NO_RESPONSE or svc_res == SERVICE_UDP_NO_RESPONSE:
                ok = False
                global_cls = CLASSIFICATION_UNCONFIRMED
                summary = (
                    f"{summary} | rota alcancou o host de destino, mas porta UDP {target.port} "
                    f"nao respondeu (UDP_NO_RESPONSE: servico inconclusivo)"
                )
            elif pv in (POLICY_TRACE_REACHED_TCP_REFUSED, POLICY_TRACE_REACHED_UDP_REFUSED) or svc_res in (
                SERVICE_TCP_REFUSED,
                SERVICE_UDP_REFUSED,
            ):
                ok = False
                global_cls = CLASSIFICATION_UNCONFIRMED
                summary = (
                    f"{summary} | rota alcancou o host de destino, mas a porta {target.port} "
                    f"recusou a conexao ({svc_res})"
                )
            elif pv == POLICY_TRACE_REACHED_TCP_TIMEOUT or svc_res in (
                SERVICE_TCP_TIMEOUT,
                SERVICE_EXECUTION_ERROR,
            ):
                ok = False
                global_cls = CLASSIFICATION_UNCONFIRMED
                summary = (
                    f"{summary} | rota alcancou o host de destino, mas o probe de servico na porta "
                    f"{target.port} falhou ({svc_res})"
                )

        detail = "\n".join(analyzer.lines).strip("\n").rstrip() or "sem saida"
        return result(
            ok,
            summary,
            detail,
            extra_notes,
            classification=global_cls,
            trace_classification=trace_cls,
            hops=analyzer.normalized_hops(),
            composite=composite,
        )
    except Exception as exc:
        message = sanitize_text(f"{type(exc).__name__}: {exc}")
        cls = (
            CLASSIFICATION_SSH_ERROR
            if not ssh_connected
            else CLASSIFICATION_EXECUTION_ERROR
        )
        return result(
            False,
            f"Erro ao executar o trace: {message}",
            message,
            classification=cls,
            trace_classification=cls,
        )


def quote(value):
    return shlex.quote(str(value))


# ---------------------------------------------------------------------------
# Garantia de "somente leitura" nas origens + Allowlist Estrita de Comandos
#
# Nada pode ser gravado no disco dos hosts de origem. Os comandos remotos rodam via
# exec (sem PTY, sem SFTP/SCP, sem historico de shell) e tudo e lido direto da
# memoria pelo canal SSH. Todo comando remoto passa por
# ensure_remote_command_is_read_only antes de ser enviado.
# ---------------------------------------------------------------------------

REMOTE_FORBIDDEN_COMMANDS = {
    "wget", "snmpget", "snmpwalk", "snmpset", "tee", "scp", "sftp", "rsync", "dd",
    "mktemp", "touch", "mkdir", "cp", "mv", "rm", "install", "truncate", "ln", "chmod",
    "chown", "chgrp", "python", "python3", "perl", "ruby", "php", "node", "awk", "sed",
    "find", "xargs", "tar", "gzip", "bzip2", "xz", "zip", "unzip", "crontab", "at",
    "systemctl", "service", "iptables", "nft", "ufw", "firewall-cmd", "sysctl", "mount",
    "umount", "useradd", "usermod", "userdel", "passwd", "su", " eval", "exec", "source",
}
REMOTE_ALLOWED_BINARIES = {
    "traceroute", "tracepath", "ping", "nc", "curl", "dig", "nslookup", "ntpdate",
    "chronyc", "grep", "echo", "exit", "id", "ip", "getcap", "uname",
}
REMOTE_ALLOWED_WRAPPERS = {"sudo", "timeout", "bash", "command"}
REMOTE_ALLOWED_SYSTEM_DIRS = ("/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/", "/usr/local/bin/")
REMOTE_ALLOWED_REDIRECT_PREFIXES = ("/dev/null", "/dev/tcp/", "/dev/udp/")
REDIRECT_RE = re.compile(r"\d*>>?\|?\s*(?!&)(\S+)")
CURL_WRITE_OPTIONS = {
    "-o", "-O", "--output", "--remote-name", "--remote-name-all", "-c", "--cookie-jar",
    "-D", "--dump-header", "--trace", "--trace-ascii", "--libcurl", "--etag-save",
    "--hsts", "--alt-svc", "-K", "--config", "-T", "--upload-file", "-d", "--data",
    "--data-raw", "--data-binary", "-F", "--form",
}
NC_FORBIDDEN_OPTIONS = {"-l", "-e", "-c", "--sh-exec", "--exec", "-o", "-x"}
IP_ALLOWED_TOKENS = {
    "-o", "-br", "-4", "-6", "addr", "address", "route", "show", "get", "list", "dev", "from", "to",
}
SAFE_BASH_SNIPPETS = {
    "cat < /dev/null > /dev/tcp/$1/$2",
}
ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=[A-Za-z0-9_.:/-]*$")


def _validate_single_command_tokens(tokens):
    """Valida que uma clausula simples de comando remoto pertence a allowlist somente leitura."""
    idx = 0
    while idx < len(tokens) and ENV_ASSIGN_RE.match(tokens[idx]):
        idx += 1
    if idx >= len(tokens):
        raise PermissionError("Comando remoto vazio apos variaveis de ambiente")

    # Desembrulha wrappers permitidos (sudo, timeout, command -v, bash -c seguro):
    while idx < len(tokens) and tokens[idx] in REMOTE_ALLOWED_WRAPPERS:
        wrapper = tokens[idx]
        idx += 1
        if wrapper == "sudo":
            while idx < len(tokens) and tokens[idx].startswith("-"):
                flag = tokens[idx]
                if flag in ("-k", "-n", "-S"):
                    idx += 1
                elif flag == "-p":
                    idx += 2
                else:
                    raise PermissionError(f"Flag nao permitida no sudo remoto: '{flag}'")
        elif wrapper == "timeout":
            if idx >= len(tokens) or not re.match(r"^\d+(\.\d+)?[smhd]?$", tokens[idx]):
                raise PermissionError("Wrapper 'timeout' remoto requer duracao numerica")
            idx += 1
        elif wrapper == "command":
            if idx >= len(tokens) or tokens[idx] != "-v":
                raise PermissionError("Wrapper 'command' remoto permitido apenas com '-v'")
            idx += 1
            if idx >= len(tokens):
                raise PermissionError("'command -v' requer ao menos um binario")
            for target_bin in tokens[idx:]:
                if target_bin not in REMOTE_ALLOWED_BINARIES:
                    raise PermissionError(
                        f"Binario '{target_bin}' nao permitido em 'command -v'"
                    )
            return
        elif wrapper == "bash":
            if idx + 1 >= len(tokens) or tokens[idx] != "-c":
                raise PermissionError("Wrapper 'bash' remoto permitido apenas com '-c' seguro")
            snippet = tokens[idx + 1].strip()
            if snippet not in SAFE_BASH_SNIPPETS:
                raise PermissionError(
                    f"Trecho 'bash -c' nao consta na allowlist somente leitura: '{snippet}'"
                )
            for arg in tokens[idx + 2 :]:
                if any(ch in arg for ch in (";", "|", "&", "`", "$", "\n", "\r", ">", "<")):
                    raise PermissionError(f"Argumento invalido para 'bash -c': '{arg}'")
            return

    if idx >= len(tokens):
        raise PermissionError("Comando remoto incompleto apos wrapper")

    exe = tokens[idx]
    args = tokens[idx + 1 :]
    if "/" in exe:
        if not exe.startswith(REMOTE_ALLOWED_SYSTEM_DIRS):
            raise PermissionError(f"Caminho de executavel remoto nao permitido: '{exe}'")
        base_exe = os.path.basename(exe)
    else:
        base_exe = exe

    if base_exe in REMOTE_FORBIDDEN_COMMANDS or base_exe not in REMOTE_ALLOWED_BINARIES:
        raise PermissionError(
            f"Comando remoto bloqueado: '{exe}' nao consta na allowlist somente leitura"
        )

    for token in args:
        if token in REMOTE_FORBIDDEN_COMMANDS:
            raise PermissionError(
                f"Comando remoto bloqueado: '{token}' pode gravar arquivos na origem"
            )

    if base_exe == "curl":
        for token in args:
            opt = token.split("=", 1)[0]
            if opt in CURL_WRITE_OPTIONS:
                raise PermissionError(
                    f"Comando remoto bloqueado: opcao '{token}' do curl grava arquivos na origem"
                )
    elif base_exe == "nc":
        for token in args:
            if token in NC_FORBIDDEN_OPTIONS:
                raise PermissionError(
                    f"Comando remoto bloqueado: opcao '{token}' do nc nao e permitida"
                )
    elif base_exe == "ip":
        if not args:
            raise PermissionError("Comando 'ip' remoto sem subcomando")
        for token in args:
            if token in IP_ALLOWED_TOKENS:
                continue
            if valid_ip(token):
                continue
            raise PermissionError(
                f"Subcomando/argumento '{token}' do 'ip' nao permitido (somente leitura)"
            )
    elif base_exe == "id":
        for token in args:
            if token not in ("-u", "-un", "-g", "-gn"):
                raise PermissionError(f"Argumento '{token}' nao permitido para 'id'")
    elif base_exe == "getcap":
        for token in args:
            if token.startswith("-"):
                raise PermissionError(f"Flag '{token}' nao permitida para 'getcap'")
            if not token.startswith(REMOTE_ALLOWED_SYSTEM_DIRS):
                raise PermissionError(f"Caminho '{token}' nao permitido para 'getcap'")
    elif base_exe == "grep":
        for token in args:
            if token.startswith("-") and token not in ("-F", "-E", "-i", "-q", "-v", "-e"):
                raise PermissionError(f"Flag '{token}' nao permitida para 'grep'")


def ensure_remote_command_is_read_only(command):
    """Bloqueia qualquer comando remoto fora da allowlist estrita somente leitura."""
    if not isinstance(command, str) or not command.strip():
        raise PermissionError("Comando remoto vazio ou invalido")
    if any(ch in command for ch in ("\n", "\r", "\x00")):
        raise PermissionError("Comando remoto bloqueado: caracteres de controle/newline detectados")
    if "`" in command or "$(" in command or "<(" in command or ">(" in command:
        raise PermissionError("Comando remoto bloqueado: substituicao de comando/processo detectada")

    for match in REDIRECT_RE.finditer(command):
        target = match.group(1).strip("'\"")
        if not target.startswith(REMOTE_ALLOWED_REDIRECT_PREFIXES):
            raise PermissionError(
                f"Comando remoto bloqueado: redirecionamento para '{target}' gravaria na origem"
            )

    raw_tokens = [token for token in re.split(r"[\s;|&()'\"]+", command) if token]
    for token in raw_tokens:
        if token in REMOTE_FORBIDDEN_COMMANDS:
            raise PermissionError(
                f"Comando remoto bloqueado: '{token}' pode gravar arquivos na origem"
            )

    # Remove redirecionamentos seguros de descritor (2>/dev/null, >&2, 2>&1) antes de tokenizar:
    cleaned = re.sub(r"\b\d*>&\d+\b", " ", command)
    cleaned = re.sub(r"\b\d*>>?\s*/dev/null\b", " ", cleaned)

    clauses = [c.strip() for c in re.split(r"\|\||&&|;", cleaned) if c.strip()]
    if not clauses:
        raise PermissionError("Comando remoto sem clausulas executaveis")

    for clause in clauses:
        pipe_parts = [p.strip() for p in clause.split("|")]
        if len(pipe_parts) > 2:
            raise PermissionError("Comando remoto bloqueado: encadeamento de pipes nao permitido")
        for idx, part in enumerate(pipe_parts):
            try:
                part_tokens = shlex.split(part)
            except ValueError as exc:
                raise PermissionError(f"Comando remoto com aspas malformadas: {exc}") from exc
            if not part_tokens:
                raise PermissionError("Clausula vazia em comando remoto")
            if len(pipe_parts) == 2 and idx == 1 and part_tokens[0] != "grep":
                raise PermissionError(
                    f"Pipe remoto permitido apenas para 'grep', encontrado: '{part_tokens[0]}'"
                )
            _validate_single_command_tokens(part_tokens)

    return command


def remote_test_command(target):
    raw_host = valid_ip(target.host) or (
        target.effective_ip if ip_family(target.effective_ip) == 6 else target.host
    )
    is_ipv6 = target_ip_family(target) == 6 or ip_family(raw_host) == 6
    host = quote(raw_host)
    port = target.port
    timeout = int(TIMEOUT_SECONDS)
    ping_cmd = "ping -6" if is_ipv6 else "ping"
    nc_tcp = "nc -6 -z" if is_ipv6 else "nc -z"
    nc_udp = "nc -6 -uz" if is_ipv6 else "nc -uz"
    url_host = f"[{raw_host}]" if ip_family(raw_host) == 6 else target.host
    curl_glob = "-g" if ip_family(raw_host) == 6 else ""

    if target.protocol == "icmp":
        return f"{ping_cmd} -c 2 -W {timeout} {host}"

    if target.protocol == "tcp":
        if port is None:
            return "echo 'TCP precisa de uma porta' >&2; exit 2"
        if is_ipv6:
            return f"{nc_tcp} -w {timeout} {host} {port}"
        return (
            f"nc -z -w {timeout} {host} {port} "
            f"|| timeout {timeout} bash -c 'cat < /dev/null > /dev/tcp/$1/$2' _ {host} {port}"
        )

    if target.protocol == "udp":
        if port is None:
            return "echo 'UDP precisa de uma porta' >&2; exit 2"
        return f"{nc_udp} -w {timeout} {host} {port}"

    if target.protocol == "http":
        port_part = f":{port}" if port and port != 80 else ""
        url = quote(f"http://{url_host}{port_part}/")
        flags = f"-gfsSI" if curl_glob else "-fsSI"
        # Sem fallback para wget: ele pode gravar ~/.wget-hsts / wget-log na origem.
        return f"curl {flags} --max-time {timeout} {url}"

    if target.protocol == "https":
        port_part = f":{port}" if port and port != 443 else ""
        url = quote(f"https://{url_host}{port_part}/")
        flags = f"-gkfsSI" if curl_glob else "-kfsSI"
        return f"curl {flags} --max-time {timeout} {url}"

    if target.protocol == "ssh":
        port = port or DEFAULT_PORTS["ssh"]
        return f"{nc_tcp} -w {timeout} {host} {port}"

    if target.protocol == "telnet":
        port = port or DEFAULT_PORTS["telnet"]
        return f"{nc_tcp} -w {timeout} {host} {port}"

    if target.protocol == "ftp":
        port = port or DEFAULT_PORTS["ftp"]
        return f"{nc_tcp} -w {timeout} {host} {port}"

    if target.protocol == "dns":
        port = port or DEFAULT_PORTS["dns"]
        return (
            f"dig @{host} -p {port} google.com A +time={timeout} +tries=1 "
            f"|| nslookup -port={port} google.com {host}"
        )

    if target.protocol == "ntp":
        port = port or DEFAULT_PORTS["ntp"]
        if port != DEFAULT_PORTS["ntp"]:
            return f"{nc_udp} -w {timeout} {host} {port}"
        return f"ntpdate -q {host} || chronyc -n sources | grep -F {host}"

    if target.protocol == "snmp":
        port = port or DEFAULT_PORTS["snmp"]
        # Sem snmpget: o net-snmp pode gravar arquivos persistentes (snmpapp.conf) na origem.
        return f"{nc_udp} -w {timeout} {host} {port}"

    if target.protocol == "tftp":
        port = port or DEFAULT_PORTS["tftp"]
        return f"{nc_udp} -w {timeout} {host} {port}"

    if port is not None:
        return f"{nc_tcp} -w {timeout} {host} {port}"
    return f"{ping_cmd} -c 2 -W {timeout} {host}"


class HostKeyVerificationError(ConnectionError):
    """Falha na verificacao da chave publica (host key) do servidor SSH."""


def _strict_host_key_enabled():
    env_val = os.environ.get("NETCHECK_STRICT_HOST_KEY")
    if env_val is not None:
        return env_val.strip().lower() not in ("0", "false", "no", "off")
    return bool(SSH_STRICT_HOST_KEY_CHECKING)


def _known_hosts_paths():
    custom = os.environ.get("NETCHECK_KNOWN_HOSTS") or os.environ.get("SSH_KNOWN_HOSTS_FILE")
    if custom:
        return [p for p in custom.split(os.pathsep) if p], True
    candidates = [
        os.path.expanduser(os.path.join("~", ".ssh", "known_hosts")),
        os.path.expanduser(os.path.join("~", ".ssh", "known_hosts2")),
    ]
    if os.name != "nt":
        candidates += ["/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2"]
    return [p for p in candidates if os.path.exists(p)], False


class ParamikoSession:
    """Sessao SSH via paramiko (conexao reaproveitada para todos os testes da origem).

    A conexao e montada manualmente (em vez de SSHClient.connect) para conseguir
    ajustar os algoritmos aceitos antes da negociacao (fallback para servidores antigos)
    e validar a chave do servidor em memoria contra o known_hosts (somente leitura).
    Nada e gravado em disco: nem na origem, nem no known_hosts local.
    """

    def __init__(self, transport, profile_name, ssh_audit=None):
        self._transport = transport
        self.profile_name = profile_name
        self.last_exit_code = None
        self.ssh_audit = ssh_audit or SSHAuditInfo(
            profile_name=profile_name,
            backend="paramiko",
            legacy_fallback_used=(profile_name == SSH_PARAMIKO_LEGACY),
            enabled_legacy_algorithms=(
                {k: list(v) for k, v in SSH_LEGACY_ALGORITHMS.items()}
                if profile_name == SSH_PARAMIKO_LEGACY
                else {}
            ),
            sha1_signatures_enabled=(profile_name == SSH_PARAMIKO_LEGACY),
            host_key_verified=_strict_host_key_enabled(),
            security_warning=(
                "Algoritmos SSH legados habilitados via paramiko."
                if profile_name == SSH_PARAMIKO_LEGACY
                else ""
            ),
        ).to_dict()

    def is_active(self):
        return self._transport.is_active()

    def _open_channel(self):
        try:
            return self._transport.open_session(timeout=TIMEOUT_SECONDS)
        except TypeError:
            return self._transport.open_session()

    def run(self, command, timeout):
        channel = self._open_channel()
        try:
            channel.settimeout(timeout)
            channel.exec_command(command)
            channel.shutdown_write()
            stdout = channel.makefile("rb", -1).read().decode(errors="replace")
            stderr = channel.makefile_stderr("rb", -1).read().decode(errors="replace")
            code = channel.recv_exit_status()
            self.last_exit_code = code
            return code, stdout, stderr
        finally:
            channel.close()

    def stream(self, command, stdin_data=None):
        self.last_exit_code = None
        channel = self._open_channel()
        try:
            channel.set_combine_stderr(True)
            channel.settimeout(1.0)
            channel.exec_command(command)
            if stdin_data:
                channel.sendall(stdin_data.encode())
            # Fecha o stdin: se a senha do sudo estiver errada ele falha na hora, sem travar.
            channel.shutdown_write()
            while True:
                try:
                    data = channel.recv(4096)
                except socket.timeout:
                    yield None
                    continue
                yield data.decode(errors="replace") if data else ""
                if not data:
                    return
        finally:
            exit_ready = getattr(channel, "exit_status_ready", None)
            if callable(exit_ready):
                try:
                    if exit_ready():
                        self.last_exit_code = channel.recv_exit_status()
                except Exception:
                    pass
            channel.close()

    def close(self):
        self._transport.close()


# Algoritmos antigos habilitados apenas no perfil de fallback "legado" do paramiko.
SSH_LEGACY_ALGORITHMS = {
    "kex": (
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group1-sha1",
    ),
    "ciphers": ("aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc"),
    "digests": ("hmac-sha1", "hmac-sha1-96", "hmac-md5", "hmac-md5-96"),
    "key_types": ("ssh-rsa", "ssh-dss"),
}
SSH_LEGACY_SUPPORTED_ATTR = {
    "kex": "_kex_info",
    "ciphers": "_cipher_info",
    "digests": "_mac_info",
    "key_types": "_key_info",
}
SSH_PARAMIKO_DEFAULT = "paramiko padrao"
SSH_PARAMIKO_LEGACY = "paramiko legado (ssh-rsa/SHA1, kex e cifras antigas)"
SSH_OPENSSH_DEFAULT = "OpenSSH do sistema (algoritmos padrao)"
SSH_OPENSSH_LEGACY = "OpenSSH do sistema com algoritmos legados (ssh-rsa/SHA1)"


def _paramiko_supports_legacy():
    """paramiko >= 4/5 removeu ssh-rsa e kex SHA1; nesse caso o perfil legado nao ajuda."""
    transport_class = paramiko.Transport
    return "ssh-rsa" in getattr(transport_class, "_key_info", {}) or any(
        name in getattr(transport_class, "_kex_info", {}) for name in SSH_LEGACY_ALGORITHMS["kex"]
    )


def _enable_legacy_algorithms(transport):
    options = transport.get_security_options()
    enabled = {}
    for attr, legacy in SSH_LEGACY_ALGORITHMS.items():
        try:
            current = list(getattr(options, attr))
            supported = getattr(transport, SSH_LEGACY_SUPPORTED_ATTR[attr], {})
            extra = [name for name in legacy if name in supported and name not in current]
            if extra:
                setattr(options, attr, tuple(current + extra))
                enabled[attr] = extra
        except (AttributeError, ValueError, TypeError):
            # Versao do paramiko sem algum algoritmo: segue com o que estiver disponivel.
            continue
    return enabled


def _load_paramiko_host_keys():
    host_keys = paramiko.HostKeys()
    paths, _ = _known_hosts_paths()
    for path in paths:
        if os.path.exists(path):
            try:
                host_keys.load(path)
            except Exception:
                continue
    return host_keys, paths


def _host_lookup_candidates(origin):
    candidates = []
    if origin.port and origin.port != 22:
        candidates.append(f"[{origin.host}]:{origin.port}")
    candidates.append(origin.host)
    if origin.port == 22:
        candidates.append(f"[{origin.host}]:22")
    return candidates


def _prefer_known_host_key_types(transport, host_keys, origin):
    for candidate in _host_lookup_candidates(origin):
        entries = host_keys.lookup(candidate)
        if entries:
            known_types = list(entries.keys())
            try:
                options = transport.get_security_options()
                current = list(options.key_types)
                preferred = [k for k in current if k in known_types]
                others = [k for k in current if k not in known_types]
                if preferred:
                    options.key_types = tuple(preferred + others)
            except Exception:
                pass
            return


def _verify_paramiko_host_key(transport, host_keys, paths, origin):
    remote_key = transport.get_remote_server_key()
    if remote_key is None:
        raise HostKeyVerificationError(f"Servidor {origin.host}:{origin.port} nao apresentou host key")

    candidates = _host_lookup_candidates(origin)
    found_entries = None
    matched_candidate = None
    for candidate in candidates:
        entries = host_keys.lookup(candidate)
        if entries:
            found_entries = entries
            matched_candidate = candidate
            break

    if found_entries is not None:
        if not host_keys.check(matched_candidate, remote_key):
            raise HostKeyVerificationError(
                f"Verificacao de host key falhou para {origin.host}:{origin.port}: "
                f"a chave {remote_key.get_name()} recebida NAO confere com o known_hosts"
            )
        return

    if _strict_host_key_enabled():
        locations = ", ".join(paths) if paths else "~/.ssh/known_hosts"
        raise HostKeyVerificationError(
            f"Host {origin.host}:{origin.port} nao encontrado no known_hosts ({locations}). "
            f"Registre a chave publica do host antes de conectar."
        )


def _local_private_keys():
    """Chaves do agent e de ~/.ssh (somente leitura) para origens sem senha na planilha."""
    keys = []
    custom_key = os.environ.get("NETCHECK_SSH_IDENTITY_FILE") or os.environ.get("SSH_IDENTITY_FILE")
    key_classes = [
        ("id_ed25519", getattr(paramiko, "Ed25519Key", None)),
        ("id_ecdsa", getattr(paramiko, "ECDSAKey", None)),
        ("id_rsa", getattr(paramiko, "RSAKey", None)),
    ]
    if custom_key and os.path.exists(custom_key):
        for _, key_class in key_classes:
            if key_class is None:
                continue
            try:
                keys.append(key_class.from_private_key_file(custom_key))
                break
            except Exception:
                continue
        if keys:
            return keys

    try:
        keys.extend(paramiko.Agent().get_keys())
    except Exception:
        pass
    for filename, key_class in key_classes:
        path = os.path.expanduser(os.path.join("~", ".ssh", filename))
        if key_class is None or not os.path.exists(path):
            continue
        try:
            keys.append(key_class.from_private_key_file(path))
        except Exception:
            continue
    return keys


def _ssh_authenticate(transport, origin):
    if origin.password:
        try:
            transport.auth_password(origin.username, origin.password)
        except paramiko.BadAuthenticationType as exc:
            # Alguns servidores so aceitam a senha via keyboard-interactive.
            if "keyboard-interactive" not in exc.allowed_types:
                raise
            transport.auth_interactive(
                origin.username,
                lambda _title, _instructions, prompts: [origin.password for _ in prompts],
            )
        return

    last_error = None
    for key in _local_private_keys():
        try:
            transport.auth_publickey(origin.username, key)
            return
        except paramiko.AuthenticationException as exc:
            last_error = exc
    raise last_error or paramiko.AuthenticationException(
        "Origem sem senha na planilha e nenhuma chave SSH local/agent foi aceita"
    )


def _ssh_should_try_fallback(exc, origin):
    """Decide se vale tentar o proximo perfil SSH apos uma falha."""
    if isinstance(exc, HostKeyVerificationError):
        # Falha de verificacao de host key (chave divergente ou ausente no known_hosts)
        # nunca deve ser contornada tentando outro perfil.
        return False
    if isinstance(exc, PermissionError):
        return False
    if paramiko is not None and isinstance(exc, paramiko.AuthenticationException):
        # Senha errada nao melhora com algoritmos antigos e cada tentativa extra conta
        # como falha de login (risco de bloqueio da conta). So tenta de novo com chave,
        # que e onde o rsa-sha2 x ssh-rsa costuma quebrar.
        return not origin.password
    if isinstance(exc, (socket.timeout, ConnectionRefusedError, socket.gaierror)):
        return False
    if isinstance(exc, OSError) and not isinstance(exc, (ConnectionResetError, EOFError)):
        # Sem rota, host inalcancavel etc.: problema de rede, nao de algoritmo.
        return False
    return True


def _open_paramiko_session(origin, legacy, fallback_reason=""):
    host_keys, kh_paths = _load_paramiko_host_keys()
    sock = socket.create_connection((origin.host, origin.port), timeout=TIMEOUT_SECONDS)
    transport = None
    try:
        enabled_legacy = {}
        if legacy:
            # Forca ssh-rsa (SHA1) no lugar de rsa-sha2-256/512, exigido por OpenSSH
            # antigos (< 7.2), appliances e alguns equipamentos de rede.
            transport = paramiko.Transport(
                sock,
                disabled_algorithms={
                    "pubkeys": ["rsa-sha2-512", "rsa-sha2-256"],
                    "keys": ["rsa-sha2-512", "rsa-sha2-256"],
                },
            )
            enabled_legacy = _enable_legacy_algorithms(transport)
        else:
            transport = paramiko.Transport(sock)
        _prefer_known_host_key_types(transport, host_keys, origin)
        transport.banner_timeout = TIMEOUT_SECONDS
        transport.start_client(timeout=TIMEOUT_SECONDS)
        _verify_paramiko_host_key(transport, host_keys, kh_paths, origin)
        _ssh_authenticate(transport, origin)
        if not transport.is_authenticated():
            raise paramiko.AuthenticationException("autenticacao nao concluida")
        transport.set_keepalive(30)
        profile_name = SSH_PARAMIKO_LEGACY if legacy else SSH_PARAMIKO_DEFAULT
        audit = SSHAuditInfo(
            profile_name=profile_name,
            backend="paramiko",
            legacy_fallback_used=bool(legacy),
            enabled_legacy_algorithms=enabled_legacy or (
                {k: list(v) for k, v in SSH_LEGACY_ALGORITHMS.items()} if legacy else {}
            ),
            sha1_signatures_enabled=bool(legacy),
            fallback_reason=sanitize_text(fallback_reason) if legacy else "",
            host_key_verified=_strict_host_key_enabled(),
            security_warning=(
                "Algoritmos SSH legados (ssh-rsa/SHA-1) habilitados via paramiko."
                if legacy
                else ""
            ),
        ).to_dict()
        return ParamikoSession(transport, profile_name, ssh_audit=audit)
    except BaseException:
        if transport is not None:
            transport.close()
        sock.close()
        raise


# ----------------------------- Fallback OpenSSH -----------------------------

OPENSSH_LEGACY_WANTED = {
    "HostKeyAlgorithms": ("key", ("ssh-rsa", "ssh-dss")),
    "PubkeyAcceptedAlgorithms": ("key", ("ssh-rsa",)),
    "KexAlgorithms": (
        "kex",
        ("diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1", "diffie-hellman-group1-sha1"),
    ),
    "Ciphers": ("cipher", ("aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc")),
    "MACs": ("mac", ("hmac-sha1", "hmac-sha1-96", "hmac-md5")),
}
_openssh_supported_cache = None


def _openssh_supported_legacy_map():
    """Descobre quais algoritmos legados cada categoria do `ssh` local suporta."""
    global _openssh_supported_cache
    if _openssh_supported_cache is not None:
        return _openssh_supported_cache

    def query(kind):
        try:
            completed = subprocess.run(
                ["ssh", "-Q", kind], capture_output=True, text=True, timeout=5, check=False
            )
            return set(completed.stdout.split())
        except (OSError, subprocess.SubprocessError):
            return set()

    # OpenSSH < 8.5 chama a opcao de PubkeyAcceptedKeyTypes.
    pubkey_option = "PubkeyAcceptedAlgorithms"
    try:
        probe = subprocess.run(
            ["ssh", "-G", "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa", "localhost"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if probe.returncode != 0:
            pubkey_option = "PubkeyAcceptedKeyTypes"
    except (OSError, subprocess.SubprocessError):
        pass

    result = {}
    kind_cache = {}
    for option, (kind, wanted) in OPENSSH_LEGACY_WANTED.items():
        supported = kind_cache.setdefault(kind, query(kind))
        names = [name for name in wanted if name in supported]
        opt_name = pubkey_option if option == "PubkeyAcceptedAlgorithms" else option
        result[option] = (opt_name, names)
    _openssh_supported_cache = result
    return result


def _openssh_legacy_options():
    """Retorna todas as opcoes legadas suportadas pelo cliente OpenSSH local."""
    options = []
    for _, (opt_name, names) in _openssh_supported_legacy_map().items():
        if names:
            options += ["-o", f"{opt_name}=+{','.join(names)}"]
    return options


class OpenSSHSession:
    """Sessao usando o cliente `ssh` do sistema (com suporte a fallback legado restrito).

    - Verifica a host key do servidor no known_hosts em modo somente leitura
      (`StrictHostKeyChecking=yes`, `UpdateHostKeys=no`).
    - Tenta primeiro algoritmos modernos padrao do OpenSSH; somente habilita algoritmos
      legados especificos (KexAlgorithms, HostKeyAlgorithms, Ciphers, MACs ou
      PubkeyAcceptedAlgorithms) se a origem exigir na negociacao.
    - Quando `ssh-rsa` (SHA-1) e exigido em sistemas com OpenSSL 3.5+ (RHEL/Fedora),
      habilita `rh-allow-sha1-signatures = yes` apenas no processo filho do `ssh`.
    """

    def __init__(self, origin, fallback_reason=""):
        if shutil.which("ssh") is None:
            raise FileNotFoundError("cliente 'ssh' (OpenSSH) nao encontrado no computador local")
        self.origin = origin
        self.profile_name = SSH_OPENSSH_DEFAULT
        self.last_exit_code = None
        self._temp_dir = None
        self._enabled_legacy = {}  # canonical_option -> list of algos
        self._sha1_enabled = False
        self._fallback_reasons = [fallback_reason] if fallback_reason else []
        self.env = os.environ.copy()
        self._base_prefix = []
        self._base_args = []
        self._build_base_args()

    @property
    def ssh_audit(self):
        legacy_used = bool(self._enabled_legacy or self._sha1_enabled)
        algos_copy = {k: list(v) for k, v in self._enabled_legacy.items()}
        warning = ""
        if legacy_used:
            parts = [f"{k}=+{','.join(v)}" for k, v in algos_copy.items() if v]
            if self._sha1_enabled:
                parts.append("rh-allow-sha1-signatures=yes")
            warning = (
                f"Algoritmos SSH legados habilitados via OpenSSH ({'; '.join(parts)})"
                if parts
                else "Fallback OpenSSH legado utilizado."
            )
        return SSHAuditInfo(
            profile_name=self.profile_name,
            backend="openssh",
            legacy_fallback_used=legacy_used,
            enabled_legacy_algorithms=algos_copy,
            sha1_signatures_enabled=bool(self._sha1_enabled),
            fallback_reason=sanitize_text(" | ".join(r for r in self._fallback_reasons if r)),
            host_key_verified=_strict_host_key_enabled(),
            security_warning=warning,
        ).to_dict()

    def _ensure_temp_dir(self):
        if self._temp_dir is None:
            self._temp_dir = tempfile.mkdtemp(prefix="netcheck-")
        return self._temp_dir

    def _enable_sha1_signatures_in_env(self):
        if self._sha1_enabled or os.name == "nt":
            return
        self._sha1_enabled = True
        system_cnf = "/etc/pki/tls/openssl.cnf"
        if not os.path.exists(system_cnf):
            system_cnf = "/etc/ssl/openssl.cnf"
        temp_dir = self._ensure_temp_dir()
        cnf_path = os.path.join(temp_dir, "openssl_legacy.cnf")
        lines = []
        if os.path.exists(system_cnf):
            lines.append(f".include {system_cnf}")
        lines += [
            "[openssl_init]",
            "alg_section = evp_properties",
            "[evp_properties]",
            "rh-allow-sha1-signatures = yes",
            "",
        ]
        with open(cnf_path, "w", encoding="utf-8") as file:
            file.write("\n".join(lines))
        self.env["OPENSSL_CONF"] = cnf_path

    def _build_base_args(self):
        null_file = "NUL" if os.name == "nt" else "/dev/null"
        strict = _strict_host_key_enabled()
        kh_paths, is_custom_kh = _known_hosts_paths()
        base = [
            "ssh", "-T",
            "-p", str(self.origin.port),
            "-o", f"StrictHostKeyChecking={'yes' if strict else 'no'}",
            "-o", "UpdateHostKeys=no",
            "-o", "CheckHostIP=no",
            "-o", f"ConnectTimeout={TIMEOUT_SECONDS}",
            "-o", "ServerAliveInterval=30",
            "-o", "ForwardAgent=no",
            "-o", "ForwardX11=no",
            "-o", "ClearAllForwardings=yes",
        ]
        if strict:
            if kh_paths:
                base += ["-o", f"UserKnownHostsFile={' '.join(kh_paths)}"]
            if is_custom_kh:
                base += ["-o", f"GlobalKnownHostsFile={null_file}"]
        else:
            base += [
                "-o", f"UserKnownHostsFile={null_file}",
                "-o", f"GlobalKnownHostsFile={null_file}",
            ]

        prefix = []
        if self.origin.password:
            base += [
                "-o", "PreferredAuthentications=password,keyboard-interactive",
                "-o", "PubkeyAuthentication=no",
                "-o", "NumberOfPasswordPrompts=1",
                "-o", "BatchMode=no",
            ]
            self.env["NETCHECK_SSH_PASS"] = self.origin.password
            if shutil.which("sshpass"):
                self.env["SSHPASS"] = self.origin.password
                prefix = ["sshpass", "-e"]
            else:
                self._setup_askpass()
        else:
            base += ["-o", "BatchMode=yes"]
            custom_key = os.environ.get("NETCHECK_SSH_IDENTITY_FILE") or os.environ.get("SSH_IDENTITY_FILE")
            if custom_key and os.path.exists(custom_key):
                base += ["-i", custom_key, "-o", "IdentitiesOnly=yes"]

        self._base_prefix = prefix
        self._base_args = base

    @property
    def argv(self):
        supported_map = _openssh_supported_legacy_map()
        legacy_opts = []
        for option, algos in self._enabled_legacy.items():
            opt_name, _ = supported_map.get(option, (option, []))
            if algos:
                legacy_opts += ["-o", f"{opt_name}=+{','.join(algos)}"]
        return self._base_prefix + self._base_args + legacy_opts + [
            f"{self.origin.username}@{self.origin.host}"
        ]

    def _setup_askpass(self):
        # Script auxiliar LOCAL (nunca na origem) que apenas imprime a senha da variavel.
        temp_dir = self._ensure_temp_dir()
        if os.name == "nt":
            path = os.path.join(temp_dir, "askpass.cmd")
            content = "@echo off\r\necho %NETCHECK_SSH_PASS%\r\n"
        else:
            path = os.path.join(temp_dir, "askpass.sh")
            content = '#!/bin/sh\nprintf \'%s\\n\' "$NETCHECK_SSH_PASS"\n'
        with open(path, "w", encoding="utf-8") as file:
            file.write(content)
        os.chmod(path, 0o700)
        self.env["SSH_ASKPASS"] = path
        self.env["SSH_ASKPASS_REQUIRE"] = "force"
        self.env.setdefault("DISPLAY", ":0")

    def _add_legacy_option(self, canonical_option, offered_text=""):
        supported_map = _openssh_supported_legacy_map()
        _, supported = supported_map.get(canonical_option, (canonical_option, []))
        if not supported:
            return False
        offered = [tok.strip() for tok in offered_text.split(",") if tok.strip()]
        if offered:
            chosen = [alg for alg in supported if alg in offered]
            if not chosen:
                chosen = list(supported)
        else:
            chosen = list(supported)
        current = self._enabled_legacy.get(canonical_option, [])
        added = [alg for alg in chosen if alg not in current]
        if not added:
            return False
        self._enabled_legacy[canonical_option] = current + added
        if "ssh-rsa" in self._enabled_legacy[canonical_option]:
            self._enable_sha1_signatures_in_env()
        self.profile_name = SSH_OPENSSH_LEGACY
        return True

    def _narrow_fallback_from_stderr(self, stderr):
        lower = stderr.lower()
        offer_match = re.search(r"their offer:\s*([^\r\n]+)", stderr, re.IGNORECASE)
        offered = offer_match.group(1) if offer_match else ""

        if "no matching key exchange" in lower or "kex" in lower and "unable to negotiate" in lower:
            self._fallback_reasons.append(sanitize_text(stderr.strip()))
            return self._add_legacy_option("KexAlgorithms", offered)
        if "no matching host key type" in lower or "host key type" in lower and "unable to negotiate" in lower:
            self._fallback_reasons.append(sanitize_text(stderr.strip()))
            changed = self._add_legacy_option("HostKeyAlgorithms", offered)
            if "ssh-rsa" in self._enabled_legacy.get("HostKeyAlgorithms", ()):
                self._add_legacy_option("PubkeyAcceptedAlgorithms", "ssh-rsa")
            return changed
        if "no matching cipher" in lower:
            self._fallback_reasons.append(sanitize_text(stderr.strip()))
            return self._add_legacy_option("Ciphers", offered)
        if "no matching mac" in lower or "message authentication code" in lower:
            self._fallback_reasons.append(sanitize_text(stderr.strip()))
            return self._add_legacy_option("MACs", offered)
        if not self.origin.password and (
            "permission denied (publickey" in lower
            or "no mutual signature algorithm" in lower
            or "signing failed for rsa" in lower
            or "error in libcrypto" in lower
        ):
            self._fallback_reasons.append(sanitize_text(stderr.strip()))
            changed_pub = self._add_legacy_option("PubkeyAcceptedAlgorithms", "ssh-rsa")
            self._enable_sha1_signatures_in_env()
            return changed_pub
        if "error in libcrypto" in lower and not self._sha1_enabled:
            self._fallback_reasons.append(sanitize_text(stderr.strip()))
            self._enable_sha1_signatures_in_env()
            return True
        return False

    def check(self):
        for _ in range(5):
            code, stdout, stderr = self.run("echo netcheck-ok", TIMEOUT_SECONDS * 3)
            if code == 0 and "netcheck-ok" in stdout:
                return
            err_text = (stderr or stdout).strip() or f"ssh retornou codigo {code}"
            err_lower = err_text.lower()
            if (
                "host key verification failed" in err_lower
                or "remote host identification has changed" in err_lower
                or ("host key" in err_lower and "is known for" in err_lower)
            ):
                raise HostKeyVerificationError(err_text)
            if self._narrow_fallback_from_stderr(err_text):
                continue
            if "permission denied" in err_lower:
                raise PermissionError(f"Falha de autenticacao SSH: {err_text}")
            raise ConnectionError(err_text)
        raise ConnectionError("Nao foi possivel negociar algoritmos SSH com a origem")

    def is_active(self):
        return True

    def run(self, command, timeout):
        completed = subprocess.run(
            self.argv + [command],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout + TIMEOUT_SECONDS * 2,
            env=self.env,
            stdin=subprocess.DEVNULL,
            start_new_session=os.name != "nt",
            check=False,
        )
        self.last_exit_code = completed.returncode
        return completed.returncode, completed.stdout, completed.stderr

    def stream(self, command, stdin_data=None):
        self.last_exit_code = None
        holder = {}
        try:
            for chunk in stream_process(
                self.argv + [command],
                env=self.env,
                stdin_data=stdin_data,
                new_session=True,
                status_holder=holder,
            ):
                yield chunk
        finally:
            self.last_exit_code = holder.get("exit_code")

    def close(self):
        if self._temp_dir:
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None


def open_ssh_session(origin):
    """Abre a sessao SSH tentando, em ordem:

    1. paramiko com algoritmos padrao;
    2. paramiko com algoritmos legados (so se a versao instalada ainda os suporta);
    3. cliente OpenSSH do sistema (inicia com algoritmos padrao e habilita apenas
       as categorias legadas exigidas pela origem).
    """
    errors = []
    attempts = []
    if paramiko is not None:
        attempts.append((SSH_PARAMIKO_DEFAULT, lambda: _open_paramiko_session(origin, legacy=False)))
        if _paramiko_supports_legacy():
            attempts.append(
                (
                    SSH_PARAMIKO_LEGACY,
                    lambda: _open_paramiko_session(
                        origin, legacy=True, fallback_reason=" | ".join(errors)
                    ),
                )
            )
    if SSH_OPENSSH_FALLBACK:
        def open_openssh():
            session = OpenSSHSession(origin, fallback_reason=" | ".join(errors))
            try:
                session.check()
            except BaseException:
                session.close()
                raise
            return session
        attempts.append((SSH_OPENSSH_LEGACY, open_openssh))

    if not attempts:
        raise RuntimeError(
            "Biblioteca paramiko nao instalada e fallback OpenSSH desabilitado; "
            "nao consigo testar a partir da origem"
        )

    for index, (name, opener) in enumerate(attempts):
        try:
            session = opener()
            origin.ssh_audit = dict(getattr(session, "ssh_audit", {}) or {})
            return session
        except HostKeyVerificationError as exc:
            errors.append(f"[{name}] {type(exc).__name__}: {exc}")
            raise HostKeyVerificationError(" | ".join(errors)) from exc
        except Exception as exc:
            errors.append(f"[{name}] {type(exc).__name__}: {exc}")
            if index == len(attempts) - 1 or not _ssh_should_try_fallback(exc, origin):
                raise ConnectionError(" | ".join(errors)) from exc
    raise ConnectionError(" | ".join(errors))


def run_remote_origin_preflight(origin, session, dest_ip=None):
    """Executa preflight remoto somente leitura na VM de origem."""
    if origin is None or session is None or not hasattr(session, "run"):
        return {}
    info = {
        "checked": True,
        "uid": None,
        "is_root": False,
        "binaries": {},
        "raw_socket_capable": False,
        "configured_ips": [],
        "real_ip_present": None,
        "route_check": None,
    }
    try:
        uid_cmd = "LC_ALL=C LANG=C id -u"
        ensure_remote_command_is_read_only(uid_cmd)
        code, out, _ = session.run(uid_cmd, TIMEOUT_SECONDS)
        if code == 0 and out and out.strip().isdigit():
            info["uid"] = int(out.strip())
            info["is_root"] = info["uid"] == 0

        bins = ("traceroute", "tracepath", "ping", "nc", "ip", "getcap")
        bin_cmd = f"LC_ALL=C LANG=C command -v {' '.join(bins)}"
        ensure_remote_command_is_read_only(bin_cmd)
        _, out_bins, _ = session.run(bin_cmd, TIMEOUT_SECONDS)
        found_paths = [line.strip() for line in (out_bins or "").splitlines() if line.strip()]
        for b in bins:
            matched = next((p for p in found_paths if os.path.basename(p) == b or p == b), "")
            info["binaries"][b] = matched

        cap_ok = bool(info["is_root"])
        tr_path = info["binaries"].get("traceroute") or "/usr/bin/traceroute"
        if not cap_ok and info["binaries"].get("getcap") and tr_path.startswith(REMOTE_ALLOWED_SYSTEM_DIRS):
            cap_cmd = f"LC_ALL=C LANG=C getcap {quote(tr_path)}"
            ensure_remote_command_is_read_only(cap_cmd)
            _, out_cap, _ = session.run(cap_cmd, TIMEOUT_SECONDS)
            if "cap_net_raw" in (out_cap or "").lower() or "cap_net_admin" in (out_cap or "").lower():
                cap_ok = True
        info["raw_socket_capable"] = cap_ok

        ip_cmd = "LC_ALL=C LANG=C ip -o addr show"
        ensure_remote_command_is_read_only(ip_cmd)
        code_ip, out_ip, _ = session.run(ip_cmd, TIMEOUT_SECONDS)
        if code_ip == 0 and out_ip:
            ips = []
            for match in re.finditer(r"\binet6?\s+([^\s/]+)", out_ip):
                raw_addr = match.group(1).split("%", 1)[0].strip()
                addr = valid_ip(raw_addr) or raw_addr
                if addr and addr not in ips:
                    ips.append(addr)
            info["configured_ips"] = ips
            if origin.real_ip:
                norm_real = valid_ip(origin.real_ip) or origin.real_ip
                info["real_ip_present"] = norm_real in ips
            else:
                info["real_ip_present"] = True

        if dest_ip and valid_ip(dest_ip):
            norm_dest = valid_ip(dest_ip)
            route_cmd = (
                f"LC_ALL=C LANG=C ip -6 route get {quote(norm_dest)}"
                if ip_family(norm_dest) == 6
                else f"LC_ALL=C LANG=C ip route get {quote(norm_dest)}"
            )
            ensure_remote_command_is_read_only(route_cmd)
            code_rt, out_rt, err_rt = session.run(route_cmd, TIMEOUT_SECONDS)
            detail_rt = "\n".join(p for p in ((out_rt or "").strip(), (err_rt or "").strip()) if p)
            info["route_check"] = {
                "dest_ip": norm_dest,
                "ok": code_rt == 0,
                "detail": detail_rt,
            }
    except Exception as exc:
        info["error"] = sanitize_text(f"{type(exc).__name__}: {exc}")

    origin.remote_preflight = info
    return info


_active_ssh_pools_lock = threading.Lock()
_active_ssh_pools = set()


class SSHPool:
    """Reaproveita uma conexao SSH por origem durante toda a execucao.

    Antes cada teste abria uma conexao nova; com muitas linhas isso deixava a execucao
    lenta. Se a conexao com uma origem falhar, os demais testes dela falham na hora
    (sem esperar o timeout de novo).
    """

    def __init__(self, enable_remote_preflight=True, quiet=False):
        self.clients = {}
        self.errors = {}
        self.enable_remote_preflight = bool(enable_remote_preflight)
        self.quiet = bool(quiet)
        with _active_ssh_pools_lock:
            _active_ssh_pools.add(self)

    def get(self, origin):
        key = origin.number
        if key in self.errors:
            raise ConnectionError(f"{self.errors[key]} (falha de conexao anterior com a origem)")

        client = self.clients.get(key)
        if client is not None:
            if client.is_active():
                return client
            client.close()

        error = None
        if origin.error:
            error = origin.error
        elif origin.access_protocol != "ssh":
            error = f"Origem configurada para {origin.access_protocol}; execucao remota implementada por SSH"
        elif not origin.username:
            error = "Origem sem usuario na planilha"
        if error:
            self.errors[key] = error
            raise RuntimeError(error)

        try:
            client = open_ssh_session(origin)
        except HostKeyVerificationError as exc:
            message = sanitize_text(f"SSH para {origin.host}:{origin.port} falhou (host key): {exc}")
            self.errors[key] = message
            raise HostKeyVerificationError(message) from exc
        except Exception as exc:
            message = sanitize_text(f"SSH para {origin.host}:{origin.port} falhou: {exc}")
            self.errors[key] = message
            raise ConnectionError(message) from exc

        if not origin.ssh_audit:
            origin.ssh_audit = getattr(client, "ssh_audit", None) or SSHAuditInfo(
                profile_name=getattr(client, "profile_name", SSH_PARAMIKO_DEFAULT),
                backend="custom",
                legacy_fallback_used=(
                    getattr(client, "profile_name", SSH_PARAMIKO_DEFAULT) != SSH_PARAMIKO_DEFAULT
                ),
            ).to_dict()

        if client.profile_name != SSH_PARAMIKO_DEFAULT and not self.quiet:
            print(
                f"\033[93m[AVISO]\033[0m Origem {origin.number} ({origin.host}) conectada "
                f"via {client.profile_name}."
            )

        if self.enable_remote_preflight and not origin.remote_preflight:
            run_remote_origin_preflight(origin, client)

        self.clients[key] = client
        return client

    def close_all(self):
        for client in list(self.clients.values()):
            try:
                client.close()
            except Exception:
                pass
        self.clients.clear()
        with _active_ssh_pools_lock:
            _active_ssh_pools.discard(self)


def close_all_active_ssh_pools():
    with _active_ssh_pools_lock:
        pools = list(_active_ssh_pools)
    for pool in pools:
        try:
            pool.close_all()
        except Exception:
            pass


def run_remote_ssh_test(target, origin, ssh_pool):
    session = ssh_pool.get(origin)
    if target.protocol == "udp" and target.port is not None:
        _, svc_state, svc_detail, _ = probe_udp_service(
            target.host, target.port, origin=origin, session=session
        )
        if svc_state == SERVICE_UDP_RESPONDED:
            return True, svc_detail
        return False, svc_detail

    command = f"LC_ALL=C LANG=C {remote_test_command(target)}"
    ensure_remote_command_is_read_only(command)
    command_timeout = max(TIMEOUT_SECONDS * 6, 30) + 3
    exit_code, output, error = session.run(command, command_timeout)
    detail = "\n".join(part for part in (output.strip(), error.strip()) if part)
    if not detail:
        detail = f"comando remoto finalizou com codigo {exit_code}"
    return exit_code == 0, detail


TESTERS = {
    "icmp": test_icmp,
    "tcp": test_tcp,
    "udp": test_udp,
    "http": test_http,
    "https": lambda host, port=None, timeout=TIMEOUT_SECONDS: test_http(
        host, port, timeout, use_tls=True
    ),
    "ssh": test_ssh,
    "telnet": test_telnet,
    "ftp": test_ftp,
    "dns": test_dns,
    "ntp": test_ntp,
    "snmp": test_snmp,
    "tftp": test_tftp,
}


def _run_single_test_attempt(target, origin=None, ssh_pool=None):
    if target.error:
        return TestResult(
            target,
            origin,
            False,
            "FALHA",
            target.error,
            0,
            summary=target.error,
            classification=CLASSIFICATION_EXECUTION_ERROR,
        )

    if origin and origin.error:
        return TestResult(
            target,
            origin,
            False,
            "FALHA",
            origin.error,
            0,
            summary=origin.error,
            classification=CLASSIFICATION_EXECUTION_ERROR,
        )

    if target.protocol in TRACE_PROTOCOLS:
        return run_trace(target, origin, ssh_pool or SSHPool())

    if not target.resolved_ips:
        resolved_info = resolve_target_ips(target.host)
        target.resolved_ips = {
            "ipv4": resolved_info["ipv4"],
            "ipv6": resolved_info["ipv6"],
        }
        all_resolved = resolved_info.get("all", [])
        if not target.effective_ip and all_resolved:
            target.effective_ip = all_resolved[0]

    start = time.monotonic()
    classification = ""

    try:
        if origin:
            ok, detail = run_remote_ssh_test(target, origin, ssh_pool or SSHPool())
            detail_lower = (detail or "").lower()
            if ok:
                classification = CLASSIFICATION_REACHED
            elif "udp_no_response" in detail_lower or "inconclusivo" in detail_lower:
                classification = CLASSIFICATION_UNCONFIRMED
            else:
                classification = CLASSIFICATION_UNREACHABLE
        else:
            tester = TESTERS.get(target.protocol)
            if tester is None:
                tester = test_tcp if target.port else test_icmp
            ok, detail = tester(target.host, target.port, TIMEOUT_SECONDS)
            detail_lower = (detail or "").lower()
            if ok:
                classification = CLASSIFICATION_REACHED
            elif "udp_no_response" in detail_lower or "inconclusivo" in detail_lower:
                classification = CLASSIFICATION_UNCONFIRMED
            else:
                classification = CLASSIFICATION_UNREACHABLE
    except (HostKeyVerificationError, ConnectionError) as exc:
        ok = False
        detail = sanitize_text(f"{type(exc).__name__}: {exc}")
        classification = (
            CLASSIFICATION_SSH_ERROR if origin else CLASSIFICATION_UNREACHABLE
        )
    except socket.timeout as exc:
        ok = False
        detail = sanitize_text(f"{type(exc).__name__}: {exc}")
        classification = CLASSIFICATION_TIMEOUT
    except Exception as exc:
        ok = False
        detail = sanitize_text(f"{type(exc).__name__}: {exc}")
        classification = (
            CLASSIFICATION_SSH_ERROR if origin else CLASSIFICATION_EXECUTION_ERROR
        )

    elapsed_ms = int((time.monotonic() - start) * 1000)
    status = "OK" if ok else "FALHA"
    return TestResult(
        target,
        origin,
        ok,
        status,
        detail,
        elapsed_ms,
        classification=classification,
    )


def _should_retry_attempt(result):
    """Determina se o resultado e inconclusivo/transitorio e elegivel para nova tentativa."""
    if target_or_origin_has_preflight_error(result.target, result.origin):
        return False
    if result.classification in (
        CLASSIFICATION_UNCONFIRMED,
        CLASSIFICATION_TIMEOUT,
        CLASSIFICATION_INSUFFICIENT_EVIDENCE,
    ):
        return True
    if result.diagnosis and result.diagnosis.get("retest_recommended"):
        return True
    svc = (result.composite or {}).get("service_result", "")
    if svc in (SERVICE_TCP_TIMEOUT, SERVICE_UDP_NO_RESPONSE):
        return True
    return False


def target_or_origin_has_preflight_error(target, origin):
    return bool((target and target.error) or (origin and origin.error))


def _attempt_snapshot(attempt_index, res):
    return {
        "attempt": attempt_index,
        "ok": bool(res.ok),
        "status": res.status,
        "classification": res.classification,
        "trace_classification": res.trace_classification,
        "policy_verdict": (res.composite or {}).get("policy_verdict", POLICY_NOT_APPLICABLE),
        "service_result": (res.composite or {}).get("service_result", SERVICE_NOT_TESTED),
        "elapsed_ms": res.elapsed_ms,
        "summary": sanitize_text(res.summary or res.detail),
        "detail": sanitize_text(res.detail),
        "hops": list(res.hops or ()),
    }


def run_test(target, origin=None, ssh_pool=None, retries=0):
    max_retries = max(0, int(retries or 0))
    pool = ssh_pool or SSHPool()
    first = _run_single_test_attempt(target, origin, pool)
    attempts = [_attempt_snapshot(1, first)]
    results_chain = [first]

    if max_retries > 0 and _should_retry_attempt(first):
        for retry_idx in range(2, max_retries + 2):
            nxt = _run_single_test_attempt(target, origin, pool)
            attempts.append(_attempt_snapshot(retry_idx, nxt))
            results_chain.append(nxt)

    final = results_chain[-1]
    # Se alguma tentativa obteve sucesso mas outra falhou, ou classificacoes/vereditos divergiram:
    signatures = {
        (
            r.ok,
            r.classification,
            (r.composite or {}).get("policy_verdict", POLICY_NOT_APPLICABLE),
        )
        for r in results_chain
    }
    if len(signatures) > 1:
        # Se houve sucesso em alguma tentativa, preserva a tentativa REACHED/OK como base,
        # mas marca flaky=True e diagnostico TRANSIENT_OR_FLAKY.
        ok_candidates = [r for r in results_chain if r.ok]
        if ok_candidates:
            final = ok_candidates[-1]
        final.flaky = True
        flaky_note = (
            f"Comportamento intermitente (flaky) detectado em {len(results_chain)} tentativas."
        )
        if flaky_note not in final.notes:
            final.notes = list(final.notes) + [flaky_note]
        final.diagnosis = compute_diagnosis(final)

    final.attempts = attempts
    return final


def is_trace(result):
    return result.target.protocol in TRACE_PROTOCOLS


# ---------------------------------------------------------------------------
# Preflight Automatico (sem SSH nem testes remotos por padrao)
# ---------------------------------------------------------------------------

EXPECTED_TARGET_HEADERS = {
    2: "Origem",
    3: "Destino",
    4: "Porta",
    5: "Protocolo",
    6: "Descrição",
}
EXPECTED_ORIGIN_HEADERS = {
    8: "Número origem",
    9: "Hostname/IP",
    10: "IP Real (Opcional)",
    11: "Porta (Opcional)",
    12: "Username",
    13: "Password",
}


def detect_local_binaries():
    """Inspeciona caminhos e versoes dos binarios locais relevantes."""
    binaries = {}
    for name in ("traceroute", "tracepath", "ping", "ssh", "nc", "curl", "dig"):
        path = shutil.which(name)
        version = ""
        if path:
            ver_args = [path, "-V"] if name == "ssh" else [path, "--version"]
            try:
                proc = subprocess.run(
                    ver_args, capture_output=True, text=True, timeout=2, check=False
                )
                raw = (proc.stdout or proc.stderr or "").strip().splitlines()
                if raw:
                    version = raw[0].strip()[:120]
            except Exception:
                version = ""
        binaries[name] = {"path": path or "", "available": bool(path), "version": version}
    return binaries


def compute_file_sha256(path):
    if not path or not os.path.exists(path):
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def detect_git_commit():
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2,
            cwd=os.path.dirname(os.path.abspath(__file__)),
            check=False,
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
    except Exception:
        pass
    return ""


def run_preflight(
    template_path,
    output_dir=None,
    expand_dns=False,
    check_local_binaries=True,
):
    """Executa validacao completa de preflight (planilha, origens, destinos, segredos, ambiente).

    Retorna (PreflightReport, targets, origins).
    Erros especificos de uma origem ou linha bloqueiam apenas os testes afetados,
    permitindo que destinos independentes sigam em frente no comando `run`.
    """
    report = PreflightReport(template_path=str(template_path or ""))

    if output_dir:
        try:
            os.makedirs(output_dir, exist_ok=True)
            probe_file = os.path.join(output_dir, f".netcheck_write_test_{uuid.uuid4().hex[:8]}")
            with open(probe_file, "w", encoding="utf-8") as f:
                f.write("ok")
            os.remove(probe_file)
        except Exception as exc:
            report.add(
                PREFLIGHT_ERROR,
                "OUTPUT_DIR_NOT_WRITABLE",
                f"Diretorio de saida '{output_dir}' nao pode ser escrito: {exc}",
            )

    if not template_path or not os.path.exists(template_path):
        report.add(
            PREFLIGHT_ERROR,
            "TEMPLATE_NOT_FOUND",
            f"Arquivo de planilha nao encontrado: '{template_path}'",
        )
        return report, [], {}

    try:
        rows = read_first_sheet(template_path)
    except zipfile.BadZipFile:
        report.add(
            PREFLIGHT_ERROR,
            "TEMPLATE_INVALID_XLSX",
            f"Arquivo '{template_path}' nao e um pacote .xlsx (ZIP) valido.",
        )
        return report, [], {}
    except Exception as exc:
        report.add(
            PREFLIGHT_ERROR,
            "TEMPLATE_PARSE_ERROR",
            f"Falha ao ler planilha '{template_path}': {exc}",
        )
        return report, [], {}

    try:
        target_header_row, _ = find_header_cell(
            rows, ["Origem(Número)", "Origem(Numero)", "Origem"]
        )
        origin_header_row, _ = find_header_cell(
            rows, ["Número origem", "Numero origem"]
        )
    except ValueError as exc:
        report.add(
            PREFLIGHT_ERROR,
            "HEADER_ROW_MISSING",
            f"Cabecalho obrigatorio ausente na planilha: {exc}",
        )
        return report, [], {}

    tgt_hdr = rows.get(target_header_row, {})
    for col, expected in EXPECTED_TARGET_HEADERS.items():
        if not str(tgt_hdr.get(col, "")).strip():
            report.add(
                PREFLIGHT_WARNING,
                "HEADER_COLUMN_EMPTY",
                f"Cabecalho esperado '{expected}' ausente na coluna {col} (linha {target_header_row}).",
                row=target_header_row,
            )

    orig_hdr = rows.get(origin_header_row, {})
    for col, expected in EXPECTED_ORIGIN_HEADERS.items():
        if not str(orig_hdr.get(col, "")).strip():
            report.add(
                PREFLIGHT_WARNING,
                "HEADER_COLUMN_EMPTY",
                f"Cabecalho esperado '{expected}' ausente na coluna {col} (linha {origin_header_row}).",
                row=origin_header_row,
            )

    # Detecta origens duplicadas ou sem hostname antes do load_template:
    seen_origin_rows = {}
    for row_number in sorted(rows):
        row = rows[row_number]
        if row_number > origin_header_row:
            num = normalize_text(row.get(8, ""))
            host = str(row.get(9, "")).strip()
            if num and not host:
                report.add(
                    PREFLIGHT_ERROR,
                    "ORIGIN_HOST_MISSING",
                    f"Origem '{num}' na linha {row_number} nao possui Hostname/IP na coluna I.",
                    row=row_number,
                    origin=num,
                )
            if host and not num:
                report.add(
                    PREFLIGHT_ERROR,
                    "ORIGIN_NUMBER_MISSING",
                    f"Hostname de origem '{host}' na linha {row_number} nao possui Numero origem na coluna H.",
                    row=row_number,
                )
            if num and host:
                if num in seen_origin_rows:
                    report.add(
                        PREFLIGHT_ERROR,
                        "ORIGIN_DUPLICATE_NUMBER",
                        f"Numero de origem '{num}' duplicado nas linhas {seen_origin_rows[num]} e {row_number}.",
                        row=row_number,
                        origin=num,
                    )
                else:
                    seen_origin_rows[num] = row_number
        if row_number > target_header_row:
            dest_host = str(row.get(3, "")).strip()
            dest_port = str(row.get(4, "")).strip()
            dest_proto = str(row.get(5, "")).strip()
            if not dest_host and (dest_port or dest_proto):
                report.add(
                    PREFLIGHT_ERROR,
                    "TARGET_HOST_MISSING",
                    f"Linha {row_number} possui porta/protocolo mas o Destino (coluna C) esta vazio.",
                    row=row_number,
                )

    targets, origins = load_template(template_path, expand_dns=expand_dns)

    if not targets:
        report.add(
            PREFLIGHT_ERROR,
            "NO_TARGETS_FOUND",
            "Nenhum destino de teste encontrado a partir da linha 8 da planilha.",
        )

    local_keys_available = None

    for num, origin in sorted(origins.items()):
        if origin.error:
            err_code = "ORIGIN_CONFIG_INVALID"
            if "IP Real invalido" in origin.error:
                err_code = "ORIGIN_REAL_IP_INVALID"
            elif "porta SSH invalida" in origin.error:
                err_code = "ORIGIN_SSH_PORT_INVALID"
            elif "segredo" in origin.error.lower() or "env:" in origin.error.lower() or "keyring:" in origin.error.lower():
                err_code = "ORIGIN_SECRET_UNRESOLVED"
            report.add(
                PREFLIGHT_ERROR,
                err_code,
                origin.error,
                origin=num,
                target=origin.host,
            )
        if origin.access_protocol != "ssh":
            msg = f"Origem {num} ({origin.host}) usa protocolo '{origin.access_protocol}'; apenas 'ssh' e suportado."
            origin.error = origin.error or msg
            report.add(
                PREFLIGHT_ERROR,
                "ORIGIN_UNSUPPORTED_ACCESS_PROTOCOL",
                msg,
                origin=num,
                target=origin.host,
            )
        if not origin.username:
            msg = f"Origem {num} ({origin.host}) nao possui Username na coluna L."
            origin.error = origin.error or msg
            report.add(
                PREFLIGHT_ERROR,
                "ORIGIN_USERNAME_MISSING",
                msg,
                origin=num,
                target=origin.host,
            )
        if origin.credential_source in ("inline", "spreadsheet_literal") and origin.password:
            report.add(
                PREFLIGHT_WARNING,
                "ORIGIN_PLAINTEXT_PASSWORD",
                f"Origem {num} ({origin.host}) possui senha em texto puro na planilha; prefira 'env:VAR' ou 'keyring:servico/conta'.",
                origin=num,
                target=origin.host,
            )
        elif origin.credential_source in ("none", "ssh_key_or_agent") and not origin.password and not origin.error:
            if local_keys_available is None:
                local_keys_available = bool(_local_private_keys()) if paramiko is not None else True
            if not local_keys_available:
                report.add(
                    PREFLIGHT_WARNING,
                    "ORIGIN_NO_CREDENTIALS_FOUND",
                    f"Origem {num} ({origin.host}) esta sem senha na planilha e nenhuma chave SSH local/agent foi detectada.",
                    origin=num,
                    target=origin.host,
                )

    has_remote_targets = False
    has_local_targets = False
    needed_local_tools = set()

    for target in targets:
        origin = origins.get(target.origin_number) if target.origin_number else None
        if target.origin_number:
            has_remote_targets = True
            if origin is None:
                msg = f"Origem {target.origin_number} nao encontrada na tabela de origens"
                target.error = target.error or msg
                report.add(
                    PREFLIGHT_ERROR,
                    "TARGET_ORIGIN_NOT_FOUND",
                    msg,
                    row=target.row,
                    origin=target.origin_number,
                    target=target.host,
                )
            elif origin.error:
                report.add(
                    PREFLIGHT_ERROR,
                    "TARGET_BLOCKED_BY_ORIGIN_ERROR",
                    f"Linha {target.row} ({target.host}) bloqueada por erro na origem {origin.number}: {origin.error}",
                    row=target.row,
                    origin=origin.number,
                    target=target.host,
                )
        else:
            has_local_targets = True
            if target.protocol in TRACE_PROTOCOLS:
                needed_local_tools.add(
                    "tracepath" if target.protocol == "tracepath" else "traceroute"
                )
            elif target.protocol == "icmp":
                needed_local_tools.add("ping")

        if not valid_ip(target.host) and not target.resolved_ips:
            info = resolve_target_ips(target.host)
            target.resolved_ips = {"ipv4": info["ipv4"], "ipv6": info["ipv6"]}
            v4 = info["ipv4"]
            v6 = info["ipv6"]
            orig_fam = ip_family(origin.real_ip) if (origin and origin.real_ip) else None
            if orig_fam == 6 and v6:
                target.effective_ip = v6[0]
            elif orig_fam == 4 and v4:
                target.effective_ip = v4[0]
            elif not target.effective_ip and info["all"]:
                target.effective_ip = info["all"][0]

        if origin and origin.real_ip:
            orig_fam = ip_family(origin.real_ip)
            dst_fam = target_ip_family(target, origin=origin)
            if orig_fam in (4, 6) and dst_fam in (4, 6) and orig_fam != dst_fam:
                msg = (
                    f"Linha {target.row} ({target.host}): incompatibilidade de familia IP entre "
                    f"IP Real da origem {origin.number} ({origin.real_ip}, IPv{orig_fam}) e "
                    f"destino ({target.effective_ip or target.host}, IPv{dst_fam})."
                )
                target.error = target.error or msg
                report.add(
                    PREFLIGHT_ERROR,
                    "IP_FAMILY_MISMATCH",
                    msg,
                    row=target.row,
                    origin=origin.number,
                    target=target.host,
                )

        if target.error and "nao encontrada na tabela de origens" not in target.error and "incompatibilidade de familia IP" not in target.error:
            report.add(
                PREFLIGHT_ERROR,
                "TARGET_PORT_OR_SPEC_INVALID",
                target.error,
                row=target.row,
                origin=target.origin_number,
                target=target.host,
            )

        if target.protocol in ("tcp", "udp") and target.port is None and not target.error:
            msg = f"Linha {target.row} ({target.host}): protocolo '{target.protocol.upper()}' exige uma porta na coluna D."
            target.error = msg
            report.add(
                PREFLIGHT_ERROR,
                "TARGET_PORT_REQUIRED",
                msg,
                row=target.row,
                origin=target.origin_number,
                target=target.host,
            )

        if target.protocol == "tracepath":
            if target.transport in ("tcp", "icmp"):
                msg = (
                    f"Linha {target.row} ({target.host}): tracepath suporta apenas sondas UDP; "
                    f"transporte '/{target.transport}' e incompativel (use traceroute)."
                )
                target.error = target.error or msg
                report.add(
                    PREFLIGHT_ERROR,
                    "TRACEPATH_TRANSPORT_INCOMPATIBLE",
                    msg,
                    row=target.row,
                    origin=target.origin_number,
                    target=target.host,
                )
            if origin and origin.real_ip:
                report.add(
                    PREFLIGHT_WARNING,
                    "TRACEPATH_SOURCE_IP_UNSUPPORTED",
                    f"Linha {target.row} ({target.host}): tracepath nao suporta fixar o IP Real ({origin.real_ip}); use traceroute se precisar forcar a interface de saida (-s).",
                    row=target.row,
                    origin=origin.number,
                    target=target.host,
                )

        if target.protocol in ("traceroute", "tracert") and target.transport == "icmp" and target.port is not None:
            report.add(
                PREFLIGHT_WARNING,
                "TRACEROUTE_ICMP_PORT_IGNORED",
                f"Linha {target.row} ({target.host}): porta {target.port} informada com '/icmp'; ICMP Echo nao utiliza porta de destino.",
                row=target.row,
                origin=target.origin_number,
                target=target.host,
            )

        if len(target.resolved_ips.get("ipv4", [])) + len(target.resolved_ips.get("ipv6", [])) > 1 and not expand_dns:
            all_ips = target.resolved_ips.get("ipv4", []) + target.resolved_ips.get("ipv6", [])
            report.add(
                PREFLIGHT_INFO,
                "TARGET_MULTIPLE_DNS_IPS",
                f"Linha {target.row} ({target.host}) resolve para multiplos IPs ({', '.join(all_ips)}); use --expand-dns para testar todos individualmente.",
                row=target.row,
                origin=target.origin_number,
                target=target.host,
            )

    if check_local_binaries:
        local_bins = detect_local_binaries()
        if has_remote_targets and paramiko is None and not local_bins.get("ssh", {}).get("available"):
            report.add(
                PREFLIGHT_ERROR,
                "LOCAL_SSH_CLIENT_MISSING",
                "Execucao remota requer a biblioteca 'paramiko' ou o binario 'ssh' instalado localmente.",
            )
        if has_remote_targets and _strict_host_key_enabled():
            kh_paths, _ = _known_hosts_paths()
            if not kh_paths:
                report.add(
                    PREFLIGHT_WARNING,
                    "SSH_KNOWN_HOSTS_MISSING",
                    "Verificacao estrita de host key esta ativa, mas nenhum arquivo known_hosts foi encontrado.",
                )
        if has_local_targets and os.name != "nt":
            for tool in sorted(needed_local_tools):
                if not local_bins.get(tool, {}).get("available"):
                    report.add(
                        PREFLIGHT_WARNING,
                        "LOCAL_BINARY_MISSING",
                        f"Binario local '{tool}' nao encontrado no PATH para testes locais.",
                    )

    report.valid_targets = sum(
        1
        for t in targets
        if not target_or_origin_has_preflight_error(
            t, origins.get(t.origin_number) if t.origin_number else None
        )
    )
    report.blocked_targets = len(targets) - report.valid_targets
    return report, targets, origins


# ---------------------------------------------------------------------------
# Comparacao com Baseline e Deteccao de Regressoes / Mudanca de Rota
# ---------------------------------------------------------------------------

def load_baseline(baseline_path):
    """Carrega um arquivo results.json (ou diretorio de execucao anterior contendo results.json)."""
    if not baseline_path:
        return None
    path = str(baseline_path)
    if os.path.isdir(path):
        candidate = os.path.join(path, JSON_RESULTS_FILE)
        if os.path.exists(candidate):
            path = candidate
        else:
            # Procura subdiretorio mais recente contendo results.json:
            subdirs = sorted(
                (
                    os.path.join(path, d, JSON_RESULTS_FILE)
                    for d in os.listdir(path)
                    if os.path.exists(os.path.join(path, d, JSON_RESULTS_FILE))
                ),
                reverse=True,
            )
            if subdirs:
                path = subdirs[0]
    if not os.path.exists(path):
        raise FileNotFoundError(f"Arquivo de baseline nao encontrado: '{baseline_path}'")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or "results" not in data:
        raise ValueError(f"Arquivo de baseline invalido (esperado objeto com 'results'): '{path}'")
    return data


def _confirmed_hop_sequence(hops):
    seq = []
    for h in hops or ():
        if isinstance(h, dict) and not h.get("is_timeout") and h.get("ip"):
            seq.append(f"{h.get('hop')}:{h.get('ip')}")
    return seq


def compare_with_baseline(results, baseline_data):
    """Compara os resultados atuais com um baseline anterior e anota cada TestResult."""
    if not baseline_data:
        return None

    prev_items = baseline_data.get("results", [])
    by_exact_key = {}
    by_loose_key = {}
    for item in prev_items:
        if not isinstance(item, dict):
            continue
        k = item.get("comparison_key")
        if not k:
            orig_id = (item.get("origin") or {}).get("number", "local")
            real_ip = (item.get("origin") or {}).get("real_ip", "")
            tgt = item.get("target") or {}
            k = (
                f"{orig_id}|{real_ip}|{tgt.get('host', '').lower()}|"
                f"{tgt.get('effective_ip', '')}|{tgt.get('port') if tgt.get('port') is not None else '-'}|"
                f"{tgt.get('protocol', '')}|{tgt.get('transport', '')}"
            )
        by_exact_key[k] = item
        tgt = item.get("target") or {}
        orig_id = (item.get("origin") or {}).get("number", "local")
        real_ip = (item.get("origin") or {}).get("real_ip", "")
        loose_k = (
            f"{orig_id}|{real_ip}|{tgt.get('host', '').lower()}|"
            f"{tgt.get('port') if tgt.get('port') is not None else '-'}|"
            f"{tgt.get('protocol', '')}|{tgt.get('transport', '')}"
        )
        by_loose_key.setdefault(loose_k, item)

    matched_keys = set()
    diffs = []
    regressions = 0
    recoveries = 0
    classification_changes = 0
    verdict_changes = 0
    route_changes = 0
    latency_changes = 0
    new_tests = 0

    for res in results:
        exact_k = res.comparison_key()
        orig_id = res.origin.number if res.origin else (res.target.origin_number or "local")
        real_ip = res.origin.real_ip if res.origin else ""
        loose_k = (
            f"{orig_id}|{real_ip}|{res.target.host.lower()}|"
            f"{res.target.port if res.target.port is not None else '-'}|"
            f"{res.target.protocol}|{res.target.transport}"
        )
        prev = by_exact_key.get(exact_k) or by_loose_key.get(loose_k)
        if prev is None:
            new_tests += 1
            res.baseline_diff = {
                "status": "NEW_TEST",
                "has_changes": False,
                "regression": False,
                "recovery": False,
            }
            continue

        prev_k = prev.get("comparison_key")
        if prev_k:
            matched_keys.add(prev_k)

        prev_ok = bool(prev.get("ok"))
        prev_status = prev.get("status", "")
        prev_cls = prev.get("classification", "")
        prev_verdict = (prev.get("composite") or {}).get("policy_verdict", POLICY_NOT_APPLICABLE)
        curr_verdict = (res.composite or {}).get("policy_verdict", POLICY_NOT_APPLICABLE)
        prev_eff_ip = (prev.get("target") or {}).get("effective_ip", "")
        curr_eff_ip = res.target.effective_ip or ""
        prev_hops = _confirmed_hop_sequence(prev.get("hops", []))
        curr_hops = _confirmed_hop_sequence(res.hops)
        prev_ms = int(prev.get("elapsed_ms", 0) or 0)
        curr_ms = int(res.elapsed_ms or 0)

        is_regression = prev_ok and not res.ok
        is_recovery = (not prev_ok) and res.ok
        cls_changed = prev_cls != res.classification
        verdict_changed = prev_verdict != curr_verdict
        route_changed = bool(prev_hops or curr_hops) and (prev_hops != curr_hops)
        eff_ip_changed = bool(prev_eff_ip and curr_eff_ip and prev_eff_ip != curr_eff_ip)
        latency_delta = curr_ms - prev_ms
        latency_changed = abs(latency_delta) >= 100 and (
            prev_ms == 0 or (max(curr_ms, 1) / max(prev_ms, 1) >= 2.0) or (max(prev_ms, 1) / max(curr_ms, 1) >= 2.0)
        )

        if is_regression:
            regressions += 1
        if is_recovery:
            recoveries += 1
        if cls_changed:
            classification_changes += 1
        if verdict_changed:
            verdict_changes += 1
        if route_changed:
            route_changes += 1
        if latency_changed:
            latency_changes += 1

        has_changes = any(
            (is_regression, is_recovery, cls_changed, verdict_changed, route_changed, eff_ip_changed, latency_changed)
        )
        diff_obj = {
            "status": (
                "REGRESSION"
                if is_regression
                else ("RECOVERY" if is_recovery else ("CHANGED" if has_changes else "UNCHANGED"))
            ),
            "has_changes": has_changes,
            "regression": is_regression,
            "recovery": is_recovery,
            "classification_changed": cls_changed,
            "previous_classification": prev_cls,
            "current_classification": res.classification,
            "status_changed": prev_status != res.status,
            "previous_status": prev_status,
            "current_status": res.status,
            "policy_verdict_changed": verdict_changed,
            "previous_policy_verdict": prev_verdict,
            "current_policy_verdict": curr_verdict,
            "effective_ip_changed": eff_ip_changed,
            "previous_effective_ip": prev_eff_ip,
            "current_effective_ip": curr_eff_ip,
            "route_changed": route_changed,
            "previous_confirmed_hops": prev_hops,
            "current_confirmed_hops": curr_hops,
            "latency_changed": latency_changed,
            "previous_elapsed_ms": prev_ms,
            "current_elapsed_ms": curr_ms,
            "latency_delta_ms": latency_delta,
        }
        res.baseline_diff = diff_obj
        if has_changes:
            diffs.append(
                {
                    "comparison_key": exact_k,
                    "row": res.target.row,
                    "origin": orig_id,
                    "destination": res.target.host,
                    "port": res.target.port,
                    "protocol": res.target.protocol,
                    **diff_obj,
                }
            )

    missing_tests = sum(1 for k in by_exact_key if k not in matched_keys)
    return {
        "baseline_run_id": baseline_data.get("run_id", ""),
        "total_compared": len(results) - new_tests,
        "regressions": regressions,
        "recoveries": recoveries,
        "classification_changes": classification_changes,
        "verdict_changes": verdict_changes,
        "route_changes": route_changes,
        "latency_changes": latency_changes,
        "new_tests": new_tests,
        "missing_tests": missing_tests,
        "diffs": diffs,
    }


# ---------------------------------------------------------------------------
# Execucao Paralela Segura por Origem
# ---------------------------------------------------------------------------

def execute_plan(
    targets,
    origins,
    workers=1,
    retries=0,
    enable_remote_preflight=True,
    quiet=False,
    progress_callback=None,
):
    """Executa a lista de testes serializando por origem e paralelizando entre origens distintas.

    - Cada grupo de origem recebe sua propria instancia isolada de SSHPool (uma sessao SSH
      nunca e compartilhada concorrentemente entre threads).
    - Preserva a ordem original das linhas da planilha no resultado final.
    - Garante o fechamento de todas as sessoes SSH em caso de erro ou Ctrl+C.
    """
    if not targets:
        return []

    max_workers = max(1, int(workers or 1))
    indexed_groups = {}
    group_order = []
    for idx, target in enumerate(targets):
        key = target.origin_number or "__local__"
        if key not in indexed_groups:
            indexed_groups[key] = []
            group_order.append(key)
        indexed_groups[key].append((idx, target))

    results_by_index = {}
    callback_lock = threading.Lock()

    def run_origin_group(group_key):
        group_items = indexed_groups[group_key]
        pool = SSHPool(enable_remote_preflight=enable_remote_preflight, quiet=quiet)
        group_results = []
        try:
            for idx, target in group_items:
                origin = origins.get(target.origin_number) if target.origin_number else None
                if target.origin_number and origin is None:
                    msg = f"Origem {target.origin_number} nao encontrada na tabela de origens"
                    res = TestResult(
                        target,
                        None,
                        False,
                        "FALHA",
                        msg,
                        0,
                        summary=msg,
                        classification=CLASSIFICATION_EXECUTION_ERROR,
                    )
                else:
                    res = run_test(target, origin, pool, retries=retries)
                group_results.append((idx, res))
                if progress_callback is not None:
                    with callback_lock:
                        progress_callback(res)
        finally:
            pool.close_all()
        return group_results

    try:
        if max_workers == 1 or len(group_order) == 1:
            for key in group_order:
                for idx, res in run_origin_group(key):
                    results_by_index[idx] = res
        else:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(max_workers, len(group_order))
            ) as executor:
                future_map = {
                    executor.submit(run_origin_group, key): key for key in group_order
                }
                for future in concurrent.futures.as_completed(future_map):
                    for idx, res in future.result():
                        results_by_index[idx] = res
    finally:
        close_all_active_ssh_pools()

    return [results_by_index[idx] for idx in sorted(results_by_index)]


def print_result(result):
    target = result.target
    origin_text = result.origin.number if result.origin else target.origin_number or "-"
    port_text = target.port if target.port is not None else "-"
    description = f" - {target.description}" if target.description else ""
    color = "\033[92m" if result.ok else "\033[91m"
    origin_ip = f" ({result.origin.display_ip})" if result.origin else ""
    print(
        f"{color}[{result.status}]\033[0m "
        f"linha={target.row} origem={origin_text}{origin_ip} "
        f"destino={target.host}:{port_text} protocolo={target.protocol} "
        f"tempo={result.elapsed_ms}ms{description}"
    )
    if is_trace(result):
        print(f"    {color}[{result.classification}] {result.summary}\033[0m")
        if result.method:
            print(f"    Metodo: {result.method}")
        if result.composite and result.composite.get("policy_verdict") != POLICY_NOT_APPLICABLE:
            print(
                f"    Policy Verdict: {result.composite.get('policy_verdict')} "
                f"(servico={result.composite.get('service_result')})"
            )
        for note in result.notes:
            print(f"    \033[93m[AVISO]\033[0m {note}")
    detail = sanitize_text(result.detail or "")
    for line in detail.splitlines():
        print(f"    {line}")


# ---------------------------------------------------------------------------
# Geracao de Relatorios (TXT, CSV, JSON, HTML e Run Manifest)
# ---------------------------------------------------------------------------

def save_trace_dump(results, path=TRACE_DUMP_FILE, run_id="", preflight_report=None, force_create=False):
    """Grava a saida integral de traceroute/tracepath em um arquivo texto separado."""
    trace_results = [result for result in results if is_trace(result)]
    if not trace_results and not force_create:
        return False

    with open(path, "w", encoding="utf-8", newline="") as file:
        if run_id:
            file.write(f"# NetCheck-XLS Trace Evidence Dump | Run ID: {run_id}\n")
        if preflight_report is not None and preflight_report.issues:
            file.write(
                f"# Preflight: {preflight_report.error_count} erro(s), "
                f"{preflight_report.warning_count} aviso(s)\n"
            )
        if not trace_results:
            file.write("Nenhum teste de trace executado nesta rodada.\n")
            return True

        for index, result in enumerate(trace_results, start=1):
            target = result.target
            origin = result.origin

            if index > 1 or run_id or (preflight_report is not None and preflight_report.issues):
                file.write("\n")
            file.write("=" * 80 + "\n")
            file.write(f"TRACE {index}\n")
            if run_id:
                file.write(f"Run ID: {run_id}\n")
            file.write(f"Status: {result.status}\n")
            file.write(f"Classificacao: {result.classification}\n")
            file.write(f"Classificacao Trace: {result.trace_classification}\n")
            file.write(f"Resultado: {sanitize_text(result.summary or '-')}\n")
            if origin:
                file.write(f"Origem: {origin.display_ip}\n")
                if origin.real_ip:
                    file.write(f"IP Real: {origin.real_ip}\n")
                else:
                    file.write(
                        f"IP Real: nao informado (exibindo Hostname/IP de gerencia da coluna I: {origin.host})\n"
                    )
                if TRACE_DUMP_SHOW_ACCESS_HOST:
                    access_host = (
                        f"{origin.host}:{origin.port}"
                        if origin.port and origin.port != 22
                        else origin.host
                    )
                    file.write(f"Acesso via (gerencia): {access_host}\n")
                if origin.ssh_audit:
                    prof = origin.ssh_audit.get("profile_name", "")
                    if prof:
                        file.write(f"SSH Profile: {prof}\n")
                    warn = origin.ssh_audit.get("security_warning", "")
                    if warn:
                        file.write(f"SSH Security Warning: {sanitize_text(warn)}\n")
            else:
                file.write("Origem: local\n")
            file.write(f"Destino: {target.host}\n")
            if target.effective_ip and target.effective_ip != target.host:
                file.write(f"Destino IP Efetivo: {target.effective_ip}\n")
            if target.port:
                file.write(f"Porta: {target.port}\n")
            file.write(f"Protocolo: {target.protocol}\n")
            file.write(f"Metodo: {result.method or '-'}\n")
            if result.command:
                file.write(f"Comando: {sanitize_text(result.command)}\n")
            if result.composite:
                pv = result.composite.get("policy_verdict", POLICY_NOT_APPLICABLE)
                svc = result.composite.get("service_result", SERVICE_NOT_TESTED)
                svc_det = sanitize_text(result.composite.get("service_detail", ""))
                eligible = "SIM" if result.composite.get("firewall_request_eligible") else "NAO"
                file.write(f"Policy Verdict: {pv}\n")
                if svc != SERVICE_NOT_TESTED:
                    file.write(f"Servico Pos-Trace: {svc} ({svc_det})\n")
                file.write(f"Elegivel para Firewall: {eligible}\n")
            if result.diagnosis:
                d_code = result.diagnosis.get("diagnosis_code", "")
                d_desc = sanitize_text(result.diagnosis.get("description", ""))
                file.write(f"Diagnostico: {d_code} - {d_desc}\n")
            file.write(f"Descricao: {target.description or '-'}\n")
            file.write(f"Tempo total: {result.elapsed_ms} ms\n")
            for note in result.notes:
                file.write(f"Aviso: {sanitize_text(note)}\n")
            file.write("-" * 80 + "\n")

            # Sem limpeza, resumo ou corte: grava exatamente todo o detalhe capturado (sanitizado).
            detail = sanitize_text(result.detail if result.detail is not None else "")
            file.write(detail)
            if not detail.endswith("\n"):
                file.write("\n")
            file.write("=" * 80 + "\n")

    return True


def save_results(results, path=RESULTS_FILE, run_id="", include_traces=False):
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(
            file,
            quoting=csv.QUOTE_MINIMAL,
            lineterminator="\n",
        )
        writer.writerow(
            [
                "status",
                "linha",
                "origem_numero",
                "origem_host",
                "origem_ip_real",
                "destino_host",
                "destino_porta",
                "protocolo",
                "descricao",
                "tempo_ms",
                "detalhe",
                "classification",
                "trace_classification",
                "service_result",
                "diagnosis_code",
                "policy_verdict",
                "run_id",
            ]
        )
        for result in results:
            if is_trace(result) and not include_traces:
                continue
            writer.writerow(
                [
                    result.status,
                    result.target.row,
                    result.origin.number if result.origin else result.target.origin_number,
                    result.origin.host if result.origin else "",
                    result.origin.real_ip if result.origin else "",
                    result.target.host,
                    result.target.port or "",
                    result.target.protocol,
                    result.target.description,
                    result.elapsed_ms,
                    sanitize_text(result.detail),
                    result.classification,
                    result.trace_classification,
                    result.service_result,
                    (result.diagnosis or {}).get("diagnosis_code", ""),
                    (result.composite or {}).get("policy_verdict", POLICY_NOT_APPLICABLE),
                    run_id,
                ]
            )


def _compute_results_summary(results):
    by_cls = {}
    by_diag = {}
    by_verdict = {}
    ok_count = 0
    trace_count = 0
    flaky_count = 0
    eligible_count = 0
    legacy_ssh_count = 0

    for r in results:
        if r.ok:
            ok_count += 1
        if is_trace(r):
            trace_count += 1
        if r.flaky:
            flaky_count += 1
        if (r.composite or {}).get("firewall_request_eligible"):
            eligible_count += 1
        if r.origin and (r.origin.ssh_audit or {}).get("legacy_fallback_used"):
            legacy_ssh_count += 1
        cls = r.classification or "UNCLASSIFIED"
        by_cls[cls] = by_cls.get(cls, 0) + 1
        d_code = (r.diagnosis or {}).get("diagnosis_code", "NONE")
        by_diag[d_code] = by_diag.get(d_code, 0) + 1
        pv = (r.composite or {}).get("policy_verdict", POLICY_NOT_APPLICABLE)
        by_verdict[pv] = by_verdict.get(pv, 0) + 1

    return {
        "total": len(results),
        "ok": ok_count,
        "failed": len(results) - ok_count,
        "traces": trace_count,
        "connectivity": len(results) - trace_count,
        "flaky": flaky_count,
        "firewall_request_eligible": eligible_count,
        "legacy_ssh_results": legacy_ssh_count,
        "by_classification": by_cls,
        "by_diagnosis_code": by_diag,
        "by_policy_verdict": by_verdict,
    }


def save_html_report(
    path,
    run_id,
    manifest,
    preflight_report,
    origins,
    results,
    baseline_summary=None,
):
    """Gera um relatorio HTML5 autocontido (sem CDN nem assets externos) com filtros e detalhes."""
    esc = html.escape
    summary = manifest.get("summary", {})

    origin_options = sorted(
        {
            (r.origin.number if r.origin else (r.target.origin_number or "local"))
            for r in results
        }
    )
    cls_options = sorted({r.classification or "-" for r in results})
    diag_options = sorted({(r.diagnosis or {}).get("diagnosis_code", "-") for r in results})
    verdict_options = sorted(
        {(r.composite or {}).get("policy_verdict", POLICY_NOT_APPLICABLE) for r in results}
    )

    preflight_rows_html = []
    if preflight_report and preflight_report.issues:
        for issue in preflight_report.issues:
            sev_class = f"badge-{issue.severity.lower()}"
            preflight_rows_html.append(
                f"<tr>"
                f"<td><span class='badge {esc(sev_class)}'>{esc(issue.severity)}</span></td>"
                f"<td><code>{esc(issue.code)}</code></td>"
                f"<td>{esc(str(issue.row or '-'))}</td>"
                f"<td>{esc(str(issue.origin or '-'))}</td>"
                f"<td>{esc(str(issue.target or '-'))}</td>"
                f"<td>{esc(sanitize_text(issue.message))}</td>"
                f"</tr>"
            )
    else:
        preflight_rows_html.append(
            "<tr><td colspan='6' class='muted'>Nenhum problema de preflight detectado.</td></tr>"
        )

    origin_rows_html = []
    for num, orig in sorted((origins or {}).items()):
        audit = orig.ssh_audit or {}
        rem = orig.remote_preflight or {}
        prof = audit.get("profile_name") or "nao conectado"
        legacy_badge = (
            "<span class='badge badge-warning'>LEGADO</span>"
            if audit.get("legacy_fallback_used")
            else "<span class='badge badge-ok'>PADRAO</span>"
        )
        real_ip_status = ""
        if rem.get("real_ip_present") is True:
            real_ip_status = " (confirmado na interface)"
        elif rem.get("real_ip_present") is False:
            real_ip_status = " (AUSENTE na interface!)"
        origin_rows_html.append(
            f"<tr>"
            f"<td>{esc(str(orig.number))}</td>"
            f"<td><code>{esc(orig.host)}:{orig.port}</code></td>"
            f"<td><code>{esc(orig.real_ip or '-')}</code>{esc(real_ip_status)}</td>"
            f"<td>{esc(orig.username or '-')}</td>"
            f"<td><code>{esc(orig.credential_source)}</code></td>"
            f"<td>{legacy_badge} {esc(prof)}</td>"
            f"<td>{esc(sanitize_text(orig.error or audit.get('security_warning') or '-'))}</td>"
            f"</tr>"
        )
    if not origin_rows_html:
        origin_rows_html.append(
            "<tr><td colspan='7' class='muted'>Nenhuma origem remota configurada.</td></tr>"
        )

    baseline_html = ""
    if baseline_summary:
        diff_rows = []
        for d in baseline_summary.get("diffs", []):
            diff_rows.append(
                f"<tr>"
                f"<td><span class='badge'>{esc(d.get('status', ''))}</span></td>"
                f"<td>{esc(str(d.get('row', '-')))}</td>"
                f"<td>{esc(str(d.get('origin', '-')))}</td>"
                f"<td><code>{esc(str(d.get('destination', '-')))}:{esc(str(d.get('port') or '-'))}</code></td>"
                f"<td><code>{esc(str(d.get('previous_classification', '-')))} &rarr; {esc(str(d.get('current_classification', '-')))}</code></td>"
                f"<td><code>{esc(str(d.get('previous_policy_verdict', '-')))} &rarr; {esc(str(d.get('current_policy_verdict', '-')))}</code></td>"
                f"<td>{'SIM' if d.get('route_changed') else 'NAO'}</td>"
                f"<td>{esc(str(d.get('previous_elapsed_ms', 0)))}ms &rarr; {esc(str(d.get('current_elapsed_ms', 0)))}ms</td>"
                f"</tr>"
            )
        if not diff_rows:
            diff_rows.append(
                "<tr><td colspan='8' class='muted'>Nenhuma divergencia em relacao ao baseline.</td></tr>"
            )
        baseline_html = f"""
        <section class="panel">
          <h2>Comparacao com Baseline ({esc(str(baseline_summary.get('baseline_run_id') or 'anterior'))})</h2>
          <p class="muted">
            Comparados: {baseline_summary.get('total_compared', 0)} |
            Regressoes: <strong>{baseline_summary.get('regressions', 0)}</strong> |
            Recuperacoes: <strong>{baseline_summary.get('recoveries', 0)}</strong> |
            Mudancas de rota: <strong>{baseline_summary.get('route_changes', 0)}</strong> |
            Novos testes: {baseline_summary.get('new_tests', 0)}
          </p>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th> Mudanca </th><th>Linha</th><th>Origem</th><th>Destino</th>
                  <th>Classificacao</th><th>Policy Verdict</th><th>Rota Alterada</th><th>Latencia</th>
                </tr>
              </thead>
              <tbody>{''.join(diff_rows)}</tbody>
            </table>
          </div>
        </section>
        """

    result_rows_html = []
    for idx, r in enumerate(results, start=1):
        t = r.target
        orig = r.origin
        orig_id = orig.number if orig else (t.origin_number or "local")
        orig_mgmt = f"{orig.host}:{orig.port}" if orig else "local"
        orig_real = orig.real_ip if orig and orig.real_ip else "-"
        cls = r.classification or "-"
        diag = r.diagnosis or {}
        diag_code = diag.get("diagnosis_code", "-")
        diag_desc = sanitize_text(diag.get("description", ""))
        comp = r.composite or {}
        verdict = comp.get("policy_verdict", POLICY_NOT_APPLICABLE)
        svc_res = comp.get("service_result", SERVICE_NOT_TESTED)
        svc_det = sanitize_text(comp.get("service_detail", ""))
        eligible = "SIM" if comp.get("firewall_request_eligible") else "NAO"
        status_cls = "badge-ok" if r.ok else "badge-error"

        hops_html = ""
        if r.hops:
            hop_lines = []
            for h in r.hops:
                hop_lines.append(
                    f"<tr><td>{h.get('hop')}</td><td><code>{esc(str(h.get('ip') or '*'))}</code></td>"
                    f"<td>{esc(str(h.get('rtt_ms') if h.get('rtt_ms') is not None else '-'))}</td>"
                    f"<td>{esc(str(h.get('annotation') or '-'))}</td>"
                    f"<td>{'SIM' if h.get('is_destination') else 'NAO'}</td></tr>"
                )
            hops_html = (
                "<h4>Hops Normalizados</h4>"
                "<table class='subtable'><thead><tr><th>Hop</th><th>IP</th><th>RTT (ms)</th>"
                "<th>Anotacao</th><th>Destino</th></tr></thead><tbody>"
                + "".join(hop_lines)
                + "</tbody></table>"
            )

        notes_html = ""
        if r.notes:
            notes_html = (
                "<ul>"
                + "".join(f"<li>{esc(sanitize_text(n))}</li>" for n in r.notes)
                + "</ul>"
            )

        result_rows_html.append(
            f"<tr class='result-row' "
            f"data-origin='{esc(str(orig_id))}' "
            f"data-status='{esc(r.status)}' "
            f"data-classification='{esc(cls)}' "
            f"data-diagnosis='{esc(diag_code)}' "
            f"data-verdict='{esc(verdict)}'>"
            f"<td>{t.row}</td>"
            f"<td><span class='badge {status_cls}'>{esc(r.status)}</span></td>"
            f"<td><strong>{esc(str(orig_id))}</strong><br><small>Ger: <code>{esc(orig_mgmt)}</code><br>Real: <code>{esc(orig_real)}</code></small></td>"
            f"<td><code>{esc(t.host)}</code>"
            + (f"<br><small>Efetivo: <code>{esc(t.effective_ip)}</code></small>" if t.effective_ip else "")
            + f"</td>"
            f"<td>{esc(str(t.port if t.port is not None else '-'))}</td>"
            f"<td><code>{esc(t.protocol)}</code>"
            + (f" ({esc(t.transport)})" if t.transport else "")
            + "</td>"
            f"<td><code>{esc(cls)}</code>"
            + (
                f"<br><small>Trace: <code>{esc(r.trace_classification)}</code></small>"
                if r.trace_classification and r.trace_classification not in (cls, "NOT_APPLICABLE")
                else ""
            )
            + "</td>"
            f"<td><code>{esc(verdict)}</code><br><small>{esc(svc_res)}</small></td>"
            f"<td><code>{esc(diag_code)}</code><br><small>{esc(diag_desc)}</small></td>"
            f"<td>{eligible}</td>"
            f"<td>{r.elapsed_ms} ms</td>"
            f"<td>"
            f"<details><summary>{esc(sanitize_text(r.summary or (r.detail or '')[:80] or 'Ver detalhes'))}</summary>"
            f"<div class='detail-box'>"
            f"<p><strong>Descricao:</strong> {esc(t.description or '-')} | "
            f"<strong>Metodo:</strong> {esc(r.method or '-')} | "
            f"<strong>Tentativas:</strong> {len(r.attempts or [1])}</p>"
            + (f"<p><strong>Comando:</strong> <code>{esc(sanitize_text(r.command))}</code></p>" if r.command else "")
            + (f"<p><strong>Servico Pos-Trace:</strong> <code>{esc(svc_res)}</code> — {esc(svc_det)}</p>" if svc_res != SERVICE_NOT_TESTED else "")
            + notes_html
            + hops_html
            + f"<pre>{esc(sanitize_text(r.detail or ''))}</pre>"
            f"</div></details></td>"
            f"</tr>"
        )

    def _opts(values):
        return "".join(f"<option value='{esc(str(v))}'>{esc(str(v))}</option>" for v in values)

    html_doc = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetCheck-XLS Report — {esc(run_id)}</title>
<style>
  :root {{
    --bg: #0f172a; --panel: #1e293b; --border: #334155; --text: #f8fafc;
    --muted: #94a3b8; --ok: #16a34a; --err: #dc2626; --warn: #d97706; --info: #2563eb;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; padding: 24px; font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.45; }}
  h1, h2, h3, h4 {{ margin-top: 0; }}
  .header {{ display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px; margin-bottom: 20px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(155px, 1fr)); gap: 12px; margin-bottom: 20px; }}
  .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 14px; }}
  .card .label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; }}
  .card .val {{ font-size: 26px; font-weight: 700; margin-top: 4px; }}
  .panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 20px; }}
  .filters {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 14px; }}
  .filters input, .filters select {{ background: #0b1120; color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 7px 10px; }}
  .table-wrap {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ border-bottom: 1px solid var(--border); padding: 8px 10px; text-align: left; vertical-align: top; }}
  th {{ background: #0b1120; color: var(--muted); font-weight: 600; }}
  .subtable {{ margin: 8px 0; font-size: 12px; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; background: var(--border); }}
  .badge-ok {{ background: var(--ok); color: #fff; }}
  .badge-error {{ background: var(--err); color: #fff; }}
  .badge-warning {{ background: var(--warn); color: #fff; }}
  .badge-info {{ background: var(--info); color: #fff; }}
  .muted {{ color: var(--muted); }}
  .detail-box {{ margin-top: 8px; padding: 10px; background: #0b1120; border: 1px solid var(--border); border-radius: 6px; }}
  pre {{ white-space: pre-wrap; word-break: break-word; margin: 8px 0 0; font-size: 12px; color: #e2e8f0; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }}
</style>
</head>
<body>
  <div class="header">
    <div>
      <h1>NetCheck-XLS — Relatorio de Evidencia e Diagnostico</h1>
      <div class="muted">
        Run ID: <code>{esc(run_id)}</code> |
        Template: <code>{esc(str(manifest.get('template_path', '')))}</code> |
        SHA-256: <code>{esc(str(manifest.get('template_sha256', ''))[:16])}...</code> |
        Inicio UTC: <code>{esc(str(manifest.get('started_at_utc', '')))}</code>
      </div>
    </div>
  </div>

  <div class="cards">
    <div class="card"><div class="label">Total de Testes</div><div class="val">{summary.get('total', 0)}</div></div>
    <div class="card"><div class="label">Validados (OK)</div><div class="val" style="color:#4ade80">{summary.get('ok', 0)}</div></div>
    <div class="card"><div class="label">Falhas</div><div class="val" style="color:#f87171">{summary.get('failed', 0)}</div></div>
    <div class="card"><div class="label">Elegiveis Firewall</div><div class="val">{summary.get('firewall_request_eligible', 0)}</div></div>
    <div class="card"><div class="label">Flaky / Intermitentes</div><div class="val">{summary.get('flaky', 0)}</div></div>
    <div class="card"><div class="label">Erros Preflight</div><div class="val">{preflight_report.error_count if preflight_report else 0}</div></div>
  </div>

  <section class="panel">
    <h2>Preflight &amp; Validacao de Entrada</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Severidade</th><th>Codigo</th><th>Linha</th><th>Origem</th><th>Alvo</th><th>Mensagem</th></tr></thead>
        <tbody>{''.join(preflight_rows_html)}</tbody>
      </table>
    </div>
  </section>

  <section class="panel">
    <h2>Origens &amp; Auditoria de Seguranca SSH</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Origem</th><th>IP Gerencia (SSH)</th><th>IP Real (Firewall / -s)</th><th>Usuario</th><th>Credencial</th><th>Perfil SSH</th><th>Observacoes / Avisos</th></tr></thead>
        <tbody>{''.join(origin_rows_html)}</tbody>
      </table>
    </div>
  </section>

  {baseline_html}

  <section class="panel">
    <h2>Resultados de Conectividade, Traces e Politica Composta</h2>
    <div class="filters">
      <input type="search" id="f-search" placeholder="Filtrar por host, IP, detalhe..." oninput="applyFilters()">
      <select id="f-origin" onchange="applyFilters()"><option value="">Todas as Origens</option>{_opts(origin_options)}</select>
      <select id="f-status" onchange="applyFilters()"><option value="">Todos os Status</option><option value="OK">OK</option><option value="FALHA">FALHA</option></select>
      <select id="f-cls" onchange="applyFilters()"><option value="">Todas as Classificacoes</option>{_opts(cls_options)}</select>
      <select id="f-diag" onchange="applyFilters()"><option value="">Todos os Diagnosticos</option>{_opts(diag_options)}</select>
      <select id="f-verdict" onchange="applyFilters()"><option value="">Todos os Policy Verdicts</option>{_opts(verdict_options)}</select>
    </div>
    <div class="table-wrap">
      <table id="results-table">
        <thead>
          <tr>
            <th>Linha</th><th>Status</th><th>Origem (Gerencia vs Real)</th><th>Destino</th>
            <th>Porta</th><th>Protocolo</th><th>Classificacao</th><th>Policy Verdict</th>
            <th>Diagnostico Automatico</th><th>Firewall?</th><th>Tempo</th><th>Evidencia / Trace</th>
          </tr>
        </thead>
        <tbody>{''.join(result_rows_html)}</tbody>
      </table>
    </div>
  </section>

<script>
function applyFilters() {{
  var q = (document.getElementById('f-search').value || '').toLowerCase();
  var orig = document.getElementById('f-origin').value;
  var st = document.getElementById('f-status').value;
  var cls = document.getElementById('f-cls').value;
  var diag = document.getElementById('f-diag').value;
  var verd = document.getElementById('f-verdict').value;
  var rows = document.querySelectorAll('#results-table tbody tr.result-row');
  rows.forEach(function(row) {{
    var show = true;
    if (orig && row.getAttribute('data-origin') !== orig) show = false;
    if (st && row.getAttribute('data-status') !== st) show = false;
    if (cls && row.getAttribute('data-classification') !== cls) show = false;
    if (diag && row.getAttribute('data-diagnosis') !== diag) show = false;
    if (verd && row.getAttribute('data-verdict') !== verd) show = false;
    if (show && q && row.textContent.toLowerCase().indexOf(q) === -1) show = false;
    row.style.display = show ? '' : 'none';
  }});
}}
</script>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_doc)


def generate_run_id(started_dt=None):
    dt = started_dt or datetime.datetime.now(datetime.timezone.utc)
    ts = dt.strftime("%Y-%m-%dT%H%M%SZ")
    short_id = uuid.uuid4().hex[:8]
    return f"{ts}_{short_id}"


def parse_formats_option(format_str):
    if not format_str:
        return ("json", "html", "csv", "txt")
    allowed = {"json", "html", "csv", "txt"}
    items = []
    for part in str(format_str).split(","):
        tok = part.strip().lower()
        if not tok:
            continue
        if tok not in allowed:
            raise ValueError(
                f"Formato de relatorio invalido '{tok}' (permitidos: json, html, csv, txt)"
            )
        if tok not in items:
            items.append(tok)
    return tuple(items) if items else ("json", "html", "csv", "txt")


def write_run_bundle(
    output_dir,
    run_id,
    command_name,
    template_path,
    started_dt,
    finished_dt,
    parameters,
    preflight_report,
    origins,
    results,
    baseline_summary=None,
    formats=("json", "html", "csv", "txt"),
):
    """Cria o diretorio exclusivo da execucao e grava todos os artefatos solicitados."""
    run_dir = os.path.join(output_dir, run_id)
    os.makedirs(run_dir, exist_ok=True)

    template_sha256 = compute_file_sha256(template_path)
    duration_ms = max(0, int((finished_dt - started_dt).total_seconds() * 1000))
    summary = _compute_results_summary(results)

    sanitized_params = {}
    for k, v in (parameters or {}).items():
        if isinstance(v, str):
            sanitized_params[k] = sanitize_text(v)
        else:
            sanitized_params[k] = v

    artifacts = {}
    if "csv" in formats:
        csv_path = os.path.join(run_dir, RESULTS_FILE)
        has_regular = any(not is_trace(r) for r in results)
        save_results(
            results,
            path=csv_path,
            run_id=run_id,
            include_traces=not has_regular,
        )
        artifacts["csv"] = csv_path

    if "txt" in formats:
        txt_path = os.path.join(run_dir, TRACE_DUMP_FILE)
        save_trace_dump(
            results,
            path=txt_path,
            run_id=run_id,
            preflight_report=preflight_report,
            force_create=True,
        )
        artifacts["txt"] = txt_path

    manifest_path = os.path.join(run_dir, RUN_MANIFEST_FILE)
    results_json_path = os.path.join(run_dir, JSON_RESULTS_FILE)
    html_path = os.path.join(run_dir, HTML_REPORT_FILE)

    if "json" in formats:
        artifacts["results_json"] = results_json_path
        artifacts["run_manifest_json"] = manifest_path
    if "html" in formats:
        artifacts["html"] = html_path

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "app_version": APP_VERSION,
        "git_commit": detect_git_commit(),
        "run_id": run_id,
        "command": command_name,
        "started_at_utc": started_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "finished_at_utc": finished_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration_ms": duration_ms,
        "template_path": str(template_path or ""),
        "template_sha256": template_sha256,
        "parameters": sanitized_params,
        "environment": {
            "platform": sys.platform,
            "os_name": os.name,
            "python_version": sys.version.split()[0],
            "binaries": detect_local_binaries(),
        },
        "preflight_summary": preflight_report.to_dict() if preflight_report else {},
        "summary": summary,
        "baseline_summary": baseline_summary,
        "artifacts": artifacts,
    }

    results_payload = {
        "schema_version": SCHEMA_VERSION,
        "app_version": APP_VERSION,
        "run_id": run_id,
        "generated_at_utc": finished_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "template_path": str(template_path or ""),
        "template_sha256": template_sha256,
        "preflight": preflight_report.to_dict() if preflight_report else {},
        "origins": [orig.to_dict() for _, orig in sorted((origins or {}).items())],
        "summary": summary,
        "baseline_comparison": baseline_summary,
        "results": [r.to_dict() for r in results],
    }

    if "json" in formats:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
        with open(results_json_path, "w", encoding="utf-8") as f:
            json.dump(results_payload, f, indent=2, ensure_ascii=False)

    if "html" in formats:
        save_html_report(
            html_path,
            run_id=run_id,
            manifest=manifest,
            preflight_report=preflight_report,
            origins=origins,
            results=results,
            baseline_summary=baseline_summary,
        )

    return run_dir, manifest, results_payload


def countdown():
    clear_terminal()
    print("Iniciando os testes em...")
    time.sleep(1)
    for value in ["3", "2", "1"]:
        clear_terminal()
        print(f"{value}...\npressione Ctrl + C para encerrar o programa")
        time.sleep(1)
    clear_terminal()


def write_outputs(results):
    regular_results = [result for result in results if not is_trace(result)]

    if regular_results:
        save_results(results)
    elif os.path.exists(RESULTS_FILE):
        os.remove(RESULTS_FILE)

    trace_dump_created = save_trace_dump(results)
    if regular_results:
        print(f"Testes de conectividade salvos em: {RESULTS_FILE}")
    if trace_dump_created:
        print(f"Saidas completas de trace salvas em: {TRACE_DUMP_FILE}")


def loop_reader(path):
    targets, origins = load_template(path)
    if not targets:
        print("Nenhum destino encontrado na planilha.")
        return []

    countdown()
    results = []
    print(f"{len(targets)} teste(s) carregado(s).")

    ssh_pool = SSHPool()
    try:
        for target in targets:
            origin = origins.get(target.origin_number)
            if target.origin_number and origin is None:
                result = TestResult(
                    target,
                    None,
                    False,
                    "FALHA",
                    f"Origem {target.origin_number} nao encontrada na tabela de origens",
                    0,
                    summary=f"Origem {target.origin_number} nao encontrada na tabela de origens",
                )
            else:
                result = run_test(target, origin, ssh_pool)
            print_result(result)
            results.append(result)
    except KeyboardInterrupt:
        # Preserva o que ja foi executado antes do Ctrl+C.
        print("\nExecucao interrompida pelo usuario; salvando resultados parciais...")
    finally:
        ssh_pool.close_all()
        if results:
            ok_count = sum(1 for result in results if result.ok)
            print(f"\nResumo: {ok_count}/{len(results)} OK, {len(results) - ok_count} FALHA.")
            write_outputs(results)
    return results


# ---------------------------------------------------------------------------
# CLI Nao Interativa (argparse) e Codigos de Saida Previsiveis
# ---------------------------------------------------------------------------

ALLOWED_FAIL_ON_TOKENS = {
    "any-failure",
    "preflight-error",
    "regression",
    "unconfirmed",
    "unreachable",
    "ssh-error",
    "execution-error",
    "legacy-ssh",
    "flaky",
    "none",
}


def parse_fail_on_option(fail_on_str):
    if not fail_on_str:
        return ("any-failure",)
    tokens = []
    for part in str(fail_on_str).split(","):
        tok = part.strip().lower()
        if not tok:
            continue
        if tok not in ALLOWED_FAIL_ON_TOKENS:
            raise ValueError(
                f"Condicao --fail-on invalida '{tok}' (permitidas: {', '.join(sorted(ALLOWED_FAIL_ON_TOKENS))})"
            )
        if tok not in tokens:
            tokens.append(tok)
    return tuple(tokens) if tokens else ("any-failure",)


def evaluate_exit_code(
    command_name,
    preflight_report,
    results,
    origins=None,
    baseline_summary=None,
    fail_on=("any-failure",),
):
    """Calcula o codigo de saida deterministico (0, 1, 2, 3)."""
    if command_name == "preflight":
        if preflight_report.has_errors:
            return EXIT_CONFIG_ERROR
        return EXIT_OK

    # Se o template nao existe, ou diretorio nao gravavel, ou nenhum destino valido:
    fatal_codes = {
        "OUTPUT_DIR_NOT_WRITABLE",
        "TEMPLATE_NOT_FOUND",
        "TEMPLATE_INVALID_XLSX",
        "TEMPLATE_PARSE_ERROR",
        "NO_TARGETS_FOUND",
        "LOCAL_SSH_CLIENT_MISSING",
    }
    if any(i.code in fatal_codes for i in preflight_report.issues):
        return EXIT_CONFIG_ERROR
    if preflight_report.valid_targets == 0:
        return EXIT_CONFIG_ERROR

    if "none" in fail_on:
        return EXIT_OK

    if "preflight-error" in fail_on and preflight_report.has_errors:
        return EXIT_CONFIG_ERROR

    for cond in fail_on:
        if cond == "any-failure" and any(not r.ok for r in results):
            return EXIT_TEST_FAILURE
        if cond == "regression" and baseline_summary and baseline_summary.get("regressions", 0) > 0:
            return EXIT_TEST_FAILURE
        if cond == "unconfirmed" and any(r.classification == CLASSIFICATION_UNCONFIRMED for r in results):
            return EXIT_TEST_FAILURE
        if cond == "unreachable" and any(r.classification == CLASSIFICATION_UNREACHABLE for r in results):
            return EXIT_TEST_FAILURE
        if cond == "ssh-error" and any(r.classification == CLASSIFICATION_SSH_ERROR for r in results):
            return EXIT_TEST_FAILURE
        if cond == "execution-error" and any(r.classification == CLASSIFICATION_EXECUTION_ERROR for r in results):
            return EXIT_TEST_FAILURE
        if cond == "flaky" and any(r.flaky for r in results):
            return EXIT_TEST_FAILURE
        if cond == "legacy-ssh":
            if any((o.ssh_audit or {}).get("legacy_fallback_used") for o in (origins or {}).values()):
                return EXIT_TEST_FAILURE
            if any(r.origin and (r.origin.ssh_audit or {}).get("legacy_fallback_used") for r in results):
                return EXIT_TEST_FAILURE

    return EXIT_OK


def _add_common_cli_arguments(subparser):
    subparser.add_argument(
        "--template",
        default=DEFAULT_TEMPLATE,
        help=f"Caminho da planilha .xlsx (padrao: {DEFAULT_TEMPLATE})",
    )
    subparser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Diretorio base para gravar artefatos da execucao (padrao: {DEFAULT_OUTPUT_DIR})",
    )
    subparser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Numero maximo de origens distintas testadas em paralelo (padrao: 1)",
    )
    subparser.add_argument(
        "--timeout",
        type=float,
        default=TIMEOUT_SECONDS,
        help=f"Timeout por operacao de socket/servico em segundos (padrao: {TIMEOUT_SECONDS})",
    )
    subparser.add_argument(
        "--trace-timeout",
        type=float,
        default=TRACE_TIMEOUT_SECONDS,
        help=f"Timeout total por trace em segundos (padrao: {TRACE_TIMEOUT_SECONDS})",
    )
    subparser.add_argument(
        "--baseline",
        default=None,
        help="Caminho para um arquivo results.json (ou pasta de execucao) anterior para comparacao",
    )
    subparser.add_argument(
        "--no-baseline",
        action="store_true",
        help="Desabilita comparacao com baseline mesmo se --baseline for informado",
    )
    subparser.add_argument(
        "--format",
        dest="formats",
        default="json,html,csv,txt",
        help="Formatos de saida separados por virgula: json,html,csv,txt (padrao: json,html,csv,txt)",
    )
    subparser.add_argument(
        "--fail-on",
        default="any-failure",
        help=(
            "Condicoes para codigo de saida != 0 separadas por virgula: "
            "any-failure,preflight-error,regression,unconfirmed,unreachable,"
            "ssh-error,execution-error,legacy-ssh,flaky,none"
        ),
    )
    subparser.add_argument(
        "--retries",
        type=int,
        default=0,
        help="Numero de novas tentativas automaticas para resultados inconclusivos/timeout (padrao: 0)",
    )
    subparser.add_argument(
        "--expand-dns",
        action="store_true",
        help="Expande hostnames com multiplos registros A/AAAA em testes individuais por IP",
    )
    subparser.add_argument(
        "--no-remote-preflight",
        action="store_true",
        help="Desabilita a coleta de preflight remoto somente leitura via SSH",
    )
    subparser.add_argument(
        "--allow-sudo-fallback",
        action="store_true",
        help=(
            "Permite tentar 'sudo -k -S' quando traceroute TCP/ICMP exigir root "
            "(atencao: o SO remoto pode gravar logs no syslog ou arquivo de lecture)"
        ),
    )
    subparser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suprime logs linha a linha no stdout durante a execucao",
    )


class _NetCheckArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def build_cli_parser():
    parser = _NetCheckArgumentParser(
        prog="main.py",
        description="NetCheck-XLS — Validacao automatica de conectividade, traces e evidencias de firewall",
    )
    subparsers = parser.add_subparsers(dest="command")
    run_p = subparsers.add_parser(
        "run",
        help="Executa preflight, testes de conectividade/traces e gera relatorios completos",
    )
    _add_common_cli_arguments(run_p)

    pre_p = subparsers.add_parser(
        "preflight",
        help="Valida planilha, origens, destinos, segredos e ambiente sem executar testes de rede/SSH",
    )
    _add_common_cli_arguments(pre_p)
    return parser


def run_cli(argv=None):
    """Ponto de entrada nao interativo da CLI. Retorna codigo de saida (0, 1, 2 ou 3)."""
    global TIMEOUT_SECONDS, TRACE_TIMEOUT_SECONDS, ALLOW_SUDO_FALLBACK
    old_timeout = TIMEOUT_SECONDS
    old_trace_timeout = TRACE_TIMEOUT_SECONDS
    old_sudo_fallback = ALLOW_SUDO_FALLBACK

    try:
        parser = build_cli_parser()
        args = parser.parse_args(argv)
        if not args.command:
            parser.print_help()
            return EXIT_CONFIG_ERROR

        if args.workers < 1:
            raise ValueError("--workers deve ser >= 1")
        if args.timeout <= 0 or args.trace_timeout <= 0:
            raise ValueError("--timeout e --trace-timeout devem ser > 0")
        if args.retries < 0:
            raise ValueError("--retries deve ser >= 0")

        formats = parse_formats_option(args.formats)
        fail_on = parse_fail_on_option(args.fail_on)
    except ValueError as exc:
        print(f"Erro de configuracao CLI: {sanitize_text(str(exc))}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    TIMEOUT_SECONDS = float(args.timeout)
    TRACE_TIMEOUT_SECONDS = float(args.trace_timeout)
    ALLOW_SUDO_FALLBACK = bool(args.allow_sudo_fallback)
    started_dt = datetime.datetime.now(datetime.timezone.utc)
    run_id = generate_run_id(started_dt)

    try:
        baseline_data = None
        if args.baseline and not args.no_baseline:
            try:
                baseline_data = load_baseline(args.baseline)
            except Exception as exc:
                print(f"Erro ao carregar baseline: {sanitize_text(str(exc))}", file=sys.stderr)
                return EXIT_CONFIG_ERROR

        preflight_report, targets, origins = run_preflight(
            args.template,
            output_dir=args.output_dir,
            expand_dns=args.expand_dns,
        )

        # Se diretorio de saida nao e gravavel, retorna EXIT_CONFIG_ERROR imediatamente:
        if any(i.code == "OUTPUT_DIR_NOT_WRITABLE" for i in preflight_report.issues):
            for issue in preflight_report.issues:
                print(f"[{issue.severity}] {issue.code}: {sanitize_text(issue.message)}", file=sys.stderr)
            return EXIT_CONFIG_ERROR

        results = []
        baseline_summary = None

        if args.command == "run" and preflight_report.valid_targets > 0 and not any(
            i.code == "LOCAL_SSH_CLIENT_MISSING" for i in preflight_report.issues
        ):
            cb = (lambda r: print_result(r)) if not args.quiet else None
            results = execute_plan(
                targets,
                origins,
                workers=args.workers,
                retries=args.retries,
                enable_remote_preflight=not args.no_remote_preflight,
                quiet=args.quiet,
                progress_callback=cb,
            )
            if baseline_data is not None:
                baseline_summary = compare_with_baseline(results, baseline_data)
        elif args.command == "run" and targets:
            # Todos os alvos foram bloqueados pelo preflight: gera resultados bloqueados
            for t in targets:
                orig = origins.get(t.origin_number) if t.origin_number else None
                err_msg = (t.error or (orig.error if orig else "") or "Bloqueado pelo preflight")
                results.append(
                    TestResult(
                        t,
                        orig,
                        False,
                        "FALHA",
                        err_msg,
                        0,
                        summary=err_msg,
                        classification=CLASSIFICATION_EXECUTION_ERROR,
                    )
                )

        finished_dt = datetime.datetime.now(datetime.timezone.utc)
        params = {
            "template": args.template,
            "output_dir": args.output_dir,
            "workers": args.workers,
            "timeout": args.timeout,
            "trace_timeout": args.trace_timeout,
            "baseline": args.baseline if not args.no_baseline else None,
            "no_baseline": bool(args.no_baseline),
            "formats": list(formats),
            "fail_on": list(fail_on),
            "retries": args.retries,
            "expand_dns": bool(args.expand_dns),
            "no_remote_preflight": bool(args.no_remote_preflight),
            "allow_sudo_fallback": bool(args.allow_sudo_fallback),
        }

        run_dir, _, _ = write_run_bundle(
            output_dir=args.output_dir,
            run_id=run_id,
            command_name=args.command,
            template_path=args.template,
            started_dt=started_dt,
            finished_dt=finished_dt,
            parameters=params,
            preflight_report=preflight_report,
            origins=origins,
            results=results,
            baseline_summary=baseline_summary,
            formats=formats,
        )

        if not args.quiet:
            print(
                f"Preflight: {preflight_report.error_count} erro(s), "
                f"{preflight_report.warning_count} aviso(s)."
            )
            if args.command == "run":
                ok_count = sum(1 for r in results if r.ok)
                print(f"Resumo: {ok_count}/{len(results)} OK, {len(results) - ok_count} FALHA.")
            print(f"Artefatos gerados em: {run_dir}")

        return evaluate_exit_code(
            command_name=args.command,
            preflight_report=preflight_report,
            results=results,
            origins=origins,
            baseline_summary=baseline_summary,
            fail_on=fail_on,
        )
    except KeyboardInterrupt:
        close_all_active_ssh_pools()
        print("\nExecucao interrompida pelo usuario.", file=sys.stderr)
        return EXIT_INTERNAL_ERROR
    except Exception as exc:
        close_all_active_ssh_pools()
        print(f"Erro interno de execucao: {sanitize_text(str(exc))}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR
    finally:
        TIMEOUT_SECONDS = old_timeout
        TRACE_TIMEOUT_SECONDS = old_trace_timeout
        ALLOW_SUDO_FALLBACK = old_sudo_fallback


def main(argv=None):
    args_list = sys.argv[1:] if argv is None else list(argv)
    if args_list:
        code = run_cli(args_list)
        if argv is None:
            sys.exit(code)
        return code

    # Modo legado interativo preservado apenas quando chamado sem argumentos em TTY:
    if not sys.stdin.isatty():
        code = run_cli(["run"])
        if argv is None:
            sys.exit(code)
        return code

    path = menu()
    if not path:
        return EXIT_OK
    try:
        loop_reader(path)
        return EXIT_OK
    except KeyboardInterrupt:
        print("\nExecucao interrompida pelo usuario.")
        return EXIT_INTERNAL_ERROR
    except Exception as exc:
        print(f"\nErro: {sanitize_text(str(exc))}")
        return EXIT_INTERNAL_ERROR


if __name__ == "__main__":
    main()
