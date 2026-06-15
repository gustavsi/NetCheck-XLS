import csv
import http.client
import os
import re
import shlex
import socket
import struct
import subprocess
import time
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
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
TIMEOUT_SECONDS = 5

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
}

NS = {"a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


@dataclass
class Origin:
    number: str
    host: str
    port: int
    access_protocol: str
    username: str
    password: str


@dataclass
class TestTarget:
    row: int
    origin_number: str
    host: str
    port: int | None
    protocol: str
    description: str


@dataclass
class TestResult:
    target: TestTarget
    origin: Origin | None
    ok: bool
    status: str
    detail: str
    elapsed_ms: int


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
            return input("Digite o diretorio e nome de arquivo manualmente: ").strip()
        clear_terminal()
        print("Opcao invalida, tente novamente.\n")


def normalize_text(value):
    if value is None:
        return ""
    text = str(value).strip()
    if text.endswith(".0"):
        text = text[:-2]
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


def normalize_protocol(protocol, port=None):
    text = normalize_text(protocol).lower()
    text = re.sub(r"[^a-z0-9]+", "", text)
    if text in PROTOCOL_ALIASES:
        return PROTOCOL_ALIASES[text]
    if not text and port:
        return "tcp"
    return text or "icmp"


def default_port_for(protocol):
    return DEFAULT_PORTS.get(protocol)


def column_index(cell_ref):
    letters = re.match(r"([A-Z]+)", cell_ref).group(1)
    index = 0
    for char in letters:
        index = index * 26 + ord(char) - ord("A") + 1
    return index


def read_first_sheet(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Planilha nao encontrada: {path}")

    with zipfile.ZipFile(path) as workbook:
        shared_strings = []
        if "xl/sharedStrings.xml" in workbook.namelist():
            root = ET.fromstring(workbook.read("xl/sharedStrings.xml"))
            for item in root.findall("a:si", NS):
                parts = [
                    text.text or ""
                    for text in item.iter(
                        "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t"
                    )
                ]
                shared_strings.append("".join(parts))

        root = ET.fromstring(workbook.read("xl/worksheets/sheet1.xml"))
        rows = {}
        for row in root.findall(".//a:sheetData/a:row", NS):
            row_number = int(row.attrib["r"])
            values = {}
            for cell in row.findall("a:c", NS):
                ref = cell.attrib["r"]
                value_node = cell.find("a:v", NS)
                inline_node = cell.find("a:is/a:t", NS)
                value = ""
                if value_node is not None:
                    value = value_node.text or ""
                    if cell.attrib.get("t") == "s":
                        value = shared_strings[int(value)]
                elif inline_node is not None:
                    value = inline_node.text or ""
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

    for col_number, value in rows.get(header_row, {}).items():
        if col_number < start_col:
            continue
        normalized = normalize_header(value)
        for key, aliases in normalized_expected.items():
            if normalized in aliases:
                header_map[key] = col_number

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


def load_template(path):
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
        },
    )

    origins = {}
    for _, values in origin_rows:
        number = normalize_text(values["number"])
        host = normalize_text(values["host"])
        if not number or not host:
            continue
        port = parse_port(values["port"], default=22)
        access_protocol = "telnet" if port in (21, 23) else "ssh"
        origins[number] = Origin(
            number,
            host,
            port,
            access_protocol,
            normalize_text(values.get("username")),
            normalize_text(values.get("password")),
        )

    targets = []
    for row_number, values in target_rows:
        host = normalize_text(values["host"])
        if not host:
            continue
        port = parse_port(values["port"])
        protocol = normalize_protocol(values["protocol"], port)
        if port is None:
            port = default_port_for(protocol)
        targets.append(
            TestTarget(
                row=row_number,
                origin_number=normalize_text(values["origin_number"]),
                host=host,
                port=port,
                protocol=protocol,
                description=normalize_text(values["description"]),
            )
        )
    return targets, origins


def test_tcp(host, port, timeout=TIMEOUT_SECONDS):
    if port is None:
        return False, "TCP precisa de uma porta"
    with socket.create_connection((host, port), timeout=timeout):
        return True, f"TCP conectado na porta {port}"


def test_udp(host, port, timeout=TIMEOUT_SECONDS):
    if port is None:
        return False, "UDP precisa de uma porta"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(b"connectivity-test", (host, port))
        try:
            data, _ = sock.recvfrom(1024)
            return True, f"UDP recebeu resposta ({len(data)} bytes)"
        except socket.timeout:
            return True, "UDP enviado; sem resposta, resultado inconclusivo"
        except ConnectionRefusedError:
            return False, "UDP recusado pelo destino"


def test_icmp(host, _port=None, timeout=TIMEOUT_SECONDS):
    if python_ping:
        response = python_ping(host, count=2, timeout=timeout, verbose=False)
        return response.success(), str(response)

    command = ["ping", "-n" if os.name == "nt" else "-c", "2", host]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout + 2,
        check=False,
    )
    detail = completed.stdout.strip() or completed.stderr.strip()
    return completed.returncode == 0, detail.splitlines()[-1] if detail else "sem saida"


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


def quote(value):
    return shlex.quote(str(value))


def remote_test_command(target):
    host = quote(target.host)
    port = target.port
    timeout = int(TIMEOUT_SECONDS)

    if target.protocol == "icmp":
        return f"ping -c 2 -W {timeout} {host}"

    if target.protocol == "tcp":
        if port is None:
            return "echo 'TCP precisa de uma porta' >&2; exit 2"
        return (
            f"nc -z -w {timeout} {host} {port} "
            f"|| timeout {timeout} bash -c 'cat < /dev/null > /dev/tcp/$1/$2' _ {host} {port}"
        )

    if target.protocol == "udp":
        if port is None:
            return "echo 'UDP precisa de uma porta' >&2; exit 2"
        return f"nc -uz -w {timeout} {host} {port}"

    if target.protocol == "http":
        port_part = f":{port}" if port and port != 80 else ""
        url = quote(f"http://{target.host}{port_part}/")
        return (
            f"curl -fsSI --max-time {timeout} {url} "
            f"|| wget --spider --timeout={timeout} {url}"
        )

    if target.protocol == "https":
        port_part = f":{port}" if port and port != 443 else ""
        url = quote(f"https://{target.host}{port_part}/")
        return (
            f"curl -kfsSI --max-time {timeout} {url} "
            f"|| wget --no-check-certificate --spider --timeout={timeout} {url}"
        )

    if target.protocol == "ssh":
        port = port or DEFAULT_PORTS["ssh"]
        return f"nc -z -w {timeout} {host} {port}"

    if target.protocol == "telnet":
        port = port or DEFAULT_PORTS["telnet"]
        return f"nc -z -w {timeout} {host} {port}"

    if target.protocol == "ftp":
        port = port or DEFAULT_PORTS["ftp"]
        return f"nc -z -w {timeout} {host} {port}"

    if target.protocol == "dns":
        port = port or DEFAULT_PORTS["dns"]
        return (
            f"dig @{host} -p {port} google.com A +time={timeout} +tries=1 "
            f"|| nslookup -port={port} google.com {host}"
        )

    if target.protocol == "ntp":
        port = port or DEFAULT_PORTS["ntp"]
        if port != DEFAULT_PORTS["ntp"]:
            return f"nc -uz -w {timeout} {host} {port}"
        return f"ntpdate -q {host} || chronyc -n sources | grep -F {host}"

    if target.protocol == "snmp":
        port = port or DEFAULT_PORTS["snmp"]
        host_port = quote(f"{target.host}:{port}")
        return (
            f"snmpget -v2c -c public {host_port} 1.3.6.1.2.1.1.1.0 "
            f"|| nc -uz -w {timeout} {host} {port}"
        )

    if target.protocol == "tftp":
        port = port or DEFAULT_PORTS["tftp"]
        return f"nc -uz -w {timeout} {host} {port}"

    if port is not None:
        return f"nc -z -w {timeout} {host} {port}"
    return f"ping -c 2 -W {timeout} {host}"


def run_remote_ssh_test(target, origin):
    if paramiko is None:
        return False, "Biblioteca paramiko nao instalada; nao consigo testar a partir da origem"
    if origin.access_protocol != "ssh":
        return False, f"Origem configurada para {origin.access_protocol}; execucao remota implementada por SSH"
    if not origin.username or not origin.password:
        return False, "Origem sem usuario/senha na planilha"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            origin.host,
            port=origin.port,
            username=origin.username,
            password=origin.password,
            timeout=TIMEOUT_SECONDS,
            banner_timeout=TIMEOUT_SECONDS,
            auth_timeout=TIMEOUT_SECONDS,
            look_for_keys=False,
            allow_agent=False,
        )
        command = remote_test_command(target)
        _, stdout, stderr = client.exec_command(command, timeout=TIMEOUT_SECONDS + 3)
        exit_code = stdout.channel.recv_exit_status()
        output = stdout.read().decode(errors="replace").strip()
        error = stderr.read().decode(errors="replace").strip()
        detail = output or error or f"comando remoto finalizou com codigo {exit_code}"
        return exit_code == 0, detail
    finally:
        client.close()


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


def run_test(target, origin=None):
    start = time.monotonic()

    try:
        if origin:
            ok, detail = run_remote_ssh_test(target, origin)
        else:
            tester = TESTERS.get(target.protocol)
            if tester is None:
                tester = test_tcp if target.port else test_icmp
            ok, detail = tester(target.host, target.port, TIMEOUT_SECONDS)
    except Exception as exc:
        ok = False
        detail = f"{type(exc).__name__}: {exc}"

    elapsed_ms = int((time.monotonic() - start) * 1000)
    status = "OK" if ok else "FALHA"
    return TestResult(target, origin, ok, status, detail, elapsed_ms)


def print_result(result):
    target = result.target
    origin_text = result.origin.number if result.origin else target.origin_number or "-"
    port_text = target.port if target.port is not None else "-"
    description = f" - {target.description}" if target.description else ""
    color = "\033[92m" if result.ok else "\033[91m"
    print(
        f"{color}[{result.status}]\033[0m "
        f"linha={target.row} origem={origin_text} "
        f"destino={target.host}:{port_text} protocolo={target.protocol} "
        f"tempo={result.elapsed_ms}ms{description}"
    )
    print(f"    {result.detail}")


def save_results(results, path=RESULTS_FILE):
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(
            [
                "status",
                "linha",
                "origem_numero",
                "origem_host",
                "destino_host",
                "destino_porta",
                "protocolo",
                "descricao",
                "tempo_ms",
                "detalhe",
            ]
        )
        for result in results:
            writer.writerow(
                [
                    result.status,
                    result.target.row,
                    result.origin.number if result.origin else result.target.origin_number,
                    result.origin.host if result.origin else "",
                    result.target.host,
                    result.target.port or "",
                    result.target.protocol,
                    result.target.description,
                    result.elapsed_ms,
                    result.detail,
                ]
            )


def countdown():
    clear_terminal()
    print("Iniciando os testes em...")
    time.sleep(1)
    for value in ["3", "2", "1"]:
        clear_terminal()
        print(f"{value}...\npressione Ctrl + C para encerrar o programa")
        time.sleep(1)
    clear_terminal()


def loop_reader(path):
    targets, origins = load_template(path)
    if not targets:
        print("Nenhum destino encontrado na planilha.")
        return []

    countdown()
    results = []
    print(f"{len(targets)} teste(s) carregado(s).")

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
            )
        else:
            result = run_test(target, origin)
        print_result(result)
        results.append(result)

    save_results(results)
    ok_count = sum(1 for result in results if result.ok)
    print(f"\nResumo: {ok_count}/{len(results)} OK.")
    print(f"Resultado salvo em: {RESULTS_FILE}")
    return results


def main():
    path = menu()
    if not path:
        return
    try:
        loop_reader(path)
    except KeyboardInterrupt:
        print("\nExecucao interrompida pelo usuario.")
    except Exception as exc:
        print(f"\nErro: {exc}")


if __name__ == "__main__":
    main()
