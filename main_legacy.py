"""NetCheck: execution layer corrected. Run: python main.py."""
import atexit
import collections
import importlib
import os
import queue
import re
import shlex
import shutil
import signal
import socket
import subprocess
import threading
import time
import uuid
from pathlib import Path

import netcheck_base as base

TRACE_MAX_HOPS = 20
TRACE_MAX_CONSECUTIVE_NO_REPLY = 5
TRACE_TIMEOUT_SECONDS = 180
SSH_CONNECT_TIMEOUT = 15
SSH_AUTO_FALLBACK = True
TRACE_PROTOCOLS = ('traceroute', 'tracepath')
_SESSIONS = {}
_NATIVE = set()
_CONNECT_FAILURES = {}
MARKER = '__NETCHECK_TRACE_RESULT__='

# No pipeline consumer closes early. Bash owns the producer's process group,
# keeps the FIFO open while stopping it, and drains data already produced.
TRACE_ENGINE = r'''
export LC_ALL=C
umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/netcheck.XXXXXXXX") || exit 125
fifo="$work/output"
mkfifo "$fifo" || { rm -rf -- "$work"; exit 125; }
pid=''
cleanup() {
    if [ -n "$pid" ]; then
        kill -TERM -- "-$pid" 2>/dev/null || :
        kill -KILL -- "-$pid" 2>/dev/null || :
        wait "$pid" 2>/dev/null || :
    fi
    rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
set -m
if command -v stdbuf >/dev/null 2>&1; then
    stdbuf -oL -eL "$@" >"$fifo" 2>&1 &
else
    "$@" >"$fifo" 2>&1 &
fi
pid=$!
set +m
exec 3<"$fifo"
start=$SECONDS
reason=FINALIZADO_SEM_CONFIRMACAO
last_hop=0
missing=0
reached=0
last_missing=0
destination="$NC_HOST"
while :; do
    remaining=$((NC_SECONDS - (SECONDS - start)))
    if [ "$remaining" -le 0 ]; then reason=TIMEOUT; break; fi
    line=''
    IFS= read -r -t "$remaining" line <&3
    read_status=$?
    if [ -n "$line" ] || [ "$read_status" -eq 0 ]; then
        printf '%s\n' "$line"
        # Obtain exact destination address from the tool's own header.
        if [[ "$line" == traceroute\ to* ]] && [[ "$line" =~ \(([^\)]+)\) ]]; then
            destination="${BASH_REMATCH[1]}"
        fi
        if [[ "$line" =~ ^[[:space:]]*([0-9]+)(\?)?:?[[:space:]] ]]; then
            hop=$((10#${BASH_REMATCH[1]}))
            unanswered=0
            if [[ "$line" == *'no reply'* ]] || [[ "$line" =~ ^[[:space:]]*[0-9]+[[:space:]]+\*[[:space:]]+\*[[:space:]]+\*[[:space:]]*$ ]]; then
                unanswered=1
            fi
            if [ "$hop" -ne "$last_hop" ]; then
                if [ "$unanswered" -eq 1 ]; then missing=$((missing + 1)); else missing=0; fi
                last_hop=$hop
                last_missing=$unanswered
            elif [ "$unanswered" -eq 0 ]; then
                missing=0
                last_missing=0
            elif [ "$last_missing" -eq 0 ]; then
                missing=$((missing + 1))
                last_missing=1
            fi
            # A header is not evidence of reaching the destination.
            if [[ "$line" == *' reached'* ]]; then reached=1; fi
            if [ "$NC_PROTOCOL" = traceroute ] && [[ "$line" != *'!'* ]]; then
                for token in $line; do
                    token=${token#(}; token=${token%)}
                    if [ "$token" = "$destination" ]; then reached=1; fi
                done
            fi
            if [ "$reached" -eq 1 ]; then reason=DESTINO_ALCANCADO; break; fi
            if [ "$missing" -ge "$NC_MISSING" ]; then reason=LIMITE_SEM_RESPOSTA; break; fi
            if [ "$hop" -ge "$NC_HOPS" ]; then reason=LIMITE_HOPS; break; fi
        fi
    fi
    if [ "$read_status" -ne 0 ]; then
        if [ "$read_status" -gt 128 ]; then reason=TIMEOUT; fi
        break
    fi
done
if [ "$reason" != FINALIZADO_SEM_CONFIRMACAO ]; then
    kill -TERM -- "-$pid" 2>/dev/null || :
    sleep 0.1
    kill -KILL -- "-$pid" 2>/dev/null || :
fi
# Keep FIFO open until the writer has stopped; preserve queued output.
while IFS= read -r -t 1 line <&3; do printf '%s\n' "$line"; done
wait "$pid" 2>/dev/null
rc=$?
pid=''
exec 3<&-
if [ "$reason" = FINALIZADO_SEM_CONFIRMACAO ] && [ "$rc" -ne 0 ]; then reason=ERRO_EXECUCAO; fi
printf '\n__NETCHECK_TRACE_RESULT__=%s:%s\n' "$reason" "$rc"
case "$reason" in
    DESTINO_ALCANCADO|LIMITE_SEM_RESPOSTA|LIMITE_HOPS|FINALIZADO_SEM_CONFIRMACAO) exit 0 ;;
    TIMEOUT) exit 124 ;;
    *) exit 1 ;;
esac
'''


def trace_command(target, command_override=None, seconds=None):
    if command_override is None:
        if target.protocol == 'traceroute':
            args = ['traceroute', '-m', str(TRACE_MAX_HOPS), '-w', '5', target.host]
        else:
            # Native max-hop support varies. The supervisor enforces the limit.
            args = ['tracepath', target.host]
    else:
        args = command_override
    env = {
        'NC_HOST': target.host, 'NC_PROTOCOL': target.protocol,
        'NC_SECONDS': str(seconds or TRACE_TIMEOUT_SECONDS),
        'NC_HOPS': str(TRACE_MAX_HOPS),
        'NC_MISSING': str(TRACE_MAX_CONSECUTIVE_NO_REPLY),
    }
    return (' '.join(k + '=' + shlex.quote(v) for k, v in env.items()) +
            ' bash -c ' + shlex.quote(TRACE_ENGINE) + ' netcheck ' +
            ' '.join(shlex.quote(a) for a in args))


def parse_trace(output, code):
    pattern = r'(?m)^' + re.escape(MARKER) + r'([A-Z_]+):(\d+)\r?$'
    found = list(re.finditer(pattern, output))
    if not found:
        return ('TIMEOUT' if code == 124 else 'ERRO_EXECUCAO'), output
    match = found[-1]
    # Remove only our own protocol marker. Do not filter tool diagnostics.
    detail = output[:match.start()] + output[match.end():]
    return match.group(1), detail


def _local(command, seconds):
    proc = subprocess.Popen(['bash', '-c', command], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, start_new_session=True)
    try:
        data, _ = proc.communicate(timeout=seconds + 10)
        return proc.returncode, data.decode('utf-8', errors='replace')
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        data, _ = proc.communicate()
        return 124, data.decode('utf-8', errors='replace') + '\n[AVISO] Limite do cliente atingido.\n'


def _negotiation_error(exc):
    return any(s in str(exc).lower() for s in (
        'incompatible ssh', 'no acceptable', 'no matching', 'negotiation'))


def _new_client(origin):
    p = base.paramiko
    if p is None:
        raise RuntimeError('Paramiko indisponivel')
    client = p.SSHClient()
    try:
        client.load_system_host_keys()
        # TOFU: unknown hosts accepted once and persisted; changed keys rejected.
        known = Path('netcheck_known_hosts')
        known.touch(mode=0o600, exist_ok=True)
        client.load_host_keys(str(known))
        client.set_missing_host_key_policy(p.AutoAddPolicy())
        client.connect(origin.host, port=origin.port, username=origin.username,
                       password=origin.password, timeout=SSH_CONNECT_TIMEOUT,
                       banner_timeout=SSH_CONNECT_TIMEOUT, auth_timeout=SSH_CONNECT_TIMEOUT,
                       allow_agent=False, look_for_keys=False)
        return client
    except Exception:
        client.close()
        raise


def _paramiko_command(client, command, seconds):
    channel = client.get_transport().open_session(timeout=SSH_CONNECT_TIMEOUT)
    data = bytearray()
    try:
        channel.set_combine_stderr(True)
        channel.exec_command(command + ' 2>&1')
        deadline = time.monotonic() + seconds + 10
        while True:
            while channel.recv_ready():
                data.extend(channel.recv(65536))
            if channel.exit_status_ready() and not channel.recv_ready():
                return channel.recv_exit_status(), data.decode('utf-8', errors='replace')
            if time.monotonic() >= deadline:
                return 124, data.decode('utf-8', errors='replace') + '\n[AVISO] Timeout do canal SSH; saida parcial.\n'
            time.sleep(0.02)
    finally:
        channel.close()


def _native_command(origin, command, seconds):
    executable = shutil.which('ssh')
    if not executable:
        raise RuntimeError('OpenSSH nao encontrado no PATH')
    package = 'wexpect' if os.name == 'nt' else 'pexpect'
    try:
        expect = importlib.import_module(package)
    except ImportError as exc:
        raise RuntimeError('Instale: python -m pip install ' + package) from exc
    marker = '__NC_SSH_' + uuid.uuid4().hex + '__'
    wrapped = 'bash -c ' + shlex.quote(command + ' 2>&1')
    wrapped += '; rc=$?; printf "\\n' + marker + ':%s\\n" "$rc"'
    args = ['-T', '-p', str(origin.port), '-o', 'HostKeyAlgorithms=+ssh-rsa',
            '-o', 'PubkeyAcceptedAlgorithms=+ssh-rsa',
            '-o', 'StrictHostKeyChecking=accept-new',
            '-o', 'NumberOfPasswordPrompts=1', '-o', 'ConnectionAttempts=1',
            '-o', 'ConnectTimeout=' + str(SSH_CONNECT_TIMEOUT),
            '-l', origin.username, '--', origin.host, wrapped]
    kwargs = {'args': args, 'echo': False}
    if os.name != 'nt':
        kwargs.update(encoding='utf-8', codec_errors='replace')
    child = expect.spawn(executable, **kwargs)
    child.logfile = None
    chunks = []
    sent = False
    deadline = time.monotonic() + seconds + SSH_CONNECT_TIMEOUT + 15
    def text(value):
        return value.decode('utf-8', errors='replace') if isinstance(value, bytes) else (value or '')
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return 124, ''.join(chunks) + '\n[AVISO] Timeout OpenSSH.\n'
            event = child.expect([r'(?im)(?:password|senha)[^\r\n]*:\s*$',
                                  expect.EOF, expect.TIMEOUT], timeout=remaining)
            chunks.append(text(child.before))
            if event == 0:
                if sent:
                    raise RuntimeError('Autenticacao rejeitada; senha nao reenviada')
                child.sendline(origin.password)
                sent = True
            elif event == 1:
                break
            else:
                return 124, ''.join(chunks) + '\n[AVISO] Timeout OpenSSH.\n'
        output = ''.join(chunks)
        matches = list(re.finditer(re.escape(marker) + r':(\d+)', output))
        if not matches:
            raise RuntimeError('OpenSSH nao confirmou execucao remota:\n' + output)
        m = matches[-1]
        return int(m.group(1)), output[:m.start()] + output[m.end():]
    finally:
        if child.isalive():
            child.terminate(force=True)
        child.close()


def remote_execute(target, origin, command, seconds):
    if origin.access_protocol != 'ssh':
        raise RuntimeError('Origem requer SSH; nao existe downgrade para Telnet')
    if not origin.username or not origin.password:
        raise RuntimeError('Origem sem usuario/senha')
    key = (origin.host, origin.port, origin.username)
    if key in _CONNECT_FAILURES:
        raise RuntimeError('Conexao indisponivel nesta execucao: ' + _CONNECT_FAILURES[key])
    if key in _NATIVE:
        code, output = _native_command(origin, command, seconds)
        return code, output, 'OpenSSH: compatibilidade RSA legada'
    client = _SESSIONS.get(key)
    if client is not None:
        transport = client.get_transport()
        if transport is None or not transport.is_active():
            client.close()
            _SESSIONS.pop(key, None)
            client = None
    if client is None:
        try:
            client = _new_client(origin)
            _SESSIONS[key] = client
        except Exception as exc:
            p = base.paramiko
            if p is not None and isinstance(exc, (p.AuthenticationException, p.BadHostKeyException)):
                raise
            eligible = isinstance(exc, (OSError, RuntimeError)) or (
                p is not None and isinstance(exc, p.SSHException) and _negotiation_error(exc))
            if not SSH_AUTO_FALLBACK or not eligible:
                raise
            try:
                code, output = _native_command(origin, command, seconds)
            except Exception as native_error:
                _CONNECT_FAILURES[key] = str(native_error).replace(origin.password, '[CREDENCIAL OMITIDA]')
                raise
            _NATIVE.add(key)
            return code, output, 'OpenSSH: compatibilidade RSA legada'
    # Never retry a command after dispatch: avoid duplicate tests on uncertainty.
    code, output = _paramiko_command(client, command, seconds)
    return code, output, 'Paramiko'


def close_sessions():
    for client in _SESSIONS.values():
        client.close()
    _SESSIONS.clear()


atexit.register(close_sessions)
_ORIGINAL_COMMAND = base.remote_test_command
_ORIGINAL_RUN = base.run_test


def _remote_regular(target, origin):
    code, detail, backend = remote_execute(target, origin, _ORIGINAL_COMMAND(target), 40)
    detail = detail.replace(origin.password, '[CREDENCIAL OMITIDA]')
    return code == 0, '[SSH] ' + backend + '\n' + detail


def _windows_trace(target):
    if target.protocol == 'tracepath':
        return 'ERRO_EXECUCAO', 'tracepath nao esta disponivel nativamente no Windows.\n'
    # Read incrementally so early-stop works on Windows as well.
    args = ['tracert', '-h', str(TRACE_MAX_HOPS), '-w', '5000', target.host]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    lines = queue.Queue()
    def reader():
        for line in iter(proc.stdout.readline, b''):
            lines.put(line)
        lines.put(None)
    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    chunks = []
    reason = 'FINALIZADO_SEM_CONFIRMACAO'
    missing = 0
    deadline = time.monotonic() + TRACE_TIMEOUT_SECONDS
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = 'TIMEOUT'; break
            try:
                line = lines.get(timeout=remaining)
            except queue.Empty:
                reason = 'TIMEOUT'; break
            if line is None:
                break
            value = line.decode(errors='replace')
            chunks.append(value)
            hop = re.match(r'^\s*(\d+)\s+', value)
            if not hop:
                continue
            missing = missing + 1 if re.match(r'^\s*\d+\s+\*\s+\*\s+\*', value) else 0
            addresses = re.findall(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])', value)
            if target.host in addresses:
                reason = 'DESTINO_ALCANCADO'; break
            if missing >= TRACE_MAX_CONSECUTIVE_NO_REPLY:
                reason = 'LIMITE_SEM_RESPOSTA'; break
            if int(hop.group(1)) >= TRACE_MAX_HOPS:
                reason = 'LIMITE_HOPS'; break
    finally:
        if proc.poll() is None:
            subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        proc.wait()
        thread.join(timeout=2)
        while not lines.empty():
            extra = lines.get_nowait()
            if extra is not None:
                chunks.append(extra.decode(errors='replace'))
    if reason == 'FINALIZADO_SEM_CONFIRMACAO' and proc.returncode != 0:
        reason = 'ERRO_EXECUCAO'
    return reason, ''.join(chunks)


def run_test(target, origin=None):
    if target.protocol not in TRACE_PROTOCOLS:
        return _ORIGINAL_RUN(target, origin)
    start = time.monotonic()
    backend = 'local'
    try:
        if origin:
            code, output, backend = remote_execute(target, origin, trace_command(target), TRACE_TIMEOUT_SECONDS)
            status, detail = parse_trace(output, code)
        elif os.name == 'nt':
            status, detail = _windows_trace(target)
        else:
            code, output = _local(trace_command(target), TRACE_TIMEOUT_SECONDS)
            status, detail = parse_trace(output, code)
    except Exception as exc:
        status, detail = 'ERRO_EXECUCAO', type(exc).__name__ + ': ' + str(exc) + '\n'
    if origin and origin.password:
        detail = detail.replace(origin.password, '[CREDENCIAL OMITIDA]')
    detail += '\n[NetCheck] Resultado: ' + status + '; executor: ' + backend + '\n'
    return base.TestResult(target, origin, status == 'DESTINO_ALCANCADO', status, detail,
                           int((time.monotonic() - start) * 1000))


def print_result(result):
    if result.target.protocol not in TRACE_PROTOCOLS:
        return base.print_result(result)
    target = result.target
    color = "\033[92m" if result.ok else (
        "\033[91m" if result.status in ("ERRO_EXECUCAO", "TIMEOUT") else "\033[93m"
    )
    print(f"{color}[{result.status}]\033[0m destino={target.host} "
          f"protocolo={target.protocol} tempo={result.elapsed_ms}ms - {target.description}")
    print(result.detail)


def loop_reader(path):
    targets, origins = base.load_template(path)
    if not targets:
        print('Nenhum destino encontrado.'); return []
    print(str(len(targets)) + ' teste(s) carregado(s).')
    results = []
    trace_started = False
    regular_started = False
    try:
        for target in targets:
            origin = origins.get(target.origin_number)
            if target.origin_number and origin is None:
                result = base.TestResult(target, None, False, 'ERRO_EXECUCAO',
                                         'Origem nao encontrada na tabela de origens', 0)
            else:
                result = run_test(target, origin)
            results.append(result)
            print_result(result)
            if target.protocol in TRACE_PROTOCOLS:
                mode = 'a' if trace_started else 'w'
                with open(base.TRACE_DUMP_FILE, mode, encoding='utf-8', newline='') as file:
                    file.write('=' * 80 + '\n')
                    file.write('Status: ' + result.status + '\n')
                    file.write('Origem host: ' + (origin.host if origin else 'local') + '\n')
                    file.write('Destino: ' + target.host + '\nProtocolo: ' + target.protocol + '\n')
                    file.write('Descricao: ' + target.description + '\n')
                    file.write('Tempo total: ' + str(result.elapsed_ms) + ' ms\n' + '-' * 80 + '\n')
                    file.write(result.detail)
                    if not result.detail.endswith('\n'): file.write('\n')
                    file.flush()
                trace_started = True
            else:
                # Existing CSV schema; rewrite only current-run ordinary results.
                base.save_results([r for r in results if r.target.protocol not in TRACE_PROTOCOLS])
                regular_started = True
    finally:
        close_sessions()
        counts = collections.Counter(r.status for r in results)
        print('\nResumo: ' + ', '.join(k + '=' + str(v) for k, v in counts.items()))
        if trace_started: print('Traces: ' + base.TRACE_DUMP_FILE)
        if regular_started: print('Testes comuns: ' + base.RESULTS_FILE)
        print('Arquivos de execucoes anteriores sem resultados novos nao foram excluidos.')
    return results


base.run_remote_ssh_test = _remote_regular
base.loop_reader = loop_reader

if __name__ == '__main__':
    base.main()
