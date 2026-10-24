# NetCheck-XLS

Validador automatizado de conectividade, rotas (`traceroute`, `tracert`, `tracepath`) e regras de firewall a partir de planilhas Excel (`Template_IP.xlsx`), executando testes locais ou remotos via SSH.

## Requisitos (Ubuntu / Debian)

```bash
# Pacotes de sistema (execução local e nas VMs de origem):
sudo apt update && sudo apt install -y \
  python3 python3-pip traceroute iputils-tracepath iputils-ping \
  netcat-openbsd openssh-client sshpass libcap2-bin

# (Opcional) Bibliotecas Python para SSH nativo e cofre de senhas:
pip3 install paramiko keyring

# (Recomendado nas origens) Permitir traceroute TCP/ICMP sem root/sudo:
sudo setcap cap_net_raw+ep "$(readlink -f $(command -v traceroute))"
```

## Uso Rápido (CLI)

```bash
# Execução completa (preflight + testes + pacote de relatórios):
python3 main.py run --template Template_IP.xlsx --output-dir ./netcheck-results

# Apenas validação da planilha e preflight local (sem conexões de rede):
python3 main.py preflight --template Template_IP.xlsx --output-dir ./netcheck-results

# Rodar suíte de testes automatizados:
python3 -B -m unittest -v test_netcheck.py
```

### Principais Flags

| Flag | Padrão | Descrição |
|---|---|---|
| `--template PATH` | `Template_IP.xlsx` | Planilha `.xlsx` de entrada. |
| `--output-dir PATH` | `./netcheck-results` | Diretório base onde é criada a pasta `<run_id>` da execução. |
| `--workers N` | `1` | Origens distintas executadas em paralelo (1 sessão SSH isolada por origem). |
| `--timeout SEG` | `5` | Timeout por conexão/probe (TCP/UDP/ICMP/SSH). |
| `--trace-timeout SEG` | `180` | Timeout máximo por trace completo. |
| `--retries N` | `0` | Retentativas automáticas para falhas transientes ou `TIMEOUT`. |
| `--baseline PATH` | *(nenhum)* | Compara com `results.json` anterior para detectar regressões e mudanças de rota. |
| `--expand-dns` | `False` | Testa todos os IPs (`A`/`AAAA`) resolvidos para um hostname (respeitando a família do `IP Real`). |
| `--fail-on LISTA` | `any-failure` | Condições de falha no exit code (`any-failure`, `preflight-error`, `regression`, `unconfirmed`, `unreachable`, `ssh-error`, `execution-error`, `legacy-ssh`, `flaky`, `none`). |
| `--allow-sudo-fallback` | `False` | Tenta `sudo -k -S` quando `traceroute` exigir `root` *(atenção: pode gerar logs/`lecture` do `sudo` no SO remoto, saindo da garantia estrita de zero escrita)*. |
| `-q`, `--quiet` | `False` | Suprime logs linha a linha no terminal. |

**Exit Codes**: `0` (`EXIT_OK`), `1` (`EXIT_CONNECTIVITY_FAILURE`), `2` (`EXIT_CONFIG_ERROR`), `3` (`EXIT_INTERNAL_ERROR`).

---

## Estrutura da Planilha (`Template_IP.xlsx`)

A primeira aba da planilha é dividida em duas tabelas lado a lado, separadas pela **Coluna G** (vazia). As linhas **2 a 5** (`B2:F5` e `H2:M5`) são reservadas para os blocos visuais de título/instruções e podem ser estilizadas livremente.

### 1. Tabela de Destinos (Colunas `B` a `F`)
* **Linha 6 (`B6:F6`)**: Cabeçalho obrigatório da tabela de destinos.
* **Linha 7 em diante (`B7:F...`)**: Linhas de testes a serem executados.

| Célula do Cabeçalho | Nome Exato da Coluna | Obrigatório | Descrição e Valores Aceitos |
|---|---|---|---|
| **`B6`** | `Origem(Número)` | Não | ID da origem cadastrado em `H8+`. Se deixado **vazio**, o teste roda a partir da máquina local. |
| **`C6`** | `Hostname/IP` | **Sim** | Endereço IP (IPv4/IPv6) ou hostname de destino. |
| **`D6`** | `Portas (Opcional)` | Condicional | Porta(s) de destino: `443`, `443/tcp`, `5060/udp`, `22, 443`. Obrigatória para protocolos `tcp`/`udp`. Em `traceroute`, define o probe (`-T -p` para TCP ou `-U -p` para UDP) e aciona o teste composto pós-trace na porta. |
| **`E6`** | `Protocolos (Opcional)` | Não | `traceroute`, `tracert`, `tracepath`, `traceroute-tcp`, `traceroute-udp`, `traceroute-icmp`, `icmp`, `tcp`, `udp`, `ssh`. (Padrão: `tcp` se houver porta, ou `icmp` se sem porta). |
| **`F6`** | `Descrição (Opcional)` | Não | Contexto operacional da regra/integração (ex.: `"Sinalização SIP SBC"`). |

### 2. Tabela de Origens (Colunas `H` a `M`)
* **Linha 7 (`H7:M7`)**: Cabeçalho obrigatório da tabela de origens.
* **Linha 8 em diante (`H8:M...`)**: Cadastro das VMs remotas que executarão os testes via SSH.

| Célula do Cabeçalho | Nome Exato da Coluna | Obrigatório | Descrição e Valores Aceitos |
|---|---|---|---|
| **`H7`** | `Número origem` | **Sim** | Identificador único da origem (ex.: `1`, `2`, `3`), referenciado na coluna `B` dos destinos. |
| **`I7`** | `Hostname/IP` | **Sim** | IP ou hostname de **gerência/acesso** usado exclusivamente para abrir a conexão SSH. |
| **`J7`** | `IP Real (Opcional)` | Não | IP da interface produtiva (sinalização, bilhetagem, mídia) usado em `traceroute -s <IP Real>` e exibido nos relatórios como origem real da regra de firewall. |
| **`K7`** | `Porta (Opcional)` | Não | Porta SSH de gerência da VM de origem (padrão: `22`). |
| **`L7`** | `Username` | **Sim** | Usuário SSH na VM de origem. |
| **`M7`** | `Password` | Não | Segredo SSH: recomendado `env:NOME_DA_VAR` ou `keyring:servico/conta`, senha literal, ou vazio para usar chave SSH local / `ssh-agent`. |

---

## Regras de Validação e Segurança

* **Validação Hop a Hop + Probe de Serviço**: Nunca confia apenas no exit code do `traceroute`/`tracepath`. Separa `trace_classification` (rota) de `service_result` (porta) e `classification` (resultado global).
* **Semântica Conservadora (TCP Refused e UDP)**:
  * `Status: OK` (`ok=True`) exige rota `REACHED` **e** confirmação do serviço (`TCP_CONNECTED` ou `UDP_RESPONDED`).
  * **UDP sem resposta (`UDP_NO_RESPONSE`)**: Mantém `trace_classification=REACHED` e `policy_verdict=TRACE_REACHED_UDP_NO_RESPONSE`, mas resulta em `ok=False`, `Status=FALHA`, `classification=UNCONFIRMED` e exit code `1`.
  * **Porta recusada (`TRACE_REACHED_TCP_REFUSED` / `UDP_REFUSED`)**: Mantém `trace_classification=REACHED` e `diagnosis_code=DESTINATION_REACHED_SERVICE_REFUSING`, mas resulta em `ok=False`, `Status=FALHA`, `classification=UNCONFIRMED`, `firewall_request_eligible=False` e exit code `1`.
* **Zero Escrita Remota e SSH Seguro**:
  * Sem criação de arquivos nas VMs remotas, sem SFTP/SCP, sem PTY, allowlist estrita de comandos somente leitura e `ALLOW_SUDO_FALLBACK=False` por padrão (falta de privilégio resulta em `EXECUTION_ERROR` / `SOURCE_CAPABILITY_FAILURE`).
  * Verificação estrita de `known_hosts` (`UpdateHostKeys=no`) com fallback restrito para algoritmos SSH legados (`ssh-rsa`/SHA-1) apenas em erro de negociação KEX/hostkey.
  * Suporte completo a **IPv4/IPv6** (`-6` automático e bloqueio de `IP_FAMILY_MISMATCH` no preflight) e sanitização total de segredos em todos os outputs.

---

## Artefatos Gerados (`<output-dir>/<run_id>/`)

1. **`run_manifest.json`**: Metadados da execução, hash SHA-256 da planilha, resumo de preflight e contadores.
2. **`results.json`**: Resultados completos estruturados (hops, `composite`, `diagnosis`, `ssh_audit`, `attempts`, `baseline_comparison`).
3. **`connectivity_results.csv`**: Colunas `status`, `linha`, `origem_numero`, `origem_host`, `origem_ip_real`, `destino_host`, `destino_porta`, `protocolo`, `descricao`, `tempo_ms`, `detalhe`, `classification`, `trace_classification`, `service_result`, `diagnosis_code`, `policy_verdict`, `run_id`.
4. **`dump_traces.txt`**: Evidência bruta dos traces com cabeçalho de origem (`IP Real` vs gerência), diagnóstico e veredito de firewall.
5. **`report.html`**: Relatório visual interativo e autocontido (offline).
