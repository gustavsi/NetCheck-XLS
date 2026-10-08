# NetCheck-XLS

Ferramenta em Python para validar conectividade a partir de uma planilha Excel. Os testes podem ser executados localmente ou em hosts remotos via SSH.

## Funcionalidades

- Leitura de destinos e origens a partir de uma planilha `.xlsx`.
- Execução local ou remota via SSH.
- Testes ICMP, TCP, UDP, HTTP, HTTPS, DNS, NTP, SNMP, TFTP, FTP, SSH, Telnet, SMTP, POP3, IMAP, SMB, LDAPS e RDP.
- Rastreamento de rota com `traceroute`, `tracert` e `tracepath`.
- Resultados comuns em CSV e traces completos em arquivo de texto separado.

## Formato da planilha

O script utiliza duas tabelas: **Destinos** e **Origens**.

### Destinos

| Campo | Descrição |
|---|---|
| `Origem(Número)` | Identificador da origem remota. Se ficar vazio, o teste será local. |
| `Hostname/IP` | Endereço IP ou hostname de destino. |
| `Portas (Opcional)` | Porta do serviço. Pode ficar vazia quando houver uma porta padrão. |
| `Protocolos (Opcional)` | Protocolo do teste. Se protocolo e porta ficarem vazios, será usado ICMP. |
| `Descrição (Opcional)` | Identificação livre do teste. |

Exemplo:

| Origem(Número) | Hostname/IP | Portas (Opcional) | Protocolos (Opcional) | Descrição (Opcional) |
|---|---|---|---|---|
| 1 | `10.1.1.2` | 443 | `https` | Aplicação principal |
| 1 | `10.1.1.2` |  | `traceroute` | Rota até a aplicação |
| 1 | `10.1.1.3` |  | `tracepath` | Caminho e MTU |

`traceroute` e `tracepath` não precisam de porta.

### Origens

| Campo | Descrição |
|---|---|
| `Número origem` | Identificador usado em `Origem(Número)`. |
| `Hostname/IP` | IP ou hostname da origem remota. |
| `Porta (Opcional)` | Porta SSH. O padrão é `22`. |
| `Usuario` | Usuário SSH. |
| `Senha` | Senha SSH. |

Quando uma origem é informada, o script acessa o host por SSH e executa o teste a partir dele.

## Protocolos de trace

Na coluna `Protocolos (Opcional)`, use:

- `traceroute`
- `tracert`, tratado como alias de `traceroute`
- `tracepath`

Os traces seguem estas regras:

- Máximo de **20 hops** por teste.
- Encerramento antecipado após **5 hops consecutivos sem resposta**.
- Uma resposta válida reinicia a contagem de hops sem resposta.
- Timeout de segurança de **180 segundos por teste**.
- A saída obtida é preservada mesmo quando o timeout é atingido.

No Linux, o script utiliza `traceroute` ou `tracepath`. No Windows, `traceroute` utiliza o comando nativo `tracert`; `tracepath` não está disponível nativamente.

## Portas padrão

Quando a porta fica vazia, o script utiliza a porta padrão do protocolo, quando aplicável:

| Protocolo | Porta |
|---|---:|
| FTP | 21 |
| SSH | 22 |
| Telnet | 23 |
| SMTP | 25 |
| DNS | 53 |
| TFTP | 69 |
| HTTP | 80 |
| POP3 | 110 |
| NTP | 123 |
| IMAP | 143 |
| SNMP | 161 |
| HTTPS | 443 |
| SMB | 445 |
| LDAPS | 636 |
| RDP | 3389 |

## Requisitos

- Python 3.10 ou superior.
- Planilha `.xlsx` no formato esperado.
- Acesso de rede aos destinos.
- Acesso SSH às origens remotas, quando utilizadas.

Instale o Paramiko para execução remota:

```bash
python -m pip install paramiko
```

Dependências opcionais:

```bash
python -m pip install dnspython ntplib tftpy pysnmp pythonping
```

Em Debian ou Ubuntu, instale as ferramentas de sistema:

```bash
sudo apt update
sudo apt install iputils-ping iputils-tracepath traceroute netcat-openbsd curl wget dnsutils ntpdate snmp
```

Os hosts Linux usados para traces também precisam de `bash`, `awk` e `timeout`, normalmente incluído no pacote `coreutils`.

## Uso

Execute:

```bash
python main.py
```

No menu, escolha iniciar o script e informe se deseja usar `Template_IP.xlsx` no diretório atual ou selecionar outro arquivo.

## Arquivos de resultado

### `connectivity_results.csv`

Contém os resultados dos testes comuns, incluindo status, origem, destino, porta, protocolo, tempo de execução e detalhes.

Resultados de `traceroute`, `tracert` e `tracepath` não são gravados nesse arquivo.

### `dump_traces.txt`

Contém a saída completa dos traces, separada em blocos identificados por origem, destino, protocolo, descrição, status e tempo total.

Exemplo resumido:

```text
================================================================================
TRACE 1
Status: OK
Origem host: 10.1.1.1
Destino: 10.1.1.2
Protocolo: traceroute
Descricao: Rota até a aplicação
Tempo total: 15234 ms
--------------------------------------------------------------------------------
traceroute to 10.1.1.2 (10.1.1.2), 20 hops max, 60 byte packets
 1  10.2.3.4  13.054 ms  14.026 ms  12.884 ms
 2  * * *
 3  10.4.3.2  7.357 ms  4.538 ms  4.638 ms
================================================================================
```
