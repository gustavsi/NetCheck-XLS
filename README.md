# NetCheck-XLS

Validador de conectividade baseado em uma planilha Excel. O script le o arquivo
`Template_IP.xlsx`, monta uma lista de destinos e executa testes de rede como
ICMP, TCP, UDP, HTTP, HTTPS, SSH, Telnet, FTP, DNS, NTP, SNMP e TFTP.

## Como funciona

O arquivo Excel possui duas areas principais:

### Destinos

Tabela com os testes que devem ser executados:

| Coluna | Campo | Descricao |
| --- | --- | --- |
| B | Origem(Número) | Numero da origem que deve executar o teste. Se ficar vazio, o teste roda localmente. |
| C | Hostname/IP | Destino que sera testado. |
| D | Portas (Opcional) | Porta de destino. Se vazia, o script usa a porta padrao do protocolo. |
| E | Protocolos (Opcional) | Protocolo do teste. Se protocolo e porta ficarem vazios, o teste sera ICMP. |
| F | Descrição (Opcional) | Texto livre para identificar o teste. |

### Origens

Tabela com os hosts de origem usados para testes remotos:

| Coluna | Campo | Descricao |
| --- | --- | --- |
| H | Número origem | Identificador usado na coluna `Origem(Número)`. |
| I | Hostname/IP | IP ou hostname da maquina de origem. |
| J | Porta (Opcional) | Porta SSH da origem. Padrao: `22`. |
| K | Usuario | Usuario SSH. |
| L | Senha | Senha SSH. |

Quando um destino possui `Origem(Número)`, o script acessa essa origem via SSH e
executa o teste a partir dela. Quando a origem esta vazia, o teste e executado na
maquina local.

## Portas padrao

Quando o protocolo e informado mas a porta fica vazia, o script usa:

| Protocolo | Porta |
| --- | ---: |
| FTP | 21 |
| SSH | 22 |
| Telnet | 23 |
| SMTP | 25 |
| DNS | 53 |
| HTTP | 80 |
| POP3 | 110 |
| NTP | 123 |
| IMAP | 143 |
| SNMP | 161 |
| HTTPS | 443 |
| SMB | 445 |
| LDAPS | 636 |
| TFTP | 69 |
| RDP | 3389 |

## Requisitos

Python 3.10 ou superior.

Dependencia obrigatoria para executar testes a partir de outra origem:

```bash
python -m pip install paramiko
```

Dependencias opcionais para testes mais especificos:

```bash
python -m pip install dnspython ntplib tftpy pysnmp pythonping
```

Sem essas bibliotecas opcionais, o script tenta usar recursos basicos do sistema
quando possivel.

Nos hosts de origem, instale as ferramentas usadas pelos comandos remotos:

```bash
sudo apt install iputils-ping netcat-openbsd curl wget dnsutils ntpdate snmp
```

## Uso

Execute:

```bash
python main.py
```

No menu, escolha:

```text
[1] Iniciar o script
[0] Fechar o programa
```

Depois selecione se deseja usar `Template_IP.xlsx` no diretorio atual ou informar
outro caminho manualmente.

## Resultado

Ao final, o script salva um CSV com os resultados:

```text
connectivity_results.csv
```

O arquivo contem status, linha da planilha, origem, destino, porta, protocolo,
tempo de execucao e detalhe do teste.

## Observacao de seguranca

Evite compartilhar o template contendo usuario e senha de origens. Se possivel, use credenciais
temporarias, variaveis de ambiente ou outro mecanismo seguro para producao.
