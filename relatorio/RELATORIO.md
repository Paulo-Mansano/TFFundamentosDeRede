# Relatório Técnico — Ataque MITM com ARP Spoofing e Auditoria de Metadados

**PUCRS — Fundamentos de Redes de Computadores — 2026/2**
**Grupo G__ — Integrantes: ____________________**
**Data: novembro de 2026**

> Documento-base do relatório. O texto técnico e os resultados já estão
> preenchidos a partir da execução real do laboratório. Restam ao grupo:
> (a) inserir as **capturas de tela do Wireshark** abrindo
> `evidencias/captura_auditoria.pcap` (indicado com 🖼️ onde encaixam); e
> (b) revisar/assinar a autoria. Converter para PDF ao final.

---

## 1. Introdução e objetivos

Este trabalho implementa, do zero e com **raw sockets nativos** (`AF_PACKET`),
um interceptador *Man-in-the-Middle* (MITM) que se posiciona entre uma vítima e
o gateway de uma rede local via **ARP Spoofing**, repassa o tráfego de forma
transparente (**IP forwarding**) e **audita os metadados** que vazam em cada
camada da pilha TCP/IP: consultas **DNS** (UDP/53), requisições **HTTP** (80) e o
**SNI** do **TLS ClientHello** em conexões **HTTPS** (443). Nenhuma biblioteca de
sniffing/ataque pronta é usada (sem Scapy, libpcap, arpspoof, ettercap,
bettercap).

Os objetivos de aprendizagem (enunciado, Seção 1) são cobertos camada a camada:
enlace (ARP/Ethernet), rede (IPv4/TTL/forwarding), transporte (TCP/UDP/portas) e
aplicação/segurança (DNS/HTTP/SNI e o contraste com DoH/DoT/ECH).

## 2. Arquitetura da aplicação

### 2.1 Visão de módulos

A aplicação é um pacote Python (`src/interceptor/`) dividido por
responsabilidade:

| Módulo | Responsabilidade | Camada |
|--------|------------------|--------|
| `netutil` | MAC/IP/máscara da interface via `ioctl`; enumeração da sub-rede | — |
| `arp` | montar/parsear ARP; scan; envenenamento; anúncios de auto-cura | Enlace |
| `parser` | decodificar Ethernet → IPv4 → TCP/UDP (offsets por IHL/Data Offset) | Enlace/Rede/Transporte |
| `dns` | parsear mensagem DNS (QNAME + registros A, com compressão) | Aplicação |
| `web` | parsear HTTP (método/URI/Host/headers) e extrair SNI do ClientHello | Aplicação |
| `audit` | estado, contadores e correlação domínio↔IP (sob `lock`) | — |
| `persist` | gravar `captura_*.log` e `resumo_*.csv` | — |
| `panel` | painel textual em tempo real | — |
| `app` | orquestração: threads, sinais/auto-cura, CLI | — |

### 2.2 Modelo de concorrência

Quatro frentes paralelas comunicando-se por uma **fila thread-safe**
(`queue.Queue`) e um **estado compartilhado protegido por `lock`**:

```
 T1 Captura (raw socket) ──enfileira──▶ Fila ──▶ T2 Processamento ──▶ AuditState
 T3 ARP spoofer (periódico, Event p/ parada limpa)        │
 T4 Painel (1 s)                                           └──▶ Persistência (.log/.csv)
```

- **T1 (captura)** nunca bloqueia: só lê o quadro e enfileira. Descarta os
  quadros `PACKET_OUTGOING` (as cópias reencaminhadas pelo próprio atacante),
  evitando contagem em dobro.
- **T2 (processamento)** decodifica, **filtra o fluxo da vítima** (origem ou
  destino = IP da vítima) e alimenta DNS/HTTP/SNI e a correlação.
- **T3 (spoofer)** reenvia os *ARP replies* forjados a cada `interval` segundos;
  usa `threading.Event` para parar **imediatamente** na auto-cura.
- **T4 (painel)** lê apenas *snapshots* imutáveis do estado (nunca corrompe).

### 2.3 Estruturas de dados principais (`audit.py`)

- `counters`: pacotes, DNS, HTTP, TLS, bytes.
- `dns_map`: `IP_resolvido → domínio` (correlação DNS→conexão).
- `destinations`: agregação por domínio `{domínio, ip, protocolos, bytes}`.
- `recent`: fila curta dos últimos eventos (painel).

## 3. Metodologia do ambiente de testes

Ambiente **Cenário A** (contêineres isolados), 100% reprodutível e sem contato
com a rede física. Quatro nós em duas redes bridge Docker:

- `lab_net` **172.30.0.0/24**: `victim .10`, `attacker .3`, `gateway .2`
- `srv_net` **172.31.0.0/24**: `gateway .2`, `webserver .80`

O **gateway** roda `dnsmasq` (resolve `*.lab → 172.31.0.80`) e faz roteamento
entre as redes; a **vítima** usa o gateway como rota default e DNS; o
**webserver** (nginx) serve HTTP em claro e HTTPS com certificado autoassinado e
`server_name` distintos (`loja.lab`, `banco.lab`, `noticias.lab`, `video.lab`,
`site-http.lab`). Reprodução: `lab/scripts/00_setup.sh` → `rodar_todos.sh`.

**Validação do MITM (caches ARP durante o ataque)** — o MAC do atacante
(`96:b7:66:24:39:be`) aparece no lugar do MAC real tanto na vítima quanto no
gateway:

```
vítima:  172.30.0.2  (gateway) → 96:b7:66:24:39:be   (MAC do ATACANTE)
gateway: 172.30.0.10 (vítima)  → 96:b7:66:24:39:be   (MAC do ATACANTE)
```

🖼️ *Wireshark:* filtrar `arp` e mostrar os *replies* forjados
(`172.30.0.2 is-at 96:b7:...` e `172.30.0.10 is-at 96:b7:...`).

## 4. Resultados dos três experimentos obrigatórios

Captura global de evidência: `evidencias/captura_auditoria.pcap`
(abrir no Wireshark para os prints).

### 4.1 Experimento 1 — Exposição: HTTP vs. HTTPS

**Procedimento.** A vítima acessa a mesma URL em HTTP (porta 80) e em HTTPS
(porta 443), ambos com `User-Agent` e `Cookie`.

**Saída real da aplicação (`evidencias/exp1/captura_*.log`):**
```
172.30.0.10 -> 172.31.0.80 | HTTP  | host=site-http.lab GET /area-cliente?user=joao&senha=123 UA="NavegadorVitima/1.0" cookie=PRESENTE | 217 bytes
172.30.0.10 -> 172.31.0.80 | HTTPS | sni=banco.lab | 583 bytes
```

**Tabela comparativa de exposição (preenchida com os resultados):**

| Dado observável pelo interceptador | HTTP (80) | HTTPS (443) |
|------------------------------------|:---------:|:-----------:|
| Método e URI completo              | **Sim** (`GET /area-cliente?user=joao&senha=123`) | Não |
| Cabeçalhos (User-Agent, Cookie)    | **Sim** (`UA`, `cookie=PRESENTE`) | Não |
| Corpo da mensagem                  | Sim       | Não |
| IP e porta de destino              | Sim (`172.31.0.80:80`) | Sim (`172.31.0.80:443`) |
| Nome do domínio                    | Sim (`Host: site-http.lab`) | Sim (**SNI** `banco.lab`) |

**Explicação teórica.** No HTTP o payload trafega em claro; o interceptador lê
método, URI, cabeçalhos e corpo. No HTTPS, tudo isso ocorre **após** o
*handshake* TLS, já cifrado — por isso o interceptador só enxerga IP/porta
(necessários ao roteamento/demultiplexação) e o **SNI**, que viaja em claro no
`ClientHello` porque o servidor precisa escolher o certificado (virtual hosting)
**antes** de cifrar a sessão.

🖼️ *Wireshark:* (a) requisição HTTP com `Host`/`GET` visíveis; (b) frame
`Client Hello` com extensão `server_name = banco.lab`.

### 4.2 Experimento 2 — Correlação DNS → HTTPS (e efeito do DoH)

**Procedimento.** A vítima acessa 4 sites distintos; depois, um acesso com a
resolução fora da rede (efeito do DoH para o sniffer local).

**Cadeia causal capturada (`evidencias/exp2/captura_*.log`), por site:**
```
172.30.0.10 -> 172.30.0.2 | DNS   | qname=loja.lab resolvido=-            (consulta A)
172.30.0.2  -> 172.30.0.10| DNS   | qname=loja.lab resolvido=172.31.0.80 (resposta A)
172.30.0.10 -> 172.31.0.80| HTTPS | sni=loja.lab                         (ClientHello)
```
O mesmo padrão repete para `banco.lab`, `noticias.lab` e `video.lab`. Ou seja,
reconstruímos: **(1)** consulta DNS (QNAME) → **(2)** resposta DNS (IP resolvido)
→ **(3)** conexão TCP/443 ao IP → **(4)** ClientHello com o **mesmo domínio** no
SNI.

**Resumo consolidado (`evidencias/exp2/resumo_*.csv`):**
```
dominio,ip_destino,protocolos,bytes_total
loja.lab,172.31.0.80,DNS|HTTPS,1604
banco.lab,172.31.0.80,DNS|HTTPS,1022
noticias.lab,172.31.0.80,DNS|HTTPS,1025
video.lab,172.31.0.80,DNS|HTTPS,1418
```

**Efeito do DoH.** No acesso final a resolução **não trafegou em UDP/53** na
rede local (equivalente, para o sniffer, a ter DoH ligado). No log, a linha
HTTPS aparece **sem** a consulta DNS precedente:
```
172.30.0.10 -> 172.31.0.80 | HTTPS | sni=loja.lab   (sem consulta UDP/53 antes)
```
**Conclusão:** DoH esconde *qual* domínio foi consultado no DNS, mas o **SNI
continua expondo o site** em conexões HTTPS convencionais. DoH sozinho não
oculta o destino.

🖼️ *Wireshark:* ordenar por tempo e destacar a sequência DNS→TCP SYN→ClientHello
para um dos domínios.

### 4.3 Experimento 3 — Avaliação do IP forwarding (blackhole/DoS)

**Procedimento.** Com o MITM ativo, alternar o `ip_forward` do atacante.

**Resultado real:**
```
FASE A  ip_forward=1  → navegação OK            (espionagem silenciosa)
FASE B  ip_forward=0  → navegação TRAVOU/timeout (Negação de Serviço / blackhole)
FASE C  ip_forward=1  → navegação RESTABELECIDA
```
Durante a FASE B, o log mostra **consultas da vítima sem resposta** (os pacotes
chegam ao atacante e morrem ali):
```
14:19:22 172.30.0.10 -> 172.30.0.2 | DNS | qname=loja.lab resolvido=- (sem resposta)
14:19:27 172.30.0.10 -> 172.30.0.2 | DNS | qname=loja.lab resolvido=- (retransmissão)
```
**Interpretação.** Sem o encaminhamento, o ataque de **espionagem** degrada
para **negação de serviço** — o atacante vira um *blackhole*. Isso evidencia por
que o IP forwarding é essencial à transparência do MITM.

🖼️ *Wireshark:* na FASE B, pacotes da vítima entrando no atacante sem o
correspondente repasse ao gateway.

## 5. Análise de Segurança e Investigação de Contramedidas

### 5.1 Exposição residual do HTTPS
Mesmo cifrado, o HTTPS não oculta **IP de destino**, **portas** nem o **SNI**,
pois cada um tem papel funcional: o IP é necessário ao **roteamento**; a porta à
**demultiplexação** do serviço (TCP/443); e o SNI à **seleção de certificado**
em *virtual hosting* (um IP hospeda vários domínios). São dados que a própria
infraestrutura de rede precisa ler para funcionar.

### 5.2 Defesas na camada de enlace (contra ARP spoofing)
- **Dynamic ARP Inspection (DAI):** o switch valida cada ARP contra a tabela do
  **DHCP Snooping** (binding IP↔MAC↔porta) e descarta ARPs forjados.
- **DHCP Snooping:** constrói a base confiável de bindings usada pelo DAI.
- **Port Security:** limita/fixa os MACs por porta do switch.
- **Client Isolation (Wi-Fi):** impede a comunicação L2 direta entre clientes,
  bloqueando o envenenamento entre estações.
É por isso que o ataque **não funciona** na rede corporativa da PUCRS (DAI +
Client Isolation), apenas no laboratório isolado.

### 5.3 Privacidade na resolução de nomes
- **DoH (DNS over HTTPS, RFC 8484)** e **DoT (DNS over TLS, RFC 7858)** cifram a
  consulta DNS; **DNSCrypt** é alternativa semelhante. Eles tiram o QNAME da
  rede local, mas **não impedem** identificar o site, porque o **SNI** do
  HTTPS convencional continua em claro (demonstrado no Experimento 2).

### 5.4 Ocultação do SNI
- **ESNI / ECH (Encrypted Client Hello):** cifram o ClientHello (incluindo o
  SNI) usando uma chave pública do servidor publicada via **DNS seguro**.
  Desafios de adoção: dependência de DoH/DoT para obter a chave, suporte de
  servidor/CDN, e **bloqueio por censores/firewalls** que tratam ECH como
  tráfego suspeito. Sites com ECH ativo não expõem o SNI ao interceptador.

### 5.5 Síntese: contramedida por ponto do ataque
| Ponto do ataque | Contramedida |
|-----------------|--------------|
| Envenenamento ARP (enlace) | DAI, DHCP Snooping, Port Security, Client Isolation |
| QNAME em claro (DNS) | DoH, DoT, DNSCrypt |
| SNI em claro (TLS) | ECH/ESNI (+ DNS seguro) |
| Repasse/forwarding | detecção de MITM, TLS obrigatório fim a fim (HSTS) |

## 6. Uso de Inteligência Artificial

*(ver `IA_log.md` para o registro detalhado com prompts e avaliação crítica.)*
Modelos/ferramentas utilizados, como a IA foi empregada em cada etapa
(explicação de RFCs, concorrência/sincronização, estrutura de testes), exemplos
de prompts e a avaliação crítica do grupo, além de dificuldades/alucinações
encontradas e como foram superadas.

## 7. Conclusão

A aplicação cumpre todos os requisitos do enunciado e foi validada ponta a ponta
no laboratório: descoberta ARP, MITM bidirecional transparente, auto-cura
determinística, decodificação multicamadas própria, extração de DNS/HTTP/SNI,
correlação domínio↔IP, persistência e painel em tempo real. Os experimentos
confirmaram, empiricamente, a diferença de exposição HTTP×HTTPS, a cadeia
DNS→SNI (e o limite do DoH) e a degradação para DoS sem IP forwarding.

## Referências

RFC 826 (ARP), RFC 791 (IPv4), RFC 9293 (TCP), RFC 768 (UDP), RFC 1035 (DNS),
RFC 9112 (HTTP/1.1), RFC 8446 (TLS 1.3), RFC 6066 (SNI), RFC 8484 (DoH),
RFC 7858 (DoT) e *draft* TLS ECH (IETF).
