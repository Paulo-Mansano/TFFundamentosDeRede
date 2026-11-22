# Interceptador MITM + Auditoria de Metadados de Tráfego Web

Trabalho Final — Fundamentos de Redes de Computadores (PUCRS, 2026/2)
**Ataque Man-in-the-Middle com ARP Spoofing e auditoria de metadados
(DNS / HTTP / HTTPS-SNI).**

Aplicação escrita em **Python puro**, usando **apenas raw sockets nativos**
(`AF_PACKET`) e `struct` — **sem Scapy, libpcap/pcap, arpspoof, ettercap ou
bettercap**, conforme exigido pelo enunciado. Toda a manipulação binária de
quadros (Ethernet, ARP, IPv4, TCP, UDP, DNS, TLS ClientHello) é feita à mão.

> ⚠️ **Uso ético e legal.** Esta ferramenta roda **exclusivamente** no
> laboratório isolado em contêineres Docker descrito abaixo (Cenário A do
> enunciado). Todo o ARP spoofing acontece dentro de redes virtuais Docker e
> **nunca toca a rede física** da máquina host. Executar ARP spoofing em redes
> da universidade ou de terceiros é **crime** (ver Seção 10 do enunciado).

---

## 1. Estrutura do repositório

```
TF_Redes_MITM/
├── README.md                 ← este arquivo
├── AVALIACAO_DO_GUIA.md      ← revisão técnica do guia do grupo
├── src/
│   ├── interceptor/          ← a aplicação (pacote Python)
│   │   ├── netutil.py        ← interface (MAC/IP/máscara) via ioctl/sysfs
│   │   ├── arp.py            ← ARP: scan, envenenamento, auto-cura
│   │   ├── parser.py         ← Ethernet / IPv4 / TCP / UDP
│   │   ├── dns.py            ← parsing de DNS (QNAME + registros A)
│   │   ├── web.py            ← HTTP + extração de SNI do TLS ClientHello
│   │   ├── audit.py          ← estado, contadores, correlação domínio↔IP
│   │   ├── persist.py        ← captura_*.log e resumo_*.csv
│   │   ├── panel.py          ← painel textual em tempo real
│   │   └── app.py            ← orquestração (threads, sinais, CLI)
│   └── selftest_parsers.py   ← testes de unidade dos parsers (qualquer SO)
├── lab/
│   ├── docker-compose.yml    ← topologia isolada (vítima/gateway/atacante/web)
│   ├── attacker|gateway|victim|webserver/  ← Dockerfiles + entrypoints
│   └── scripts/              ← setup, experimentos e teardown
└── evidencias/               ← logs, CSVs e capturas .pcap gerados
```

## 2. Topologia do laboratório (Cenário A)

```
   lab_net 172.30.0.0/24                 srv_net 172.31.0.0/24
   ─────────────────────                 ─────────────────────
   victim   .10 ──┐                               ┌── webserver .80
   attacker .3  ──┼── gateway .2 ════(roteia)════ .2
                  │   (DNS dnsmasq + IP forward)
```

- A **vítima** usa o **gateway (.2)** como rota default e servidor DNS.
- O **webserver** só é alcançável *através* do gateway → o tráfego
  vítima→web **passa pelo gateway**, exatamente onde o **atacante** se insere
  via ARP spoofing (envenenando vítima↔gateway).
- O webserver serve **HTTP (80)** em claro e **HTTPS (443)** com certificado
  autoassinado e múltiplos `server_name` (exercita o **SNI**).

## 3. Pré-requisitos

- **Docker** + **Docker Compose v2** (testado com Docker 29.x).
  No Windows: Docker Desktop com backend WSL2.
- Nada além disso — o laboratório é autocontido (não depende de internet).

## 4. Como executar (reprodução completa)

Todos os comandos a partir de `lab/scripts/`:

```bash
# 1) Sobe o laboratório e valida o baseline (sem ataque)
bash 00_setup.sh

# 2) Roda os 3 experimentos obrigatórios + captura global (captura_auditoria.pcap)
bash rodar_todos.sh

# ...ou individualmente:
bash exp1_http_vs_https.sh
bash exp2_dns_https_correlacao.sh
bash exp3_ip_forwarding.sh

# 3) Derruba o laboratório
bash 99_teardown.sh
```

As evidências aparecem em `evidencias/` (logs `captura_*.log`, resumos
`resumo_*.csv`, capturas `*.pcap` e snapshot do painel).

### Rodar a aplicação manualmente (demo ao vivo / arguição)

```bash
# Dentro do contêiner atacante, com o painel em tempo real:
docker exec -it lab-attacker sh -c \
  "cd /app/src && python3 -m interceptor --victim 172.30.0.10 --gateway 172.30.0.2 -i eth0"

# Varredura de descoberta apenas:
docker exec -it lab-attacker sh -c "cd /app/src && python3 -m interceptor --scan-only -i eth0"

# Encerrar com Ctrl+C  → dispara a AUTO-CURA (restaura ARP e ip_forward).
```

Gerar tráfego na vítima (outro terminal):
```bash
docker exec lab-victim curl -s      http://site-http.lab/area?user=joao
docker exec lab-victim curl -s -k   https://banco.lab/
```

### Testes de unidade dos parsers (não precisa de Docker)
```bash
cd src && python3 selftest_parsers.py
```

## 5. Opções da aplicação (`python3 -m interceptor --help`)

| Opção | Função |
|-------|--------|
| `-i, --iface` | interface (default: rota default) |
| `--victim IP` / `--gateway IP` | alvos (modo automático, sem menu) |
| `--interval S` | intervalo das rajadas de ARP (default 2 s) |
| `--outdir DIR` | diretório de `captura_*.log` / `resumo_*.csv` |
| `--no-panel` | desativa o painel (útil para log em arquivo) |
| `--scan-only` | só descobre hosts e sai |
| `--non-interactive` | exige `--victim/--gateway` (sem menu) |

Sem `--victim/--gateway`, a aplicação faz a **varredura ARP**, lista os hosts e
pede a **seleção interativa** da vítima e do gateway (requisito 3.1).

## 6. Mapeamento requisito → onde está implementado

| Requisito (enunciado) | Implementação |
|-----------------------|---------------|
| 3.1 Mapeamento/descoberta (ARP scan) | `arp.ArpScanner`, `app.Interceptor.discover` |
| 3.2 Envenenamento bidirecional + IP forward | `arp.arp_poison`, `app.spoof_loop`, `app.set_ip_forward` |
| 3.3 Auto-cura (SIGINT/SIGTERM) | `app._on_signal`, `app.heal`, `arp.arp_announce/arp_restore` |
| 3.4 Captura/decodificação multicamadas | `parser.py` (Eth/IPv4/TCP/UDP), raw `AF_PACKET` |
| 3.5 Monitor DNS (UDP/53) + correlação | `dns.py`, `audit.learn_dns`, `audit.dns_map` |
| 3.6 Inspeção HTTP + SNI do HTTPS | `web.parse_http`, `web.extract_sni` |
| 3.7 Persistência (.log + .csv temporais) | `persist.py` |
| 3.8 Painel em tempo real | `panel.py` |
| Concorrência (threads/fila/lock) | `app.py` (T1–T4), `queue.Queue`, `audit.lock` |

## 7. Observações de implementação relevantes (para a arguição)

- **Filtro de duplicatas:** descartamos quadros `PACKET_OUTGOING` para não
  contar duas vezes o pacote que nós mesmos reencaminhamos.
- **Estabilidade do MITM:** desativamos `send_redirects` (ICMP Redirect
  desfaria o desvio).
- **Auto-cura robusta:** além dos *replies* unicast, enviamos **gratuitous ARP
  *requests*** (anúncios) — o Linux ignora *replies* não solicitados para
  entradas `REACHABLE`.
- **DNS com compressão:** `_read_name` segue ponteiros `0xC0` (necessário nas
  respostas).
- **Correlação:** o "IP de destino" do domínio é o **IP resolvido/servidor
  web**, nunca o servidor DNS.

Detalhes e justificativas completas em `AVALIACAO_DO_GUIA.md` e
`relatorio/RELATORIO.md`.
