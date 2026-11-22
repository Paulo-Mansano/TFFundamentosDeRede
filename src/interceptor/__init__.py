"""
Pacote `interceptor` — Aplicação MITM (ARP spoofing) + auditoria de metadados
de tráfego web, implementada com raw sockets nativos (AF_PACKET) e struct,
sem bibliotecas de sniffing/ataque prontas.

Módulos:
  netutil  - descoberta de interface (MAC/IP/máscara) via ioctl/sysfs
  arp      - construção/parse de ARP, varredura, envenenamento, auto-cura
  parser   - decodificação Ethernet/IPv4/TCP/UDP
  dns      - parsing de mensagens DNS (QNAME + registros A)
  web      - inspeção HTTP e extração do SNI do TLS ClientHello
  audit    - estado compartilhado, contadores e correlação domínio<->IP
  persist  - geração contínua de captura_*.log e resumo_*.csv
  panel    - painel textual em tempo real
  app      - orquestração (threads, sinais/auto-cura, CLI)
"""
__version__ = "1.0.0"
