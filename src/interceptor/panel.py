"""
panel.py — Interface textual em tempo real (Seção 3.8).

Desenha, a cada ~1 segundo, um painel no terminal com:
  * Status do envenenamento ARP (alvos, IPs e MACs);
  * Contadores globais (pacotes, DNS, HTTP, TLS, bytes);
  * Tabela dos últimos destinos acessados (domínio DNS/SNI + volume).

Lê apenas o snapshot imutável do AuditState, então nunca corrompe o estado
compartilhado. Usa sequências ANSI para limpar a tela (sem libs de TUI).
"""

import time


def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _fmt_mac(mac):
    from .netutil import mac_to_str
    if isinstance(mac, bytes):
        return mac_to_str(mac)
    return str(mac)


def render(state):
    """Monta a string completa do painel a partir do snapshot."""
    snap = state.snapshot()
    c = snap["counters"]
    arp = snap["arp_status"]
    lines = []
    lines.append("\033[2J\033[H")  # limpa tela + cursor no topo
    lines.append("=" * 72)
    lines.append("  INTERCEPTADOR MITM — Auditoria de Metadados (uptime "
                 f"{snap['uptime']:.0f}s)")
    lines.append("=" * 72)

    # --- Status ARP ---
    lines.append("[ARP SPOOFING]")
    if arp:
        lines.append(f"  Interface : {arp.get('iface')}  "
                     f"(meu MAC {_fmt_mac(arp.get('my_mac'))})")
        lines.append(f"  Vitima    : {arp.get('victim_ip')}  "
                     f"MAC {_fmt_mac(arp.get('victim_mac'))}")
        lines.append(f"  Gateway   : {arp.get('gateway_ip')}  "
                     f"MAC {_fmt_mac(arp.get('gateway_mac'))}")
        lines.append(f"  Status    : {arp.get('state', '-')}   "
                     f"ip_forward={arp.get('ip_forward', '?')}")
    else:
        lines.append("  (aguardando seleção de alvos)")

    # --- Contadores ---
    lines.append("")
    lines.append("[CONTADORES]")
    lines.append(f"  Pacotes: {c['packets']:<8} DNS: {c['dns']:<6} "
                 f"HTTP: {c['http']:<6} TLS: {c['tls']:<6} "
                 f"Total: {_human_bytes(c['bytes'])}")

    # --- Destinos ---
    lines.append("")
    lines.append("[ULTIMOS DESTINOS]")
    lines.append(f"  {'DOMINIO':<34}{'IP':<16}{'PROTOCOLOS':<14}{'BYTES':>8}")
    lines.append("  " + "-" * 70)
    dests = snap["destinations"][-12:]
    for d in reversed(dests):
        dom = (d["domain"] or "-")[:33]
        proto = ",".join(d["protocols"])[:13]
        lines.append(f"  {dom:<34}{d['ip']:<16}{proto:<14}"
                     f"{_human_bytes(d['bytes']):>8}")
    if not dests:
        lines.append("  (nenhum destino ainda)")

    lines.append("")
    lines.append("  Ctrl+C para encerrar (dispara auto-cura do ARP)")
    return "\n".join(lines)


def run_panel_loop(state, stop_flag, interval: float = 1.0):
    """Loop de thread: redesenha o painel até parar."""
    while not stop_flag():
        try:
            print(render(state), flush=True)
        except Exception:
            pass
        time.sleep(interval)
