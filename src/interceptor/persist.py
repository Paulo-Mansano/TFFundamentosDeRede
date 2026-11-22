"""
persist.py — Persistência contínua dos dados auditados (Seção 3.7).

Gera DOIS arquivos com sufixo temporal YYYYMMDDHHMI:

  1. captura_YYYYMMDDHHMI.log  — um registro por evento/fluxo:
       timestamp | src -> dst | PROTO | metadados | bytes

  2. resumo_YYYYMMDDHHMI.csv   — tabela consolidada de destinos:
       dominio, ip_destino, protocolos, bytes_total

O log é escrito em tempo real (append + flush) a cada evento, via callback
registrado no AuditState. O CSV é reescrito periodicamente (snapshot) pela
thread de persistência. Flush frequente evita perder dados se o programa cair.
"""

import csv
import os
import time
from datetime import datetime


def timestamp_suffix() -> str:
    """Sufixo YYYYMMDDHHMI (ano, mês, dia, hora, minuto)."""
    return datetime.now().strftime("%Y%m%d%H%M")


class Persistence:
    def __init__(self, state, outdir: str = ".", suffix: str = None):
        os.makedirs(outdir, exist_ok=True)
        self.state = state
        self.suffix = suffix or timestamp_suffix()
        self.log_path = os.path.join(outdir, f"captura_{self.suffix}.log")
        self.csv_path = os.path.join(outdir, f"resumo_{self.suffix}.csv")
        self._log_file = open(self.log_path, "a", encoding="utf-8")
        self._write_log_header()
        # Cada novo evento vira uma linha no .log imediatamente.
        state.add_event_sink(self._on_event)

    def _write_log_header(self):
        self._log_file.write(
            f"# Log de captura MITM iniciado em "
            f"{datetime.now().isoformat(timespec='seconds')}\n"
        )
        self._log_file.write(
            "# timestamp | origem -> destino | protocolo | metadados | bytes\n"
        )
        self._log_file.flush()

    # ---------------------------------------------------------------
    def _on_event(self, ev: dict):
        ts = datetime.fromtimestamp(ev["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        proto = ev["type"]
        meta = ""
        if proto == "DNS":
            ips = ",".join(ev.get("ips") or []) or "-"
            meta = f"qname={ev.get('domain')} resolvido={ips}"
        elif proto == "HTTP":
            meta = (f"host={ev.get('domain')} {ev.get('method')} "
                    f"{ev.get('uri')}")
            if ev.get("user_agent"):
                meta += f" UA=\"{ev['user_agent']}\""
            if ev.get("cookie"):
                meta += " cookie=PRESENTE"
        elif proto == "HTTPS":
            meta = f"sni={ev.get('sni') or ev.get('domain')}"
        line = (f"{ts} | {ev.get('src')} -> {ev.get('dst')} | {proto} | "
                f"{meta} | {ev.get('bytes', 0)} bytes\n")
        try:
            self._log_file.write(line)
            self._log_file.flush()
        except Exception:
            pass

    # ---------------------------------------------------------------
    def dump_csv(self):
        """Reescreve o CSV consolidado a partir do snapshot atual."""
        snap = self.state.snapshot()
        tmp = self.csv_path + ".tmp"
        try:
            with open(tmp, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["dominio", "ip_destino", "protocolos",
                            "bytes_total"])
                for d in snap["destinations"]:
                    w.writerow([d["domain"], d["ip"],
                                "|".join(d["protocols"]), d["bytes"]])
            os.replace(tmp, self.csv_path)   # troca atômica
        except Exception:
            pass

    def run_csv_loop(self, stop_flag, interval: float = 2.0):
        """Loop de thread: regrava o CSV periodicamente até parar."""
        while not stop_flag():
            self.dump_csv()
            time.sleep(interval)
        self.dump_csv()  # dump final

    def close(self):
        self.dump_csv()
        try:
            self._log_file.close()
        except Exception:
            pass
