#!/usr/bin/env python3
"""Detector de abuso de credenciais SSH: parseia auth.log, aplica regras, gera alertas (JSON + console) e dashboard HTML."""
import re, sys, json, html, datetime as dt
from collections import defaultdict, Counter

LOG = sys.argv[1] if len(sys.argv) > 1 else "logs/auth.log"
YEAR = 2026
# ---- Limiares (ajuste conforme seu ambiente) ----
WINDOW = dt.timedelta(minutes=5)
T_BRUTE = 20      # falhas de 1 IP na janela
T_SPRAY = 8       # usuários distintos de 1 IP na janela
T_DIST  = 40      # falhas contra 1 usuário vindas de >=10 IPs na janela
T_DIST_IPS = 10
RX = re.compile(r"^(\w{3})\s+(\d+) (\d\d:\d\d:\d\d) \S+ sshd\[\d+\]: "
                r"(Failed|Accepted) password for (invalid user )?(\S+) from (\S+) port")

def parse():
    for l in open(LOG):
        m = RX.match(l)
        if not m: continue
        mon, d, hms, res, inv, user, ip = m.groups()
        t = dt.datetime.strptime(f"{YEAR} {mon} {d} {hms}", "%Y %b %d %H:%M:%S")
        yield t, res == "Accepted", user, ip, bool(inv)

events = sorted(parse())
alerts, seen = [], set()

def alert(sev, rule, key, t, detail, mitre):
    if (rule, key) in seen: return  # deduplica por regra+entidade
    seen.add((rule, key))
    alerts.append(dict(time=t.strftime("%H:%M:%S"), severity=sev, rule=rule, entity=key, detail=detail, mitre=mitre))

by_ip, by_user = defaultdict(list), defaultdict(list)
for t, ok_, u, ip, inv in events:
    if not ok_:
        by_ip[ip].append((t, u)); by_user[u].append((t, ip))

def window(items):  # gera (t_fim, itens_na_janela) com janela deslizante
    j = 0
    for i, it in enumerate(items):
        while it[0] - items[j][0] > WINDOW: j += 1
        yield it[0], items[j:i+1]

for ip, items in by_ip.items():
    for t, w in window(items):
        if len(w) >= T_BRUTE:
            alert("HIGH", "SSH-001 Brute force", ip, t, f"{len(w)} falhas em 5 min", "T1110.001")
        if len({u for _, u in w}) >= T_SPRAY:
            alert("HIGH", "SSH-002 Password spraying", ip, t, f"{len({u for _, u in w})} usuários distintos em 5 min", "T1110.003")
for u, items in by_user.items():
    for t, w in window(items):
        ips = {ip for _, ip in w}
        if len(w) >= T_DIST and len(ips) >= T_DIST_IPS:
            alert("HIGH", "SSH-003 Brute force distribuído", u, t, f"{len(w)} falhas de {len(ips)} IPs", "T1110")
# Sucesso após rajada de falhas = possível credencial comprometida
for t, ok_, u, ip, _ in events:
    if ok_:
        prev = [x for x in by_ip.get(ip, []) if dt.timedelta(0) <= t - x[0] <= WINDOW and x[1] == u]
        if len(prev) >= 10:
            alert("CRITICAL", "SSH-004 Login após brute force", f"{u}@{ip}", t, f"sucesso após {len(prev)} falhas", "T1078")

alerts.sort(key=lambda a: a["time"])
json.dump(alerts, open("output/alerts.json", "w"), indent=2)
for a in alerts: print(f"[{a['severity']:8}] {a['time']} {a['rule']:36} {a['entity']:20} {a['detail']}")

# ---- Dashboard ----
fails = [e for e in events if not e[1]]
hours = Counter(e[0].hour for e in fails)
top_ip = Counter(e[3] for e in fails).most_common(8)
top_user = Counter(e[2] for e in fails).most_common(8)
def bars(pairs, color):
    mx = max([v for _, v in pairs] or [1])
    return "".join(f'<div class="row"><span>{html.escape(str(k))}</span><div class="bar" style="width:{v/mx*100:.0f}%;background:{color}"></div><b>{v}</b></div>' for k, v in pairs)
hour_bars = "".join(f'<div class="col" title="{h:02d}h: {hours.get(h,0)}"><div style="height:{hours.get(h,0)/max(hours.values() or [1])*100:.0f}%"></div><i>{h}</i></div>' for h in range(24))
rows = "".join(f'<tr class="{a["severity"]}"><td>{a["time"]}</td><td>{a["severity"]}</td><td>{html.escape(a["rule"])}</td><td>{html.escape(a["entity"])}</td><td>{a["detail"]}</td><td>{a["mitre"]}</td></tr>' for a in alerts)
doc = f"""<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>SSH Brute Force Dashboard</title>
<style>:root{{color-scheme:light dark;--bg:#fff;--fg:#1a1a1a;--card:#f4f5f7;--bd:#d8dbe0}}
@media(prefers-color-scheme:dark){{:root{{--bg:#12141a;--fg:#e8e8ea;--card:#1c1f27;--bd:#2d313c}}}}
body{{font:14px system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px;max-width:1100px;margin:auto}}
.kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.card{{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px;margin-top:12px}}
.kpi b{{font-size:28px;display:block}}.g2{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
.row{{display:grid;grid-template-columns:120px 1fr 40px;align-items:center;gap:8px;margin:4px 0}}.bar{{height:12px;border-radius:4px}}
.hours{{display:flex;align-items:flex-end;gap:3px;height:120px}}.col{{flex:1;height:100%;display:flex;flex-direction:column;justify-content:flex-end;align-items:center}}.col div{{width:100%;background:#e5484d;border-radius:3px 3px 0 0}}.col i{{font-size:10px}}
table{{width:100%;border-collapse:collapse}}td,th{{padding:6px 8px;border-bottom:1px solid var(--bd);text-align:left}}tr.CRITICAL td{{color:#e5484d;font-weight:600}}tr.HIGH td:nth-child(2){{color:#f59e0b;font-weight:600}}
@media(max-width:700px){{.kpis,.g2{{grid-template-columns:1fr 1fr}}}}</style>
<h1>SSH Brute Force — Dashboard</h1><p>Fonte: {html.escape(LOG)} · {len(events)} eventos</p>
<div class="kpis"><div class="card kpi"><b>{len(fails)}</b>falhas de login</div><div class="card kpi"><b>{len({e[3] for e in fails})}</b>IPs com falhas</div>
<div class="card kpi"><b>{len(alerts)}</b>alertas</div><div class="card kpi"><b>{sum(a['severity']=='CRITICAL' for a in alerts)}</b>críticos</div></div>
<div class="card"><h3>Falhas por hora</h3><div class="hours">{hour_bars}</div></div>
<div class="g2"><div class="card"><h3>Top IPs atacantes</h3>{bars(top_ip,'#e5484d')}</div><div class="card"><h3>Usuários mais visados</h3>{bars(top_user,'#f59e0b')}</div></div>
<div class="card"><h3>Alertas</h3><table><tr><th>Hora</th><th>Sev.</th><th>Regra</th><th>Entidade</th><th>Detalhe</th><th>MITRE</th></tr>{rows}</table></div></html>"""
open("output/dashboard.html", "w").write(doc)
print(f"\nDashboard: output/dashboard.html | Alertas: output/alerts.json")
