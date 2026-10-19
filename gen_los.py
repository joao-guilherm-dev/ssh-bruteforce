#!/usr/bin/env python3
"""Gera um auth.log SINTÉTICO (formato syslog do OpenSSH) com tráfego normal + 4 cenários de ataque.
Nenhum ataque real é executado: é uma simulação de logs para treinar detecção."""
import random, datetime as dt, sys
random.seed(42)
out = sys.argv[1] if len(sys.argv) > 1 else "logs/auth.log"
start = dt.datetime(2026, 10, 19, 0, 0, 0)
HOST = "srv-web01"
ev = []  # (datetime, linha)

def line(t, msg, pid=None):
    pid = pid or random.randint(1000, 60000)
    ev.append((t, f"{t:%b %e %H:%M:%S} {HOST} sshd[{pid}]: {msg}"))

def fail(t, u, ip, valid=True):
    p = random.randint(30000, 65000)
    pre = "" if valid else "invalid user "
    line(t, f"Failed password for {pre}{u} from {ip} port {p} ssh2")

def ok(t, u, ip):
    line(t, f"Accepted password for {u} from {ip} port {random.randint(30000,65000)} ssh2")

# 1) Tráfego legítimo
users = ["joao", "deploy", "backup", "maria"]
for _ in range(220):
    t = start + dt.timedelta(seconds=random.randint(0, 86399))
    u, ip = random.choice(users), f"10.0.0.{random.randint(10, 40)}"
    if random.random() < 0.08: fail(t, u, ip)  # erro de digitação
    else: ok(t, u, ip)

# 2) Brute force clássico: 1 IP, 1 usuário, muitas tentativas
t0 = start + dt.timedelta(hours=3, minutes=12)
for i in range(180): fail(t0 + dt.timedelta(seconds=i*1.5), "root", "203.0.113.45")

# 3) Password spraying: 1 IP, muitos usuários, poucas senhas por usuário
t0 = start + dt.timedelta(hours=9, minutes=40)
names = ["admin","test","oracle","postgres","ubuntu","git","ftp","user","guest","pi","jenkins","www","mysql","dev","ansible"]
for i in range(90): fail(t0 + dt.timedelta(seconds=i*4), names[i % len(names)], "198.51.100.77", valid=False)

# 4) Brute force distribuído (botnet): vários IPs, mesmo usuário alvo
t0 = start + dt.timedelta(hours=14, minutes=5)
for i in range(150):
    ip = f"192.0.2.{random.randint(1, 60)}"
    fail(t0 + dt.timedelta(seconds=i*6 + random.randint(0, 3)), "deploy", ip)

# 5) Comprometimento: muitas falhas SEGUIDAS de sucesso (abuso de credencial)
t0 = start + dt.timedelta(hours=20, minutes=30)
for i in range(60): fail(t0 + dt.timedelta(seconds=i*2), "maria", "185.220.101.9")
ok(t0 + dt.timedelta(seconds=125), "maria", "185.220.101.9")
line(t0 + dt.timedelta(seconds=140), "pam_unix(sshd:session): session opened for user maria")

ev.sort(key=lambda x: x[0])
open(out, "w").write("\n".join(l for _, l in ev) + "\n")
print(f"{len(ev)} eventos gravados em {out}")
