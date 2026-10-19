# Detecção de Brute Force em SSH (lab)

Simulação **sintética** de logs + detecção por regras + dashboard + alertas.

```bash
python3 gen_logs.py logs/auth.log   # gera cenários: brute force, spraying, distribuído, login comprometido
python3 detect.py logs/auth.log     # imprime alertas e gera output/dashboard.html + alerts.json
```

## Regras
| ID | Detecção | MITRE |
|----|----------|-------|
| SSH-001 | ≥20 falhas de 1 IP em 5 min | T1110.001 |
| SSH-002 | ≥8 usuários distintos de 1 IP em 5 min (spraying) | T1110.003 |
| SSH-003 | ≥40 falhas contra 1 usuário vindas de ≥10 IPs (distribuído) | T1110 |
| SSH-004 | Login com sucesso após ≥10 falhas do mesmo IP/usuário | T1078 |

## Próximos passos
- Rodar em um **log real do seu próprio servidor/VM** (`/var/log/auth.log`) e calibrar os limiares.
- Mitigação: `fail2ban`, chave pública no lugar de senha, `PermitRootLogin no`, MFA.
- Evoluir para Wazuh/Elastic (Kibana) ou Grafana + Loki com as mesmas regras.

## Bloqueio automático com fail2ban
Detecção (`detect.py`) e resposta (fail2ban) se complementam: o script analisa e gera alertas/dashboard; o fail2ban bane o IP em tempo real.

```bash
./scripts/test_filter.sh     # valida o filtro no log sintético (497 falhas casadas, 0 servidores tocados)
./scripts/install.sh         # na SUA VM: instala, aplica jail e reinicia
sudo fail2ban-client status sshd-lab
sudo fail2ban-client set sshd-lab banip 203.0.113.45     # simula um ban
sudo fail2ban-client set sshd-lab unbanip 203.0.113.45
```
Jail `sshd-lab`: 5 falhas em 5 min → ban de 1h (progressivo ×2). Jail `recidive`: 3 bans em 1 dia → 1 semana.
**Atenção:** coloque seu IP em `ignoreip` antes de ativar, para não se trancar fora.

## Aviso
Projeto educacional. Use apenas em ambientes que você administra. Os logs são sintéticos (IPs de documentação RFC 5737).
