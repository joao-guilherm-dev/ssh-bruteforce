set -euo pipefail
sudo apt-get update && sudo apt-get install -y fail2ban
sudo cp fail2ban/filter.d/sshd-lab.conf /etc/fail2ban/filter.d/
sudo cp fail2ban/jail.d/sshd-lab.local /etc/fail2ban/jail.d/
sudo fail2ban-client -t            # valida a configuração
sudo systemctl enable --now fail2ban
sudo systemctl restart fail2ban
sudo fail2ban-client status sshd-lab
