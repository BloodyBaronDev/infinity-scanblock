#!/bin/bash
# Полное удаление scanblock. Запуск от root.
[ "$(id -u)" -eq 0 ] || { echo "нужен root" >&2; exit 1; }
systemctl disable --now scanblock.timer scanblock-restore.service 2>/dev/null
rm -f /etc/systemd/system/scanblock.service /etc/systemd/system/scanblock.timer /etc/systemd/system/scanblock-restore.service
systemctl daemon-reload
while iptables -D INPUT -m conntrack --ctstate NEW -m set --match-set scanblock src -m limit --limit 30/minute --limit-burst 50 -j LOG --log-prefix "SCANBLOCK " --log-level 6 2>/dev/null; do :; done
while iptables -D INPUT -m conntrack --ctstate NEW -m set --match-set scanblock src -j DROP 2>/dev/null; do :; done
ipset destroy scanblock 2>/dev/null
rm -f /usr/local/sbin/scanblock /usr/local/sbin/scanblock-restore
rm -rf /var/lib/scanblock
echo "Удалено. Конфиг /etc/scanblock.conf и журнал /var/log/scanblock.log оставлены."
