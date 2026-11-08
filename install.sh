#!/bin/bash
# Установка scanblock. Запуск от root из каталога проекта.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "нужен root" >&2; exit 1; }
for c in curl ipset iptables systemctl; do
  command -v "$c" >/dev/null || { echo "нет команды: $c" >&2; exit 1; }
done
D=$(cd "$(dirname "$0")" && pwd)
install -m 755 "$D/scanblock.sh" /usr/local/sbin/scanblock
install -m 755 "$D/scanblock-restore.sh" /usr/local/sbin/scanblock-restore
install -m 644 "$D"/systemd/scanblock.service "$D"/systemd/scanblock.timer "$D"/systemd/scanblock-restore.service /etc/systemd/system/
[ -e /etc/scanblock.conf ] || install -m 644 "$D/examples/scanblock.conf" /etc/scanblock.conf
systemctl daemon-reload
systemctl enable scanblock-restore.service
systemctl enable --now scanblock.timer
echo "Установлено. ОБЯЗАТЕЛЬНО впишите свой SSH-адрес в ALLOW: /etc/scanblock.conf"
echo "Затем: systemctl start scanblock.service && tail /var/log/scanblock.log"
