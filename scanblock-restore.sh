#!/bin/sh
# Восстанавливает набор и правила из снимка при загрузке, до старта Docker.
# Правила должны совпадать с теми, что ставит scanblock.sh, иначе появятся дубли.
set -u
SET=scanblock
SNAP=/var/lib/scanblock/rules
[ -r "$SNAP" ] || exit 0
ipset restore -exist < "$SNAP"
ensure() { iptables -C INPUT "$@" 2>/dev/null || iptables -I INPUT 1 "$@"; }
OPEN_TCP=""; OPEN_UDP=""
# shellcheck disable=SC1091
[ -r /etc/scanblock.conf ] && . /etc/scanblock.conf
iptables -N SCANBLOCK 2>/dev/null || iptables -F SCANBLOCK
[ -n "$OPEN_TCP" ] && iptables -A SCANBLOCK -p tcp -m multiport --dports "$OPEN_TCP" -j RETURN
[ -n "$OPEN_UDP" ] && iptables -A SCANBLOCK -p udp -m multiport --dports "$OPEN_UDP" -j RETURN
iptables -A SCANBLOCK -j DROP
ensure -m conntrack --ctstate NEW -m set --match-set "$SET" src -j SCANBLOCK
ensure -m conntrack --ctstate NEW -m set --match-set "$SET" src -m limit --limit 30/minute --limit-burst 50 -j LOG --log-prefix "SCANBLOCK " --log-level 6
