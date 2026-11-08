#!/bin/sh
# Восстанавливает набор и правила из снимка при загрузке, до старта Docker.
# Правила должны совпадать с теми, что ставит scanblock.sh, иначе появятся дубли.
set -eu
SET=scanblock
SNAP=/var/lib/scanblock/rules
[ -r "$SNAP" ] || exit 0
ipset restore -exist < "$SNAP"
ensure() { iptables -C INPUT "$@" 2>/dev/null || iptables -I INPUT 1 "$@"; }
ensure -m conntrack --ctstate NEW -m set --match-set "$SET" src -j DROP
ensure -m conntrack --ctstate NEW -m set --match-set "$SET" src -m limit --limit 30/minute --limit-burst 50 -j LOG --log-prefix "SCANBLOCK " --log-level 6
