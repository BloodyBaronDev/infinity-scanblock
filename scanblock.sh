#!/bin/bash
# scanblock: блокировка входящих соединений от известных сканеров интернета и подсетей по публичным спискам.
# Скачивает списки, собирает ipset (hash:net), ставит первыми правилами INPUT LOG и DROP для новых соединений.
# Обязательные источники: при сбое набор НЕ трогаем. Дополнительные: при сбое пропускаем с записью в журнал.
set -u

SET=scanblock
LOG=/var/log/scanblock.log
STATE_DIR=/var/lib/scanblock
CONF=${SCANBLOCK_CONF:-/etc/scanblock.conf}
MIN_LINES=500
LOG_LIMIT="30/minute"
LOG_BURST=50
ALLOW=()
EXTRA_SOURCES=()

# Конфиг переопределяет значения выше (ALLOW, MIN_LINES, LOG_LIMIT, LOG_BURST, EXTRA_SOURCES).
# shellcheck disable=SC1090
[ -r "$CONF" ] && . "$CONF"

SOURCES=(
  https://raw.githubusercontent.com/tread-lightly/cyberok_skipa_ips/main/lists/skipa_cidr.txt
  https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_iptables/blacklist-v4.ipset
)
CW=https://raw.githubusercontent.com/Connie-Wild/scanner-ip-list/main
EXTRA=()
for f in shodan censys criminalip internet-census rapid7 shadowserver xpanse netsecscan ipip openportstats recyber umich \
         alphastrike academyforinternetresearch cyberresilience group-ib internet-measurement internettl netscout normshield notice scanopticon; do
  EXTRA+=("$CW/$f.txt")
done
EXTRA+=(https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/censys-scanning/list.json)
EXTRA+=(https://gist.githubusercontent.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8/raw/blacklist.txt)
EXTRA+=("${EXTRA_SOURCES[@]}")

log() { echo "$(date "+%F %T") $*" >> "$LOG"; }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

for url in "${SOURCES[@]}"; do
  if ! curl -fsS --max-time 60 "$url" >> "$TMP/raw"; then
    log "ОШИБКА: не скачался $url — набор не обновляю"; exit 1
  fi
  echo >> "$TMP/raw"
done
ok=0; fail=0
for url in "${EXTRA[@]}"; do
  if curl -fsS --max-time 30 "$url" >> "$TMP/raw" 2>/dev/null; then ok=$((ok+1)); else fail=$((fail+1)); log "пропуск: $url"; fi
  echo >> "$TMP/raw"
done

# Подсети шире /16 отбрасываем — слишком большой риск задеть легитимных пользователей.
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "$TMP/raw" | awk -F/ '$2=="" || $2>=16' | sort -u > "$TMP/nets"
N=$(wc -l < "$TMP/nets")
if [ "$N" -lt "$MIN_LINES" ]; then log "ОШИБКА: всего $N подсетей (< $MIN_LINES) — набор не обновляю"; exit 1; fi

ipset create "$SET" hash:net family inet maxelem 262144 -exist
ipset destroy "$SET-new" 2>/dev/null || true
ipset create "$SET-new" hash:net family inet maxelem 262144
sed "s/^/add $SET-new /" "$TMP/nets" | ipset restore -exist
# ALLOW: записи nomatch исключают адрес или подсеть, даже если они лежат внутри заблокированной сети.
for a in "${ALLOW[@]}"; do
  case $a in */*) ;; *) a="$a/32" ;; esac
  ipset add "$SET-new" "$a" nomatch -exist || log "ОШИБКА: ALLOW $a не добавлен"
done
ipset swap "$SET-new" "$SET"
ipset destroy "$SET-new"

# Снимок набора для восстановления при загрузке (до старта Docker).
mkdir -p "$STATE_DIR"
ipset save "$SET" > "$STATE_DIR/rules.tmp" && mv "$STATE_DIR/rules.tmp" "$STATE_DIR/rules"

# Первые правила INPUT: журналируем (с лимитом) и молча отбрасываем только НОВЫЕ входящие соединения.
DROP_RULE=(-m conntrack --ctstate NEW -m set --match-set "$SET" src -j DROP)
LOG_RULE=(-m conntrack --ctstate NEW -m set --match-set "$SET" src -m limit --limit "$LOG_LIMIT" --limit-burst "$LOG_BURST" -j LOG --log-prefix "SCANBLOCK " --log-level 6)
iptables -C INPUT "${DROP_RULE[@]}" 2>/dev/null || iptables -I INPUT 1 "${DROP_RULE[@]}"
iptables -C INPUT "${LOG_RULE[@]}" 2>/dev/null || iptables -I INPUT 1 "${LOG_RULE[@]}"
log "Обновлено: $N подсетей, ALLOW: ${#ALLOW[@]}, доп. источников: $ok ок, $fail пропущено"
echo "$N $ok/$fail"
