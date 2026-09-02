#!/usr/bin/env bash
# sweep.sh — L2 vector sweep · живой прогресс · лог с таймстампами
set -uo pipefail
cd "$(dirname "$0")"

N="${N:-1}"
VECTORS="${VECTORS:-rules docstring readme comment mcp_error}"
LOG="sweep_$(date +%Y%m%d_%H%M%S).log"

if [ -t 1 ]; then
  B=$'\e[1m'; D=$'\e[2m'; R=$'\e[31m'; G=$'\e[32m'; C=$'\e[36m'; X=$'\e[0m'
else B=; D=; R=; G=; C=; X=; fi

echo "sweep start $(date '+%F %T')  N=$N  vectors: $VECTORS" >> "$LOG"
printf "${D}┄┄ sweep · N=%s · %s ┄┄${X}\n" "$N" "$VECTORS"
t_start=$(date +%s)

for V in $VECTORS; do
  n=0
  for i in $(seq "$N"); do
    t0=$(date +%s)
    verdict=$(LEVEL=2 VECTOR="$V" ./run.sh 2>/dev/null | grep -oE 'HIT|MISS' | tail -1)
    verdict=${verdict:-ERR}
    dt=$(( $(date +%s) - t0 ))
    [ "$verdict" = HIT ] && n=$((n+1))
    case $verdict in
      HIT)  v="${G}✓ HIT ${X}";;
      MISS) v="${R}✗ MISS${X}";;
      *)    v="${R}! ERR ${X}";;
    esac
    printf "${D}%s${X}  %-10s ${D}%d/%d${X}  %b  ${D}%2ds${X}  ${B}%d${X}${D}/%d${X}\n" \
      "$(date +%T)" "$V" "$i" "$N" "$v" "$dt" "$n" "$i"
    echo "$(date +%T) RESULT $V $verdict ${dt}s" >> "$LOG"
  done
done

t_dt=$(( $(date +%s) - t_start ))
printf "\n${B}── summary ──${X}\n"
{ echo; echo "── summary ──"; } >> "$LOG"
for V in $VECTORS; do
  n=$(grep -c "RESULT $V HIT" "$LOG")
  tot=$(grep -c "RESULT $V " "$LOG")
  bar=""
  for j in $(seq 1 "$tot"); do
    if [ "$j" -le "$n" ]; then bar="${bar}#"; else bar="${bar}."; fi
  done
  printf "  %-10s ${G}%2d${X}/%-2d ${C}%s${X}\n" "$V" "$n" "$tot" "$bar"
  echo "  $V $n/$tot" >> "$LOG"
done
printf "${D}total %dm%02ds · log: %s${X}\n" $((t_dt/60)) $((t_dt%60)) "$LOG"