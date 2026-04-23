#!/bin/bash
#
# btrace MySQL e2e showcase + overhead benchmark.
#
# - Uses host MySQL 8.0 (must be running).
# - Prepares a sysbench OLTP dataset.
# - Runs OLTP read-write workload twice: baseline, then with btrace attached.
# - Reports TPS for both runs and btrace overhead %.
# - Generates text + DOT + SVG + HTML report in ./out/mysql/.
#
# Requires: mysql-server 8.0 running on host, sysbench, sudo, btrace built at ./btrace.
#           For symbol resolution: mysql-server-core-8.0-dbgsym package installed.
#

set -uo pipefail

PORT=3306
TABLES=4
TABLE_SIZE=10000
THREADS=4
TIME=10
OUT="./out/mysql"
BTRACE="./btrace"
MYSQL_USER="root"
MYSQL_DB="sb"

mkdir -p "$OUT"

SB_COMMON=(
    /usr/share/sysbench/oltp_read_write.lua
    --mysql-host=127.0.0.1 --mysql-port="$PORT"
    --mysql-user="$MYSQL_USER" --mysql-password=root --mysql-db="$MYSQL_DB"
    --tables="$TABLES" --table-size="$TABLE_SIZE"
    --threads="$THREADS" --time="$TIME" --report-interval=0
)

get_mysqld_pid() {
    pidof mysqld 2>/dev/null
}

bench() {
    local label="$1"
    sysbench "${SB_COMMON[@]}" run 2>&1 \
        | awk -v l="$label" '
            /transactions:/ {
                v = $3
                gsub(/[()]/, "", v)
                printf "%s tps=%s\n", l, v
            }'
}

main() {
    if ! command -v sysbench >/dev/null; then
        echo "sysbench not found; sudo apt install sysbench" >&2
        exit 1
    fi

    local pid
    pid=$(get_mysqld_pid)
    if [ -z "$pid" ]; then
        echo "mysqld not running; start it with: sudo systemctl start mysql" >&2
        exit 1
    fi

    echo "========================================="
    echo " btrace MySQL e2e + overhead benchmark"
    echo "========================================="
    echo " mysqld pid: $pid"
    echo " sysbench: $TABLES tables x $TABLE_SIZE rows, $THREADS threads, ${TIME}s"
    echo ""

    # ---- Phase 0: prepare dataset ----
    mysql -h127.0.0.1 -P"$PORT" -u"$MYSQL_USER" -proot \
        -e "CREATE DATABASE IF NOT EXISTS $MYSQL_DB;" 2>/dev/null || true

    echo "[sysbench] preparing dataset ..."
    sysbench "${SB_COMMON[@]}" prepare 2>&1 | tail -3

    # ---- Phase 1: baseline (no btrace) ----
    echo ""
    echo "[bench] === baseline (no btrace) ==="
    local base
    base=$(bench baseline | tee "$OUT/baseline.txt" | awk -F= '{print $2}')

    # ---- Phase 2: with btrace profiling ----
    echo ""
    echo "[bench] === with btrace attached ==="
    local btfile="$OUT/btrace.btrace"
    sudo "$BTRACE" record -p "$pid" -o "$btfile" >"$OUT/record.log" 2>&1 &
    local btpid=$!
    sleep 1

    local traced
    traced=$(bench traced | tee "$OUT/traced.txt" | awk -F= '{print $2}')

    sudo kill -INT $btpid 2>/dev/null || true
    wait $btpid 2>/dev/null || true

    # ---- Phase 3: generate report ----
    echo ""
    echo "[report] generating text + DOT report ..."
    sudo chown "$USER:$USER" "$btfile" 2>/dev/null || true
    "$BTRACE" report -i "$btfile" -o "$OUT" --dot \
        > "$OUT/btrace.txt" 2>"$OUT/btrace.log"

    if [ -f "$OUT/btrace.dot" ]; then
        echo "[report] generating SVG + HTML ..."
        dot -Tsvg "$OUT/btrace.dot" > "$OUT/btrace.svg" 2>/dev/null || true
        python3 scripts/btrace2html.py "$OUT/btrace.dot" -o "$OUT/btrace.html" 2>/dev/null || true
    fi

    # ---- Phase 4: verify symbol resolution ----
    echo ""
    echo "[verify] checking symbol resolution in report ..."
    if grep -q 'mysqld:[a-zA-Z]' "$OUT/btrace_stacks.json" 2>/dev/null; then
        local nsyms
        nsyms=$(grep -oP 'mysqld:\K[a-zA-Z_][a-zA-Z0-9_:]*' "$OUT/btrace_stacks.json" 2>/dev/null | sort -u | wc -l)
        echo "  OK: $nsyms unique mysqld function names resolved"
        grep -oP 'mysqld:\K[a-zA-Z_][a-zA-Z0-9_:]*' "$OUT/btrace_stacks.json" 2>/dev/null | sort -u | head -5 | \
            while read fn; do echo "    $fn"; done
    else
        echo "  WARN: no mysqld function names found (install mysql-server-core-8.0-dbgsym?)"
    fi

    # ---- Cleanup ----
    echo ""
    echo "[sysbench] cleaning up dataset ..."
    sysbench "${SB_COMMON[@]}" cleanup >/dev/null 2>&1 || true

    # ---- Summary ----
    echo ""
    echo "========================================="
    echo " results"
    echo "========================================="
    echo " baseline tps : $base"
    echo " traced   tps : $traced"
    if [ -n "$base" ] && [ -n "$traced" ] && [ "$base" != "0" ]; then
        awk -v b="$base" -v t="$traced" 'BEGIN { printf " overhead     : %.2f%%\n", (b-t)/b*100 }'
    fi
    echo ""
    echo " artifacts in $OUT/:"
    ls -lh "$OUT/"
    echo "========================================="
}

main "$@"
