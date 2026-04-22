#!/bin/bash
#
# btrace MySQL e2e showcase + overhead benchmark.
#
# - Starts a throwaway Percona Server 8.0 container.
# - Prepares a sysbench OLTP dataset.
# - Runs OLTP read-write workload twice: baseline, then with btrace attached.
# - Reports TPS for both runs and btrace overhead %.
# - Generates text + DOT report in ./out/.
#
# Requires: docker, sysbench, sudo, btrace built at ./btrace.
#

set -uo pipefail

CONTAINER="btrace-mysql"
PORT=3307
IMAGE="percona/percona-server:8.0"
TABLES=4
TABLE_SIZE=10000
THREADS=4
TIME=10
OUT="./out/mysql"
BTRACE="./btrace"

mkdir -p "$OUT"

SB_COMMON=(
    /usr/share/sysbench/oltp_read_write.lua
    --mysql-host=127.0.0.1 --mysql-port="$PORT"
    --mysql-user=root --mysql-password=root --mysql-db=sb
    --tables="$TABLES" --table-size="$TABLE_SIZE"
    --threads="$THREADS" --time="$TIME" --report-interval=0
)

start_mysql() {
    echo "[mysql] starting $IMAGE on port $PORT ..."
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    docker run -d --name "$CONTAINER" \
        -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=sb \
        -p "${PORT}:3306" "$IMAGE" >/dev/null

    echo "[mysql] waiting for mysqld ..."
    for _ in $(seq 1 60); do
        if docker exec "$CONTAINER" mysqladmin -uroot -proot ping 2>/dev/null \
                | grep -q alive; then
            echo "[mysql] ready"
            return 0
        fi
        sleep 1
    done
    echo "[mysql] failed to start" >&2
    exit 1
}

stop_mysql() {
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}

get_host_pid() {
    docker inspect -f '{{.State.Pid}}' "$CONTAINER"
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

    echo "========================================="
    echo " btrace MySQL e2e + overhead benchmark"
    echo "========================================="
    echo " sysbench: $TABLES tables x $TABLE_SIZE rows, $THREADS threads, ${TIME}s"
    echo ""

    # ---- Phase 0: start MySQL + prepare dataset ----
    start_mysql
    local pid
    pid=$(get_host_pid)
    echo "[mysql] host pid: $pid"

    echo "[sysbench] preparing dataset ..."
    sysbench "${SB_COMMON[@]}" prepare >/dev/null

    # ---- Phase 1: baseline (no btrace) ----
    echo ""
    echo "[bench] === baseline (no btrace) ==="
    local base
    base=$(bench baseline | tee "$OUT/baseline.txt" | awk -F= '{print $2}')

    # ---- Phase 2: with btrace profiling ----
    echo ""
    echo "[bench] === with btrace attached ==="
    local btfile="$OUT/mysql.btrace"
    sudo "$BTRACE" record -p "$pid" -d 8 -o "$btfile" >"$OUT/record.log" 2>&1 &
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

    # ---- Cleanup ----
    stop_mysql

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
