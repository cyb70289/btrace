#!/bin/bash
set -e

BTRACE="./btrace"
OUTDIR="./out"
MYSQL_CTR="btrace-mysql"
MYSQL_IMG="percona/percona-server:8.0"
MYSQL_PW="test"
MYSQL_PORT=3306

mkdir -p "$OUTDIR"

start_mysql() {
    echo "Starting MySQL container..."
    docker rm -f $MYSQL_CTR 2>/dev/null || true
    docker run -d --name $MYSQL_CTR \
        -e MYSQL_ROOT_PASSWORD=$MYSQL_PW \
        -p $MYSQL_PORT:3306 \
        $MYSQL_IMG \
        --thread_handling=one-thread-per-connection \
        --thread_cache_size=2 \
        --max_connections=8 2>&1

    echo "Waiting for MySQL to be ready..."
    for i in $(seq 1 60); do
        if docker exec $MYSQL_CTR mysqladmin ping -h127.0.0.1 -uroot -p$MYSQL_PW --silent 2>/dev/null; then
            echo "  Ready after ${i}s"
            return 0
        fi
        sleep 1
    done
    echo "  MySQL failed to start"
    return 1
}

stop_mysql() {
    docker rm -f $MYSQL_CTR 2>/dev/null || true
}

get_mysqld_pid() {
    docker top $MYSQL_CTR | grep mysqld | awk '{print $2}' | head -1
}

run_benchmark() {
    local label="$1"
    local nthreads="$2"
    local niter="$3"

    echo "  Running benchmark: $nthreads threads, $niter iterations..."

    docker exec $MYSQL_CTR mysql -uroot -p$MYSQL_PW -e "
        CREATE DATABASE IF NOT EXISTS btrace_bench;
        USE btrace_bench;
        CREATE TABLE IF NOT EXISTS t1 (id INT PRIMARY KEY, val INT) ENGINE=InnoDB;
        TRUNCATE TABLE t1;
        INSERT INTO t1 VALUES (1, 0);
    " 2>/dev/null

    local start_ns=$(date +%s%N)

    for t in $(seq 1 $nthreads); do
        (
            for i in $(seq 1 $niter); do
                docker exec $MYSQL_CTR mysql -uroot -p$MYSQL_PW -e "
                    USE btrace_bench;
                    BEGIN;
                    SELECT * FROM t1 WHERE id=1 FOR UPDATE;
                    UPDATE t1 SET val=val+1 WHERE id=1;
                    COMMIT;
                " 2>/dev/null
            done
        ) &
    done
    wait

    local end_ns=$(date +%s%N)
    local elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

    echo "  Elapsed: ${elapsed_ms}ms"
    echo $elapsed_ms
}

echo "=== btrace MySQL e2e test ==="
echo ""

start_mysql

MYSQLD_PID=$(get_mysqld_pid)
echo "mysqld host PID: $MYSQLD_PID"

NTHREADS=4
NITER=50

echo ""
echo "--- Phase 1: Baseline (no btrace) ---"
BASELINE_MS=$(run_benchmark "baseline" $NTHREADS $NITER)

echo ""
echo "--- Phase 2: With btrace profiling ---"
BTFILE="$OUTDIR/mysql.btrace"
sudo $BTRACE record -p $MYSQLD_PID -d 8 -o "$BTFILE" &
BTRACE_PID=$!
sleep 1

PROFILED_MS=$(run_benchmark "profiled" $NTHREADS $NITER)

sudo kill -INT $BTRACE_PID 2>/dev/null
wait $BTRACE_PID 2>/dev/null

echo ""
echo "--- Generating report ---"
$BTRACE report -i "$BTFILE" -o "$OUTDIR" --dot > "$OUTDIR/mysql.txt" 2>"$OUTDIR/mysql_stderr.log"
if [ -f "$OUTDIR/btrace.dot" ]; then
    mv "$OUTDIR/btrace.dot" "$OUTDIR/mysql.dot"
fi

echo ""
echo "--- Results ---"
echo "  Baseline:    ${BASELINE_MS}ms"
echo "  With btrace: ${PROFILED_MS}ms"

if [ "$BASELINE_MS" -gt 0 ]; then
    OVERHEAD=$(( (PROFILED_MS - BASELINE_MS) * 100 / BASELINE_MS ))
    echo "  Overhead:    ${OVERHEAD}%"
else
    OVERHEAD=0
    echo "  Overhead:    N/A"
fi

EVENTS=$(grep "Events:" "$OUTDIR/mysql.txt" 2>/dev/null | grep -oP 'Events: \K[0-9]+' || echo "?")
CATS=$(grep -oP '\[\w+\]' "$OUTDIR/mysql.txt" 2>/dev/null | sort -u | tr '\n' ' ')

echo "  Events:      $EVENTS"
echo "  Categories:  $CATS"
echo ""
echo "Files saved:"
echo "  $BTFILE"
echo "  $OUTDIR/mysql.txt"
echo "  $OUTDIR/mysql.dot"

stop_mysql

echo ""
echo "=== MySQL e2e complete ==="
