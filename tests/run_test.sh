#!/bin/bash
#
# btrace workload test suite.
# Profiles each test case, generates text + DOT report, saves to ./out/.
#

set -uo pipefail

BTRACE="./btrace"
OUT="./out"

mkdir -p "$OUT"

PASS=0
FAIL=0

run_test() {
    local name="$1"
    local cmd="$2"
    local duration="${3:-3}"
    local expected="${4:-}"
    local tdir="$OUT/$name"

    echo ""
    echo "=== $name ==="
    mkdir -p "$tdir"

    # start workload
    $cmd &
    local wpid=$!

    # record
    local btfile="$tdir/btrace.btrace"
    sudo "$BTRACE" record -p $wpid -d 8 -o "$btfile" >/dev/null &
    local bpid=$!
    sleep "$duration"
    sudo kill -INT $bpid 2>/dev/null || true
    wait $bpid 2>/dev/null || true
    kill $wpid 2>/dev/null || true
    wait $wpid 2>/dev/null || true

    if [ ! -f "$btfile" ]; then
        echo "  FAIL: no .btrace file"
        FAIL=$((FAIL+1))
        return
    fi

    # report (text + dot)
    "$BTRACE" report -i "$btfile" -o "$tdir" --dot \
        > "$tdir/btrace.txt" 2>"$tdir/btrace.log"

    local events
    events=$(grep "Events:" "$tdir/btrace.txt" 2>/dev/null | grep -oP 'Events: \K[0-9]+' || echo 0)

    if [ "$events" -eq 0 ]; then
        echo "  FAIL: 0 events"
        FAIL=$((FAIL+1))
        return
    fi

    # generate svg + html
    if [ -f "$tdir/btrace.dot" ]; then
        dot -Tsvg "$tdir/btrace.dot" > "$tdir/btrace.svg" 2>/dev/null || true
        python3 scripts/btrace2html.py "$tdir/btrace.dot" -o "$tdir/btrace.html" 2>/dev/null || true
    fi

    # verify expected category if given
    if [ -n "$expected" ]; then
        if grep -q "$expected" "$tdir/btrace.txt" 2>/dev/null; then
            echo "  PASS  ($events events, category: $expected)"
        else
            echo "  FAIL  ($events events, expected '$expected' not found)"
            FAIL=$((FAIL+1))
            return
        fi
    else
        echo "  PASS  ($events events)"
    fi
    PASS=$((PASS+1))
}

echo "btrace test suite"
echo "Output: $OUT/"

# build
make test-cases 2>/dev/null

# run all tests
run_test "mutex"   "./tests/cases/test_mutex"   3 "futex"
run_test "condvar" "./tests/cases/test_condvar"  3 "futex"
run_test "epoll"   "./tests/cases/test_epoll"    3 "epoll"
run_test "disk_io" "./tests/cases/test_disk_io"  5 "disk_io"

# net_read needs a TCP server
(while true; do nc -l -p 19999 -q0 </dev/null >/dev/null; done) &
local_srv=$!
sleep 0.3
run_test "net_read" "./tests/cases/test_net_read" 5 "net_io"
kill $local_srv 2>/dev/null || true
wait $local_srv 2>/dev/null || true

rm -f /tmp/btrace_test_io.dat

echo ""
echo "Results: $PASS passed, $FAIL failed"
for d in "$OUT"/*/; do
    echo ""
    echo "Artifacts in $d:"
    ls -lh "$d"
done

exit $FAIL
