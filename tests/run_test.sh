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

    echo ""
    echo "=== $name ==="

    # start workload
    $cmd &
    local wpid=$!
    sleep 0.3

    # record
    local btfile="$OUT/${name}.btrace"
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

    # report
    "$BTRACE" report -i "$btfile" -o "$OUT" --dot \
        > "$OUT/${name}.txt" 2>"$OUT/${name}.log"
    if [ -f "$OUT/btrace.dot" ]; then
        mv "$OUT/btrace.dot" "$OUT/${name}.dot"
    fi

    local events
    events=$(grep "Events:" "$OUT/${name}.txt" 2>/dev/null | grep -oP 'Events: \K[0-9]+' || echo 0)

    if [ "$events" -eq 0 ]; then
        echo "  FAIL: 0 events"
        FAIL=$((FAIL+1))
        return
    fi

    # verify expected category if given
    if [ -n "$expected" ]; then
        if grep -q "$expected" "$OUT/${name}.txt" 2>/dev/null; then
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

# long-running disk_io helper
cat > /tmp/btrace_disk_io.c << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#define BUFSZ 4096
static volatile int stop = 0;
static const char *fp = "/tmp/btrace_test_io.dat";
static void *writer(void *arg) {
    (void)arg;
    int fd = open(fp, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd<0) return NULL;
    char buf[BUFSZ]; memset(buf,'W',BUFSZ);
    while (!stop) { write(fd,buf,BUFSZ); fsync(fd); lseek(fd,0,SEEK_SET); }
    close(fd); return NULL;
}
static void *reader(void *arg) {
    (void)arg;
    usleep(50000);
    int fd = open(fp, O_RDONLY);
    if (fd<0) return NULL;
    char buf[BUFSZ];
    while (!stop) { lseek(fd,0,SEEK_SET); read(fd,buf,BUFSZ); }
    close(fd); return NULL;
}
int main(void) {
    pthread_t w,r;
    pthread_create(&w,NULL,writer,NULL);
    pthread_create(&r,NULL,reader,NULL);
    sleep(10);
    stop=1;
    pthread_join(w,NULL); pthread_join(r,NULL);
    unlink(fp); return 0;
}
CEOF
gcc -o /tmp/btrace_disk_io /tmp/btrace_disk_io.c -lpthread

# run all tests
run_test "mutex"   "./tests/cases/test_mutex"   3 "futex"
run_test "condvar" "./tests/cases/test_condvar"  3 "futex"
run_test "epoll"   "./tests/cases/test_epoll"    3 "epoll"
run_test "disk_io" "/tmp/btrace_disk_io"         5 "disk_io"

# net_read needs a TCP server
(while true; do nc -l -p 19999 -q0 </dev/null >/dev/null; done) &
local_srv=$!
sleep 0.3
run_test "net_read" "./tests/cases/test_net_read" 5 "net_io"
kill $local_srv 2>/dev/null || true
wait $local_srv 2>/dev/null || true

rm -f /tmp/btrace_disk_io /tmp/btrace_disk_io.c /tmp/btrace_test_io.dat

echo ""
echo "Results: $PASS passed, $FAIL failed"
echo "Artifacts:"
ls -lh "$OUT/"

exit $FAIL
