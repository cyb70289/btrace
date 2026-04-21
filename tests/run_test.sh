#!/bin/bash
set -e

BTRACE="./btrace"
OUTDIR="./out"

mkdir -p "$OUTDIR"

run_test() {
    local name="$1"
    local cmd="$2"
    local duration="${3:-3}"

    echo "=== Profiling $name ==="

    $cmd &
    local pid=$!
    sleep 0.3

    local btfile="$OUTDIR/${name}.btrace"
    sudo $BTRACE record -p $pid -d 8 -o "$btfile" &
    local bpid=$!
    sleep $duration
    sudo kill -INT $bpid 2>/dev/null
    wait $bpid 2>/dev/null
    kill $pid 2>/dev/null
    wait $pid 2>/dev/null

    if [ ! -f "$btfile" ]; then
        echo "  FAIL: no output file"
        return 1
    fi

    $BTRACE report -i "$btfile" -o "$OUTDIR" --dot > "$OUTDIR/${name}.txt" 2>"$OUTDIR/${name}_stderr.log"

    if [ -f "$OUTDIR/btrace.dot" ]; then
        mv "$OUTDIR/btrace.dot" "$OUTDIR/${name}.dot"
    fi

    local events=$(grep "Events:" "$OUTDIR/${name}.txt" 2>/dev/null | grep -oP 'Events: \K[0-9]+' || echo 0)
    local cats=$(grep -oP '\[\w+\]' "$OUTDIR/${name}.txt" 2>/dev/null | sort -u | tr '\n' ' ')

    echo "  Events: $events"
    echo "  Categories: $cats"
    echo "  Files: $btfile, $OUTDIR/${name}.txt, $OUTDIR/${name}.dot"
}

echo "=== btrace test suite ==="
echo "Output directory: $OUTDIR"
echo ""

# Build test binaries
make test-cases 2>/dev/null

# Need a longer-running disk_io test
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
gcc -o /tmp/btrace_disk_io /tmp/btrace_disk_io.c -lpthread 2>/dev/null

# Need a server for net_read
run_test "mutex"   "./tests/cases/test_mutex" 3
run_test "condvar" "./tests/cases/test_condvar" 3
run_test "epoll"   "./tests/cases/test_epoll" 3
run_test "disk_io" "/tmp/btrace_disk_io" 5

(while true; do nc -l -p 19999 -q0 </dev/null >/dev/null; done) &
SRV_PID=$!
sleep 0.3
run_test "net_read" "./tests/cases/test_net_read" 5
kill $SRV_PID 2>/dev/null
wait $SRV_PID 2>/dev/null

rm -f /tmp/btrace_disk_io /tmp/btrace_disk_io.c

echo ""
echo "=== All outputs saved to $OUTDIR/ ==="
ls -lh "$OUTDIR"
