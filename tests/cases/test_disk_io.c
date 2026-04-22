#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define ITERS 1024
#define BUFSZ 65536

static const char *tmpfile_path = "/tmp/btrace_test_io.dat";

static void *writer(void *arg)
{
    (void)arg;
    int fd = open(tmpfile_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open write"); return NULL; }

    char buf[BUFSZ];
    memset(buf, 'W', BUFSZ);
    for (int i = 0; i < ITERS; i++) {
        write(fd, buf, BUFSZ);
        fsync(fd);
        lseek(fd, 0, SEEK_SET);
    }
    close(fd);
    return NULL;
}

static void *reader(void *arg)
{
    (void)arg;
    usleep(50000);
    int fd = open(tmpfile_path, O_RDONLY);
    if (fd < 0) { perror("open read"); return NULL; }

    char buf[BUFSZ];
    for (int i = 0; i < ITERS; i++) {
        lseek(fd, 0, SEEK_SET);
        read(fd, buf, BUFSZ);
    }
    close(fd);
    return NULL;
}

int main(void)
{
    pthread_t w, r;
    pthread_create(&w, NULL, writer, NULL);
    pthread_create(&r, NULL, reader, NULL);
    pthread_join(w, NULL);
    pthread_join(r, NULL);
    unlink(tmpfile_path);
    printf("test_disk_io done\n");
    return 0;
}
