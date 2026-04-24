#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT_BASE 19000
#define ITERS 50

static int port = PORT_BASE;

static void *server(void *arg) {
    (void)arg;
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {.sin_family = AF_INET,
                               .sin_port = htons(port),
                               .sin_addr.s_addr = INADDR_ANY};
    bind(lfd, (struct sockaddr *)&addr, sizeof(addr));
    listen(lfd, 1);

    int cfd = accept(lfd, NULL, NULL);
    char buf[256];
    for (int i = 0; i < ITERS; i++) {
        int n = recv(cfd, buf, sizeof(buf), 0);
        if (n <= 0)
            break;
    }
    close(cfd);
    close(lfd);
    return NULL;
}

static void *client(void *arg) {
    (void)arg;
    usleep(100000);

    struct sockaddr_in addr = {.sin_family = AF_INET,
                               .sin_port = htons(port),
                               .sin_addr.s_addr = inet_addr("127.0.0.1")};

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));

    char buf[64] = "hello";
    for (int i = 0; i < ITERS; i++) {
        send(fd, buf, strlen(buf), 0);
        usleep(50000);
    }
    close(fd);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc > 1)
        port = atoi(argv[1]);

    pthread_t s, c;
    pthread_create(&s, NULL, server, NULL);
    pthread_create(&c, NULL, client, NULL);
    pthread_join(s, NULL);
    pthread_join(c, NULL);
    printf("test_net_read done\n");
    return 0;
}
