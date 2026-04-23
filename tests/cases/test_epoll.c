#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

#pragma GCC diagnostic ignored "-Wunused-result"

#define ITERS 100

static void *epoll_thread(void *arg)
{
    (void)arg;
    int efd = epoll_create1(0);
    int tfd = timerfd_create(CLOCK_MONOTONIC, 0);

    struct epoll_event ev = { .events = EPOLLIN, .data.fd = tfd };
    epoll_ctl(efd, EPOLL_CTL_ADD, tfd, &ev);

    struct itimerspec its = {
        .it_interval = { 0, 20000000 },
        .it_value    = { 0, 20000000 }
    };
    timerfd_settime(tfd, 0, &its, NULL);

    for (int i = 0; i < ITERS; i++) {
        struct epoll_event events[1];
        int n = epoll_wait(efd, events, 1, 1000);
        if (n > 0) {
            unsigned long long val;
            read(tfd, &val, sizeof(val));
        }
    }

    close(tfd);
    close(efd);
    return NULL;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, NULL, epoll_thread, NULL);
    pthread_join(t, NULL);
    printf("test_epoll done\n");
    return 0;
}
