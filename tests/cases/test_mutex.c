#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define NTHREADS 4
#define ITERS 200

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

static void *worker(void *arg) {
    long id = (long)arg;
    for (int i = 0; i < ITERS; i++) {
        pthread_mutex_lock(&mtx);
        usleep(1000);
        pthread_mutex_unlock(&mtx);
        usleep(500);
    }
    return (void *)id;
}

int main(void) {
    pthread_t threads[NTHREADS];
    for (long i = 0; i < NTHREADS; i++)
        pthread_create(&threads[i], NULL, worker, (void *)i);

    for (int i = 0; i < NTHREADS; i++)
        pthread_join(threads[i], NULL);

    printf("test_mutex done\n");
    return 0;
}
