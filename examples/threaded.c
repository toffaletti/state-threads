#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "st.h"

static void *_thread(void *arg) {
    for (unsigned int i=0; i<5; i++) {
        printf("i: %u thread: %lu\n", i, pthread_self());
        pthread_yield();
    }
    return NULL;
}

static void *thread(void *arg) {
    if (st_init() < 0) {
        perror("st_init");
        exit(1);
    }

    for (unsigned int i=0; i<2; i++) {
        if (st_thread_create(_thread, NULL, 0, 0) == NULL) {
            perror("st_thread_create");
            exit(1);
        }
    }

    printf("st exiting thread: %lu\n", pthread_self());
    st_thread_exit(NULL);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (st_init() < 0) {
        perror("st_init");
        exit(1);
    }

    const unsigned int num_threads = 4;
    pthread_t threads[num_threads];
    for (unsigned int i=0; i<num_threads; i++) {
        pthread_create(&threads[i], NULL, thread, NULL);
    }

    for (unsigned int i=0; i<num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("done joining\n");
    for (unsigned int i=0; i<2; i++) {
        if (st_thread_create(_thread, NULL, 0, 0) == NULL) {
            perror("st_thread_create");
            exit(1);
        }
    }

    st_thread_exit(NULL);
    printf("does not happen\n");

    return 1;
}