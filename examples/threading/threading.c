#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{
    struct thread_data* tp = (struct thread_data*) thread_param;
    tp->thread_complete_success = false;

    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = ((long) tp->wait_to_obtain_ms) * 1000000L;

    int res = nanosleep(&ts,&ts);
    if(res) {
        perror("interrupted sleep");
        return thread_param;
    }

    int rc = pthread_mutex_lock(tp->mutex);
    if(rc) {
        perror("cannot access mutex lock");
        return thread_param;
    }

    ts.tv_nsec = ((long) tp->wait_to_release_ms) * 1000000L;
    res = nanosleep(&ts,&ts);
    if(res) {
        perror("interrupted sleep");
        return thread_param;
    }

    rc = pthread_mutex_unlock(tp->mutex);
    if(rc) {
        perror("cannot unlock mutex lock");
        return thread_param;
    }
    
    tp->thread_complete_success = true;
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TASK: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
    struct thread_data* td = malloc(sizeof(struct thread_data));
    if(!td) {
        perror("malloc failed");
        return false;
    }
    td->mutex=mutex;
    td->wait_to_obtain_ms = wait_to_obtain_ms;
    td->wait_to_release_ms = wait_to_release_ms;

    int rc = pthread_create(thread, NULL, threadfunc, td);
    if(rc) {
        perror("Could not create thread");
        free(td);
        return false;
    }
    return true;
}
