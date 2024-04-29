#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    // Obtain thread arguments from the parameter
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;

    // Wait for a specified time before acquiring the mutex
    int wait_result = usleep(thread_func_args->wait_to_obtain_ms * 1000);
    if (wait_result != 0) {
        // Log an error if waiting fails
        ERROR_LOG("usleep failed");
        // Indicate failure in the thread data structure
        thread_func_args->thread_complete_success = false;
        // Exit the thread function with an error
        return thread_param;
    }

    // Attempt to lock the mutex
    wait_result = pthread_mutex_lock(thread_func_args->mutex);
    if (wait_result != 0) {
        // Log an error if acquiring the mutex fails
        ERROR_LOG("pthread_mutex_lock failed");
        // Indicate failure in the thread data structure
        thread_func_args->thread_complete_success = false;
        // Exit the thread function with an error
        return thread_param;
    } 

    // Wait for another specified time before releasing the mutex
    wait_result = usleep(thread_func_args->wait_to_release_ms * 1000);
    if (wait_result != 0) {
        // Log an error if waiting fails
        ERROR_LOG("usleep failed");
        // Indicate failure in the thread data structure
        thread_func_args->thread_complete_success = false;
        // Exit the thread function with an error
        return thread_param;
    } 

    // Unlock the mutex to allow other threads access
    wait_result = pthread_mutex_unlock(thread_func_args->mutex);
    if (wait_result != 0) {
        // Log an error if releasing the mutex fails
        ERROR_LOG("pthread_mutex_unlock failed");
        // Indicate failure in the thread data structure
        thread_func_args->thread_complete_success = false;
        // Exit the thread function with an error
        return thread_param;
    }

    // Thread completes successfully, return the parameter (usually NULL)
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
  // Allocate memory for thread data structure
  struct thread_data *thread_data = (struct thread_data *)malloc(sizeof(struct thread_data));
  if (thread_data == NULL) {
      ERROR_LOG("Allocate memory for thread_data failed");
      return false; // Memory allocation failed
  }

  // Set wait times in the thread data structure
  thread_data->wait_to_obtain_ms = wait_to_obtain_ms;
  thread_data->wait_to_release_ms = wait_to_release_ms;
  thread_data->mutex = mutex;
  thread_data->thread_complete_success = true;

  // Pass the mutex and thread data to the thread function
  int create_result = pthread_create(thread, NULL, threadfunc, thread_data);
  if (create_result != 0) {
      ERROR_LOG("pthread_create failed");
      free(thread_data); // Free allocated memory on failure
      return false; // Thread creation failed
  }

    return true; // Thread creation successful
}

