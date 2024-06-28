#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include "queue.h"
#include "aesd_ioctl.h"

#define CONTROL_MSG "AESDCHAR_IOCSEEKTO:"
#define CONTROL_MSG_SIZE (sizeof(CONTROL_MSG) - 1)

#ifndef USE_AESD_CHAR_DEVICE
#define USE_AESD_CHAR_DEVICE 1
#endif

// Define Fixed Values
static bool sig_recieved = false;
static int fd = -1;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t main_thread;
static sigset_t signal_mask;
static volatile uint32_t thread_exit_counter = 0;
static SLIST_HEAD(thread_data_head, thread_data) list = SLIST_HEAD_INITIALIZER(thread_data_head);

// Thread Struct

struct thread_data {
    int sock;
    struct sockaddr sa;
    socklen_t salen;
    pthread_t thread;
    volatile bool thread_exited;
    SLIST_ENTRY(thread_data) next;
};

// Signal handler
static void signal_handler(int a) {}

// Process the Recieved Packet

static bool proc_packet(int sk, int fd, int *outfd, bool *ctrl)
{
    char buffer[4096];
    char *c = NULL;
    bool run_complete = false;
    ssize_t num_bytes = 0;
    bool retval = false;

#if !USE_AESD_CHAR_DEVICE
    off_t init_offset = lseek(fd, 0, SEEK_END);
#endif

*ctrl = false;

#if USE_AESD_CHAR_DEVICE
  fd = open("/dev/aesdchar", O_CREAT | O_TRUNC | O_RDWR, 0644);
  if (fd == -1) 
  {
    syslog(LOG_ERR, "Could not open file %s", strerror(errno));
    return false;
  }
#endif

    while (!sig_recieved && !run_complete)
    {
        num_bytes = recv(sk, buffer, sizeof(buffer), 0);
        if (num_bytes == -1)
        {
            syslog(LOG_ERR, "Num Bytes = -1: %s", strerror(errno));
            goto exit;
        } else if (num_bytes == 0) {
            goto exit;
        }

        c = memchr(buffer, '\n', num_bytes);
        if (c)
        {
            num_bytes = c + 1 - buffer;
            run_complete = true;
        }

        if ((run_complete && (num_bytes >= CONTROL_MSG_SIZE) &&
            !memcmp(CONTROL_MSG, buffer, CONTROL_MSG_SIZE)))
        {
            struct aesd_seekto seekto;
            char *end = NULL;

            buffer[num_bytes - 1] = 0;

            if ((c = strchr(buffer, ',')) == NULL)
            {
                syslog(LOG_ERR, "Issue with control message");
                goto exit;
            }

            *c = 0;

            seekto.write_cmd = (uint32_t) strtoul(buffer + CONTROL_MSG_SIZE, &end, 10);

            if (!buffer[CONTROL_MSG_SIZE] || (*end != 0))
            {
                syslog(LOG_ERR, "Issue with control message");
                goto exit;
            }

            seekto.write_cmd_offset = (uint32_t) strtoul(c + 1, &end, 10);

            if (!c[1] || (*end != 0))
            {
                syslog(LOG_ERR, "Issue with control message");
                goto exit;
            }

            syslog(LOG_DEBUG, "seekto=%d, offset=%d", seekto.write_cmd, seekto.write_cmd_offset);

            if (ioctl(fd, AESDCHAR_IOCSEEKTO, &seekto) == -1)
            {
                syslog(LOG_ERR, "Issue with ioctl: %s", strerror(errno));
                goto exit;
            }

            *outfd = fd;
            *ctrl = true;

        }
        else {
            if (write(fd, buffer, num_bytes) == -1)
            {
                syslog(LOG_ERR, "Could not write: %s", strerror(errno));
                #if !USE_AESD_CHAR_DEVICE
                ftruncate(fd, init_offset);
                #endif
                goto exit;
            }
        }
    }

    if (sig_recieved)
    {
        goto exit;
    }

    return true;

exit:
    #if USE_AESD_CHAR_DEVICE
    if (!*ctrl || !retval)
    {
        close(fd);
    }
    #endif
    return retval;
}

// Provide a response rationale

static void provide_resp(int sk, int fd, bool ctrl)
{
    char buffer[4096];
    ssize_t num_bytes = 0;

#if !USE_AESD_CHAR_DEVICE
    if ((lseek(fd, 0, SEEK_SET)) == -1)
    {
        syslog(LOG_ERR, "Could not find end: %s", strerror(errno));
        return;
    }
#else
    if (!ctrl)
    {
        fd = open("/dev/aesdchar", O_CREAT | O_TRUNC | O_RDWR, 0644);
        if (fd == -1) 
        {
            syslog(LOG_ERR, "Error opening file!: %s", strerror(errno));
            return;
        }
    }
#endif

    while (!sig_recieved)
    {
        num_bytes = read(fd, buffer, sizeof(buffer));
        if (num_bytes == -1)
        {
            syslog(LOG_ERR, "Num Bytes = -1: %s", strerror(errno));
            return;
        } else if (num_bytes == 0) {
            return;
        }

        if (send(sk, buffer, num_bytes, 0) == -1)
        {
            syslog(LOG_ERR, "Could not send: %s", strerror(errno));
            return;
        }
    }
    #if USE_AESD_CHAR_DEVICE
    close(fd);
    #endif
}

// Generate the Thread

static void *gen_thread(void *arg)
{
    struct thread_data *td = arg;
    char ip_addr[40];
    bool ctrl = false;
    int fdret = fd;

    pthread_mutex_lock(&mutex);

    if (inet_ntop(AF_INET, &((struct sockaddr_in *)&td->sa)->sin_addr, ip_addr, sizeof(ip_addr)) == NULL)
    {
        strncpy(ip_addr, "???", sizeof(ip_addr));
    }

    syslog(LOG_DEBUG, "Accepted connection from %s", ip_addr);

    if (!proc_packet(td->sock, fd, &fdret, &ctrl))
    {
        syslog(LOG_ERR, "There was an error processing the packet.");
    } else {
        provide_resp(td->sock, fdret, ctrl);
    }

    close(td->sock);
    td->sock = -1;
    syslog(LOG_DEBUG, "Closed connection from %s", ip_addr);
    __atomic_store_n(&td->thread_exited, true, __ATOMIC_RELEASE);
    __atomic_add_fetch(&thread_exit_counter, 1, __ATOMIC_RELEASE);

    pthread_mutex_unlock(&mutex);
    return NULL;
}

// Create timer

static void *thread_timer(void *arg)
{
    char buffer[100];
    struct tm time_dat;
    time_t timer;
    size_t s;

    while (!sig_recieved)
    {
        if (usleep(10 * 1000000) == -1)
        {
            continue;
        }

        pthread_mutex_lock(&mutex);
        do
        {
            timer = time(NULL);
            if (localtime_r(&timer, &time_dat) == NULL)
            {
                syslog(LOG_ERR, "Error in Local Time: %s", strerror(errno));
                break;
            }

            if ((s = strftime(buffer, sizeof(buffer), "timestamp:%a, %d %b %Y %T %z\n", &time_dat)) == 0)
            {
                syslog(LOG_ERR, "Error running string time: %s", strerror(errno));
                break;
            }

            if (write(fd, buffer, s) == -1)
            {
                syslog(LOG_ERR, "Cannot write: %s", strerror(errno));
            }

        } while(0);

        pthread_mutex_unlock(&mutex);

    }
    return NULL;
}

// Initialize the signal handler for threads

static void *thread_signals(void *arg)
{
    int rec;
    int signal;

    while (true) {
        if ((rec = sigwait(&signal_mask, &signal)) != 0)
        {
            syslog(LOG_ERR, "Cannot Join Pthreads: %s", strerror(errno));
        }
        switch(signal)
        {
            case SIGINT:
            case SIGTERM:
                sig_recieved = true;
                pthread_kill(main_thread, SIGUSR1);
                return NULL;
            default:
                syslog(LOG_ERR, "Unexpected Error: %d", signal);
        }
    }
}

// Server Handler

static bool server_init(int sk, const struct sockaddr *sa, socklen_t salen)
{
    struct thread_data *td = calloc(1, sizeof(struct thread_data));
    int rec = 0;

    if (!td) {
        return false;
    }

    td->sock = sk;
    td->sa = *sa;
    td->salen = salen;

    if ((rec = pthread_create(&td->thread, NULL, gen_thread, td)) != 0)
    {
        free(td);
        syslog(LOG_ERR, "Could not create thread: %s", strerror(errno));
        return false;
    }
    return true;
}

// Main Function

int main(int argc, char **argv)
{
    int sk = -1;
    int rec = 0;
    int child = -1;
    int return_val = -1;
    int setSK = 1;
    int z = 0;
    uint32_t counter = 0;
    bool is_daemon = false;
    struct addrinfo *ai = NULL;
    struct addrinfo hints;
    struct sockaddr sa;
    socklen_t salen;
    struct thread_data *td = NULL;
    struct thread_data *td2 = NULL;
    pthread_t timer_thread;
    pthread_t sig_thread;
    struct sigaction sig_action;
    #if USE_AESD_CHAR_DEVICE
    bool enable_timer = false;
    #else
    bool enable_timer = true;
    #endif


    main_thread = pthread_self();
    memset(&hints, 0, sizeof(hints));
    openlog(NULL, 0, LOG_USER);

    for (z = 1; z < argc; ++z)
    {
        if (!strcmp(argv[z], "-d"))
        {
            is_daemon = true;
        }
    }

    if ((sk = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    {
        syslog(LOG_ERR, "Could not open file: %s", strerror(errno));
        goto exit;
    }

    if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &setSK, sizeof(setSK)) == -1)
    {
        syslog(LOG_ERR, "Error setting up socket: %s", strerror(errno));
        goto exit;
    }

    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((rec = getaddrinfo(NULL, "9000", &hints, &ai)) != 0)
    {
        syslog(LOG_ERR, "Could not get ADDR: %s", gai_strerror(rec));
        goto exit;
    }

    if (bind(sk, ai->ai_addr, ai->ai_addrlen) == -1)
    {
        syslog(LOG_ERR, "Could not bind to socket: %s", strerror(errno));
        goto exit;
    }

    if (is_daemon)
    {
        pid_t child_pid = fork();
        if (child_pid != 0)
        {
            _exit(0);
        }
        setsid();
        //chdir("/");

        if ((freopen("/dev/null", "r", stdin) == NULL) ||
            (freopen("/dev/null", "w", stdout) == NULL) ||
            (freopen("/dev/null", "w", stderr) == NULL)) 
        {
            syslog(LOG_ERR, "Error in directing I/O: %s", strerror(errno));
            goto exit;
        }
    }
#if !USE_AESD_CHAR_DEVICE
    fd = open("/var/tmp/aesdsocketdata", O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (fd == -1) {
        syslog(LOG_ERR, "Could not open file: %s", strerror(errno));
        goto exit;
    }
#endif

    if (listen(sk, 10) == -1) {
        syslog(LOG_ERR, "Could not listen to socket: %s", strerror(errno));
        goto exit;
    }

    memset(&sig_action, 0, sizeof(sig_action));
    sig_action.sa_handler = signal_handler;
    sigaction(SIGUSR1, &sig_action, NULL);

    sigemptyset(&signal_mask);
    sigaddset(&signal_mask, SIGINT);
    sigaddset(&signal_mask, SIGTERM);

    if ((rec = pthread_sigmask(SIG_BLOCK, &signal_mask, NULL)) == -1)
    {
        syslog(LOG_ERR, "Error in Sigmask Threading: %s", strerror(rec));
        goto exit;
    }

    if ((rec = pthread_create(&sig_thread, NULL, thread_signals, NULL)) != 0)
    {
        syslog(LOG_ERR, "Could not create thread: %s", strerror(rec));
        goto exit;
    }
    if (enable_timer)
    {
        if ((rec = pthread_create(&timer_thread, NULL, thread_timer, NULL)) != 0)
        {
            syslog(LOG_ERR, "Could not create thread: %s", strerror(rec));
            goto exit;
        }
    }

    while(!sig_recieved)
    {
        int childT = -1;
        uint32_t j = 0;

        salen = sizeof(sa);
        if ((childT = accept(sk, &sa, &salen)) == -1)
        {
            syslog(LOG_ERR, "Could not accept: %s", strerror(errno));
            continue;
        }

        server_init(childT, &sa, salen);

        if (counter < (j = __atomic_load_n(&thread_exit_counter, __ATOMIC_ACQUIRE)))
        {
            counter = j;
            SLIST_FOREACH_SAFE(td, &list, next, td2)
            {
                if (__atomic_load_n(&td->thread_exited, __ATOMIC_ACQUIRE)) 
                {
                    SLIST_REMOVE(&list, td, thread_data, next);
                    if ((rec = pthread_join(td->thread, NULL)) != 0)
                    {
                        syslog(LOG_ERR, "Failed Joining Threads: %s", strerror(errno));
                    }
                    free(td);
                }
            }
        }
    }

    if (sig_recieved)
    {
        syslog(LOG_ERR, "Exiting");
    }

    if (enable_timer)
    {
        pthread_kill(timer_thread, SIGUSR1);
    }

    SLIST_FOREACH_SAFE(td, &list, next, td2)
    {
        if ((rec = pthread_join(td->thread, NULL)) != 0) 
        {
            syslog(LOG_ERR, "Failed Joining Threads: %s", strerror(rec));
        }
        free(td);
    }
    if (enable_timer)
    {
        if ((rec = pthread_join(sig_thread, NULL)) != 0)
        {
            syslog(LOG_ERR, "Could not create thread: %s", strerror(rec));
            goto exit;
        }
    }

    if ((rec = pthread_join(timer_thread, NULL)) != 0)
    {
        syslog(LOG_ERR, "Could not create thread: %s", strerror(rec));
        goto exit;
    }

    return_val = 0;

exit:
    if (ai)
    {
        freeaddrinfo(ai);
    }

    if (sk != -1)
    {
        close(sk);
    }

    if (child != -1)
    {
        close(child);
    }

    if (fd != -1)
    {
        close(fd);
    }
#if !USE_AESD_CHAR_DEVICE
    unlink("/var/tmp/aesdsocketdata");
#endif
    closelog();
    return return_val;

}
