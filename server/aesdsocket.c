#include <stdio.h>
#include <syslog.h>

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdbool.h>

#define PORT "9000"                            // the port users will be connecting to
#define BACKLOG 10                             // the port users will be connecting to
#define FILELOCATION "/var/tmp/aesdsocketdata" // location to write data to
#define BUFFER_SIZE 1024

FILE *myfile;
int new_fd;

void daemonize() {
    pid_t pid, sid;

    // Fork off the parent process
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    // Create a new SID for the child process
    sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }

    /* Fork off for the second time*/
    pid = fork();

    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    // Change the current working directory
    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }

    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

}

void sigchld_handler(int s)
{

    if (s == SIGINT)
        printf("SIGINT received. ");
    else if (s == SIGTERM)
        printf("SIGTERM received. ");

    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;

    // Attempt to delete the file
    if (remove(FILELOCATION) == 0)
    {
        printf("File %s deleted successfully.\n", FILELOCATION);
    }
    else
    {
        printf("Unable to delete the file %s.\n", FILELOCATION);
        perror("remove");
    }

    syslog(LOG_DEBUG, "Caught signal, exiting");
    printf("Caught signal, exiting\n");

    errno = saved_errno;

    exit(0);
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

// arg 1 is path to file
// arg 2 is string to write to file
int main(int argc, char *argv[])
{
    int daemonflag = 0;
    int sockfd; // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    char buf[BUFFER_SIZE];
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;
    bool packet_finished = false;
    int i;
    int total_size = 0;

    int c;
    // Get the args -d arg if it exists
    while ((c = getopt(argc, argv, "d")) != -1)
        switch (c)
        {
        case 'd':
            daemonflag = 1;
            break;
        default:
            abort();
        }

    if (daemonflag) {
        daemonize();
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1)
        {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                       sizeof(int)) == -1)
        {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)
    {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1)
    {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(1);
    }

    // Set the handler for SIGINT
    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(1);
    }

    // Set the handler for SIGTERM
    if (sigaction(SIGTERM, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    while (1)
    { // main accept() loop
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1)
        {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
                  get_in_addr((struct sockaddr *)&their_addr),
                  s, sizeof s);
        printf("server: got connection from %s\n", s);
        syslog(LOG_DEBUG, "server: got connection from %s\n", s);

        // // Receive via file descriptor until \n
        packet_finished = false;
        FILE *myfile = fopen(FILELOCATION, "a+");

        while (packet_finished != true)
        {

            int received_size = recv(new_fd, buf, sizeof buf, 0);

            if (received_size == -1)
            {
                perror("recv");
                return -1;
            }

            total_size += received_size;


            fwrite(buf, sizeof(char), received_size, myfile);

            fflush(myfile);

            for (i = 0; i < received_size; i++)
            {
                if (buf[i] == '\n')
                {
                    packet_finished = true;
                }
            }
        }

        char *source = NULL;
        if (myfile != NULL)
        {
            /* Allocate our buffer to that size. */
            source = malloc(sizeof(char) * (total_size + 1));

            /* Go back to the start of the file. */
            fseek(myfile, 0, SEEK_SET);

            /* Read the entire file into memory. */
            size_t newLen = fread(source, sizeof(char), total_size, myfile);
            if (ferror(myfile) != 0)
            {
                fputs("Error reading file", stderr);
            }
            else
            {
                source[newLen++] = '\0'; /* Just to be safe. */
            }
        }

        send(new_fd, source, total_size, 0);
        close(new_fd); // parent doesn't need this
        free(source);  /* Don't forget to call free() later! */
        fclose(myfile);
    }
    return 0;
}
