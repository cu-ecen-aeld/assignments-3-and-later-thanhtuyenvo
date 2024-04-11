#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

int main(int argc, char** argv) {
    //Set up syslog logging for the utility
    openlog(NULL, LOG_ODELAY, LOG_USER);

    if (argc <= 2) {
        printf("Please passing two arguments: <FILE> <STRING>\n");
        closelog();
        return 1;
    }

    const char* filename = argv[1];
    const char* text = argv[2];
    //Check if the arguments are not empty
    if (strlen(filename) == 0 || strlen(text) == 0) {
        fprintf(stderr, "Filename or writing text is blank.\n");
        closelog();
        return 1;
    }
    //Writing steps
    syslog(LOG_DEBUG, "Writing <%s> to <%s>", text, filename);
    FILE* f = fopen(filename, "w");
    if (f != NULL) {
        size_t result = fwrite(text, strlen(text), 1, f);
        if (result == 0) {
            syslog(LOG_ERR, "Failure to write file: %s", strerror(errno));
            closelog();
            return 1;
        }
        fclose(f);
    } else {
        syslog(LOG_ERR, "Failure to write file: %s", strerror(errno));
        closelog();
        return 1;
    }
    return 0;
}
