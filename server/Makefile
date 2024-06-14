CROSS_COMPILE ?=
CC ?= $(CROSS-COMPILE)gcc

CFLAGS += -g -Wall -Werror -pedantic -std=c99 -pthread -lrt
LDFLAGS += -g -Wall -Werror -pedantic -std=c99 -pthread -lrt

all: aesdsocket

clean:
	rm -rf *.o
	rm -rf aesdsocket

aesdsocket: aesdsocket.o
	$(CC) -o aesdsocket aesdsocket.o $(LDFLAGS)

%.o: %.c
	$(CC) $(INCLUDES) -c -o $@ $< $(CFLAGS)

.PHONY: clean all
