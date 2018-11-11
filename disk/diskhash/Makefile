all: diskhash.o

diskhash.o: diskhash.c diskhash.h rtable.h
	gcc $(CFLAGS) -fPIC -o $@ -Wall -c diskhash.c

.PHONY: all
