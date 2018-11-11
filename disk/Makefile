all:
	cd diskhash && make
	gcc -O3 collision.c diskhash/diskhash.o -o collision -lcrypto
