all: bf_jit.s bf_jit 

CFLAGS = -Wall -O3

bf_jit: bf_jit.c
	$(CC) $(CFLAGS) bf_jit.c -o bf_jit

bf_jit.s: bf_jit.c
	$(CC) $(CFLAGS) -S bf_jit.c

clean:
	rm bf_jit bf_jit.s
