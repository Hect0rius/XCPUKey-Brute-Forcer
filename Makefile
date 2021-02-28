LIBS=-lpthread
CFLAGS=-ggdb -O3 -Wall -std=c99
OBJS=cpu-gen.o util.o crypto/hash/hmac-sha1.o crypto/enc/rc4.o crypto/hash/sha1.o
PROGS=cpu-gen
most: cpu-gen

all: $(PROGS)
	
cpu-gen: cpu-gen.o util.o crypto/hash/hmac-sha1.o crypto/enc/rc4.o crypto/hash/sha1.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)
	
clean:
	rm -f $(OBJS) $(PROGS) $(TESTS)
