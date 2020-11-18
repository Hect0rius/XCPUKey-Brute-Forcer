LIBS=-lcrypto -lm -lpthread
CFLAGS=-ggdb -O3 -Wall -std=c99
OBJS=cpu-gen.o util.o
PROGS=cpu-gen
most: cpu-gen

all: $(PROGS)
	
cpu-gen: cpu-gen.o util.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)
	
clean:
	rm -f $(OBJS) $(PROGS) $(TESTS)
