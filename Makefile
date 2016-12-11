LIBS=-lcrypto -lm -lpthread -lcurl
CFLAGS=-ggdb -O3 -Wall -std=gnu11
OBJS=cpu-miner.o ocl-miner.o cpu-gen.o util.o
PROGS=cpu-miner ocl-miner cpu-gen

PLATFORM=$(shell uname -s)
ifeq ($(PLATFORM),Darwin)
OPENCL_LIBS=-framework OpenCL
else
OPENCL_LIBS=-lOpenCL
endif


most: cpu-miner cpu-gen

all: $(PROGS)

cpu-miner: cpu-miner.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)
	
cpu-gen: cpu-gen.o util.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)
	
ocl-miner: ocl-miner.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS) $(OPENCL_LIBS)
	
clean:
	rm -f $(OBJS) $(PROGS) $(TESTS)
