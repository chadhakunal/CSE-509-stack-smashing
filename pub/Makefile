CC=gcc
CFLAGS=-g -Wall -z execstack -DGRP=$(GRP_ID) -DLEN1=1124 -DLEN2=128 -DLEN3=512 -DRANDOM=0

all: vuln vuln.dis driver_auth_db driver_return_to_helper driver_return_to_injected_code driver_partial_overflow_attack driver_heap_overflow

vuln: vuln.o my_malloc.o
	$(CC) $(CFLAGS) -o vuln vuln.o my_malloc.o

vuln.o: padding.h vuln.c my_malloc.h
	$(CC) $(CFLAGS) -c vuln.c

vuln.dis: vuln
	rm -f vuln.dis
	objdump -S vuln > vuln.dis

my_malloc.o: my_malloc.h my_malloc.c
	$(CC) $(CFLAGS)  -c my_malloc.c

driver_auth_db: driver_auth_db.c
	$(CC) -O $(CFLAGS) -o driver_auth_db driver_auth_db.c

driver_return_to_helper: driver_return_to_helper.c
	$(CC) -O $(CFLAGS) -o driver_return_to_helper driver_return_to_helper.c

driver_return_to_injected_code: driver_return_to_injected_code.c
	$(CC) -O $(CFLAGS) -o driver_return_to_injected_code driver_return_to_injected_code.c

driver_partial_overflow_attack: driver_partial_overflow_attack.c
	$(CC) -O $(CFLAGS) -o driver_partial_overflow_attack driver_partial_overflow_attack.c

driver_heap_overflow: driver_heap_overflow.c
	$(CC) -O $(CFLAGS) -o driver_heap_overflow driver_heap_overflow.c

padding.h:
	./mkpad $(GRP_ID)

clean:
	rm -f *.o *.dis padding.h driver_auth_db driver_return_to_helper driver_return_to_injected_code driver_partial_overflow_attack vuln
