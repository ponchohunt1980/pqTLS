CC = /usr/bin/gcc
LDFLAGS = -lcrypto

SOURCES = kem.c cpapke.c fips202nh.c nttnh.c polynh.c precomp.c reducenh.c rngnh.c verify.c PQCgenKAT_kem.c
HEADERS = apinh.h cpapke.h fips202nh.h nttnh.h paramsnh.h polynh.h reducenh.h rngnh.h verify.h

PQCgenKAT_kem: $(SOURCES) $(HEADERS)
	$(CC) $(SOURCES) -o $@ $(LDFLAGS)

.PHONY: clean

clean:
	-rm PQCgenKAT_kem
