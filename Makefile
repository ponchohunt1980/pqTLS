CC = /usr/bin/gcc
LDFLAGS = -lcrypto
NISTFLAGS += -march=native -mtune=native -O3 -fomit-frame-pointer
NISTFLAGS += -DMODE=1 -DUSE_AES


SOURCES = newhope/kem.c newhope/cpapke.c newhope/fips202nh.c newhope/nttnh.c newhope/polynh.c newhope/precomp.c newhope/reducenh.c newhope/rngnh.c newhope/verify.c  pq.c dilithium1aes/sign.c dilithium1aes/polyvec.c dilithium1aes/poly.c dilithium1aes/packing.c dilithium1aes/ntt.c dilithium1aes/reduce.c dilithium1aes/rounding.c dilithium1aes/fips202.c dilithium1aes/aes256ctr.c

HEADERS = newhope/apinh.h newhope/cpapke.h newhope/fips202nh.h newhope/nttnh.h newhope/paramsnh.h newhope/polynh.h newhope/reducenh.h newhope/rngnh.h newhope/verify.h pq.h dilithium1aes/config.h dilithium1aes/api.h dilithium1aes/params.h dilithium1aes/sign.h dilithium1aes/polyvec.h dilithium1aes/poly.h dilithium1aes/packing.h dilithium1aes/ntt.h dilithium1aes/reduce.h dilithium1aes/rounding.h dilithium1aes/symmetric.h dilithium1aes/fips202.h dilithium1aes/aes256ctr.h

all: client server
client: client_tls_pq.c dilithium1aes/rng.c $(SOURCES) dilithium1aes/rng.h $(HEADERS)
	$(CC) $(NISTFLAGS) $< dilithium1aes/rng.c $(SOURCES) -o $@ $(LDFLAGS)

server: server_tls_pq.c dilithium1aes/rng.c $(SOURCES) dilithium1aes/rng.h $(HEADERS)
	$(CC) $(NISTFLAGS) $< dilithium1aes/rng.c $(SOURCES) -o $@ $(LDFLAGS)

.PHONY: clean

clean:
	-rm client
