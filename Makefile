CC=gcc

# Delithium
NISTFLAGS+=-march=native -mtune=native -O3 -fomit-frame-pointer
NISTFLAGS+=-DMODE=1 -DUSE_AES
SRCDILI=dilithium1aes/sign.c dilithium1aes/polyvec.c dilithium1aes/poly.c \
	dilithium1aes/packing.c dilithium1aes/ntt.c dilithium1aes/reduce.c dilithium1aes/rounding.c \
	dilithium1aes/fips202.c dilithium1aes/aes256ctr.c
HDRDILI=dilithium1aes/config.h dilithium1aes/api.h dilithium1aes/params.h dilithium1aes/sign.h \
	dilithium1aes/polyvec.h dilithium1aes/poly.h dilithium1aes/packing.h dilithium1aes/ntt.h \
	dilithium1aes/reduce.h dilithium1aes/rounding.h dilithium1aes/symmetric.h \
	dilithium1aes/dilithium1aes/fips202.h dilithium1aes/aes256ctr.h

ALL_OBJ = dilithium1aes.o 

all: $(ALL_OBJ)
	$(CC) -o $(ALL_OBJ) $(NISTFLAGS) tlspq
