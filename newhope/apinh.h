#ifndef APINH_H
#define APINH_H

#include "paramsnh.h"

#define CRYPTO_SECRETKEYBYTES_NH  NEWHOPE_CPAKEM_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES_NH  NEWHOPE_CPAKEM_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES_NH NEWHOPE_CPAKEM_CIPHERTEXTBYTES
#define CRYPTO_BYTES_NH           NEWHOPE_SYMBYTES

#if   (NEWHOPE_N == 512)
#define CRYPTO_ALGNAME "NewHope512-CPAKEM"
#elif (NEWHOPE_N == 1024)
#define CRYPTO_ALGNAME "NewHope1024-CPAKEM"
#else
#error "NEWHOPE_N must be either 512 or 1024"
#endif

int crypto_kem_keypair_nh(unsigned char *pk, unsigned char *sk);

int crypto_kem_enc_nh(unsigned char *ct, unsigned char *ss, const unsigned char *pk);

int crypto_kem_dec_nh(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif
