#ifndef FIPS202NH_H
#define FIPS202NH_H

#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

void shake128_absorb_nh(uint64_t *s, const unsigned char *input, unsigned long long inputByteLen);
void shake128_squeezeblocks_nh(unsigned char *output, unsigned long long nblocks, uint64_t *s);
void shake256_nh(unsigned char *output, unsigned long long outputByteLen, const unsigned char *input, unsigned long long inputByteLen);

#endif
