#ifndef NTTNH_H
#define NTTNH_H

#include "inttypes.h"

extern uint16_t omegas_inv_bitrev_montgomery[];
extern uint16_t gammas_bitrev_montgomery[];
extern uint16_t gammas_inv_montgomery[];

void bitrev_vector(uint16_t* poly);
void mul_coefficients(uint16_t* poly, const uint16_t* factors);
void ntt_nh(uint16_t* poly, const uint16_t* omegas);

#endif
