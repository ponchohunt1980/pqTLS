#include <string.h>
#include "apinh.h"
#include "cpapke.h"
#include "paramsnh.h"
#include "rngnh.h"
#include "fips202nh.h"
#include "verify.h"

/*************************************************
* Name:        crypto_kem_keypair_nh
*
* Description: Generates public and private key
*              for CCA secure NewHope key encapsulation
*              mechanism
*
* Arguments:   - unsigned char *pk: pointer to output public key (an already allocated array of CRYPTO_PUBLICKEYBYTES_NH bytes)
*              - unsigned char *sk: pointer to output private key (an already allocated array of CRYPTO_SECRETKEYBYTES_NH bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair_nh(unsigned char *pk, unsigned char *sk)
{
  cpapke_keypair(pk, sk);                                                        /* First put the actual secret key into sk */

  return 0;
}

/*************************************************
* Name:        crypto_kem_enc_nh
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - unsigned char *ct:       pointer to output cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES_NH bytes)
*              - unsigned char *ss:       pointer to output shared secret (an already allocated array of CRYPTO_BYTES_NH bytes)
*              - const unsigned char *pk: pointer to input public key (an already allocated array of CRYPTO_PUBLICKEYBYTES_NH bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc_nh(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{
  unsigned char buf[2*NEWHOPE_SYMBYTES];

  randombytes_nh(buf,NEWHOPE_SYMBYTES);

  shake256_nh(buf,2*NEWHOPE_SYMBYTES,buf,NEWHOPE_SYMBYTES);                         /* Don't release system RNG output */

  cpapke_enc(ct, buf, pk, buf+NEWHOPE_SYMBYTES);                                 /* coins are in buf+NEWHOPE_SYMBYTES_NH */

  shake256_nh(ss, NEWHOPE_SYMBYTES, buf, NEWHOPE_SYMBYTES);                         /* hash pre-k to ss */
  return 0;
}


/*************************************************
* Name:        crypto_kem_dec_nh
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - unsigned char *ss:       pointer to output shared secret (an already allocated array of CRYPTO_BYTES_NH bytes)
*              - const unsigned char *ct: pointer to input cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES_NH bytes)
*              - const unsigned char *sk: pointer to input private key (an already allocated array of CRYPTO_SECRETKEYBYTES_NH bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_dec_nh(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{
  cpapke_dec(ss, ct, sk);

  shake256_nh(ss, NEWHOPE_SYMBYTES, ss, NEWHOPE_SYMBYTES);                          /* hash pre-k to ss */

  return 0;
}
