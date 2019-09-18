// Lib PQ

#include <unistd.h>
#include <sys/socket.h>

#include "dilithium1aes/randombytes.h"
#include "dilithium1aes/params.h"
#include "dilithium1aes/sign.h"
#include "newhope/rngnh.h"
#include "newhope/apinh.h"

#define NBYTES  1024
#define MLEN 59

/****** -> Dilithium ******/
// opt = 1: KeyGen, Sign; opt = 0: Verification
void dilithium1(int sock, int opt)
{
    int ret, j;
    int flag = 0;
    unsigned char buffer[NBYTES];
    unsigned long long mlen, smlen;
    unsigned char m[MLEN];
    unsigned char m2[MLEN + CRYPTO_BYTES_DILI];
    unsigned char sm[MLEN + CRYPTO_BYTES_DILI];
    unsigned char pk[CRYPTO_PUBLICKEYBYTES_DILI];
    unsigned char sk[CRYPTO_SECRETKEYBYTES_DILI];

    // KeyGen and Sign
    if (opt)
    {
      randombytes(m, MLEN);

      crypto_sign_keypair(pk, sk); //KeyGen

      crypto_sign(sm, &smlen, m, MLEN, sk); //Sign

      send(sock, pk, CRYPTO_PUBLICKEYBYTES_DILI, 0);
      send(sock, &smlen, sizeof(smlen), 0);
      send(sock, sm, smlen, 0);
      send(sock, m, MLEN, 0);

      read(sock, &flag, sizeof(flag));

      if (flag)
      {
          ret = read(sock, buffer, NBYTES);
          buffer[ret] = '\0';
          printf("%s\n", buffer);
      }
    }
    // Verification
    else
    {
      read(sock, pk, CRYPTO_PUBLICKEYBYTES_DILI);
      read(sock, &smlen, sizeof(smlen));
      read(sock, sm, smlen);
      read(sock, m, MLEN);

      ret = crypto_sign_open(m2, &mlen, sm, smlen, pk); //Verification

      if(ret) {
          strcpy(buffer, "Verification failed");
          flag = 1;
      }
      else if(mlen != MLEN) {
          strcpy(buffer, "Message lengths don't match");
          flag = 1;
      }
      else
      {
          for(j = 0; j < mlen; ++j) {
              if(m[j] != m2[j]) {
                  strcpy(buffer, "Messages don't match");
                  flag = 1;
              }
          }
      }

      send(sock, &flag, sizeof(flag), 0);

      if(flag) {
          send(sock, buffer, strlen(buffer), 0);
      }
    }

    return;
}
/****** Dilithium <- ******/

/****** -> New Hope ******/
// opt = 1: Server; opt = 0: Client
void newhope1(int sock, int opt)
{
    int ret;
    int flag = 0;
    unsigned char buffer[NBYTES];
    unsigned char pk[CRYPTO_PUBLICKEYBYTES_NH];
    unsigned char sk[CRYPTO_SECRETKEYBYTES_NH];
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES_NH], ss[CRYPTO_BYTES_NH], ss1[CRYPTO_BYTES_NH];

    //KeyGen and Desencapsulate (server)
    if (opt)
    {
      ret = crypto_kem_keypair (pk, sk); //KeyGen

      if(ret)
      {
          strcpy(buffer, "Desencapsultaion failed");
          flag = 1;
          send(sock, buffer, strlen(buffer), 0);
          return;
      }

      send(sock, pk, CRYPTO_PUBLICKEYBYTES_NH, 0);
      read(sock, ct, CRYPTO_CIPHERTEXTBYTES_NH);

      ret = crypto_kem_dec(ss1, ct, sk); //Desencapsulate

      if(ret)
      {
          strcpy(buffer, "Desencapsultaion failed");
          flag = 1;
      }

      if(flag)
      {
          send(sock, buffer, strlen(buffer), 0);
      }
      //AES256 functions
    }
    // Encapsulate
    else
    {
      read(sock, pk, CRYPTO_PUBLICKEYBYTES_NH);

      ret = crypto_kem_enc(ct, ss, pk); // Encapsulate

      if(ret)
      {
          strcpy(buffer, "Encapsultaion failed");
          flag = 1;
      }

      send(sock, ct, sizeof(ct), 0);

      if(flag)
      {
          send(sock, buffer, strlen(buffer), 0);
      }
      //AES256 function
    }
    return;
}
/****** New Hope <- ******/

/****** -> TLS ******/
void TLS(int sock, char *opt, int opt2, int flag)
{



    // Algorithms
    if(strcmp(opt, "NEWHOPE") == 0 || strcmp(opt, "newhope") == 0)
    {
        newhope1(sock, flag);
    }
    else if(strcmp(opt, "DILITHIUM") == 0 || strcmp(opt, "dilithium") == 0)
    {
        dilithium1(sock, flag);
    }
    else if(strcmp(opt, "EXIT") == 0 || strcmp(opt, "exit") == 0)
    {
        break;
    }
    else
    {
        printf("ERROR: %s\n", opt);
    }

    return;
}
/****** TLS <- ******/
