// Lib PQ

#include <unistd.h>
#include <sys/socket.h>
#include <string.h>

#include "dilithium1aes/randombytes.h"
#include "dilithium1aes/params.h"
#include "dilithium1aes/sign.h"
#include "newhope/rngnh.h"
#include "newhope/apinh.h"
#include "opensslaes.h"

#define NBYTES  1024
#define MLEN 59

/****** -> Dilithium ******/
// opt = 1: KeyGen, Sign; opt = 0: Verification
int dilithium1(int sock, int opt)
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
    int t;

    // KeyGen and Sign
    // opt = 1 | send pk and cert with sign
    if (opt)
    {
      randombytes(m, MLEN);

      crypto_sign_keypair(pk, sk); //KeyGen

      crypto_sign(sm, &smlen, m, MLEN, sk); //Sign

      // read public key and cert from a file input
      send(sock, pk, CRYPTO_PUBLICKEYBYTES_DILI, 0);
      send(sock, &smlen, sizeof(smlen), 0);
      send(sock, sm, smlen, 0);
      send(sock, m, MLEN, 0);

      t = read(sock, &flag, sizeof(flag));

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
      t = read(sock, pk, CRYPTO_PUBLICKEYBYTES_DILI);
      t = read(sock, &smlen, sizeof(smlen));
      t = read(sock, sm, smlen);
      t = read(sock, m, MLEN);

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

    return flag;
}
/****** Dilithium <- ******/

/****** -> New Hope ******/
// opt = 1: Server; opt = 0: Client
int newhope1(int sock, int opt, unsigned char *ss)
{
    int ret;
    int flag = 0;
    unsigned char buffer[NBYTES];
    unsigned char pk[CRYPTO_PUBLICKEYBYTES_NH];
    unsigned char sk[CRYPTO_SECRETKEYBYTES_NH];
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES_NH]; //, ss[CRYPTO_BYTES_NH], ss1[CRYPTO_BYTES_NH];
    int t;

    //KeyGen and Desencapsulate (server)
    if (opt)
    {
      ret = crypto_kem_keypair_nh(pk, sk); //KeyGen

      if(ret)
      {
          strcpy(buffer, "Desencapsultaion failed");
          flag = 1;
          send(sock, buffer, strlen(buffer), 0);
          return flag;
      }

      send(sock, pk, CRYPTO_PUBLICKEYBYTES_NH, 0);
      t = read(sock, ct, CRYPTO_CIPHERTEXTBYTES_NH);

      ret = crypto_kem_dec_nh(ss, ct, sk); //Desencapsulate

      if(ret)
      {
          strcpy(buffer, "Desencapsultaion failed");
          flag = 1;
      }

      if(flag)
      {
          send(sock, buffer, strlen(buffer), 0);
      }
    }
    else // Encapsulate
    {
      t = read(sock, pk, CRYPTO_PUBLICKEYBYTES_NH);

      ret = crypto_kem_enc_nh(ct, ss, pk); // Encapsulate

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
    }

    return flag;
}
/****** New Hope <- ******/

/****** -> AES ******/
void symmetric_enc_dec(int sock, int flag, unsigned char *ss, unsigned char *msg)
{
  int t;
    // AES
  /* A 256 bit key */
  unsigned char key[32];
  /* A 128 bit IV */
  unsigned char iv[16];
  memcpy(key, ss, 32);
  memcpy(iv, ss+32, 16);

  int decryptedtext_len;
  /*
    * Buffer for ciphertext. Ensure the buffer is long enough for the
    * ciphertext which may be longer than the plaintext, depending on the
    * algorithm and mode.
  */
  unsigned char ciphertext[BS];
  /* Buffer for the decrypted text */
  unsigned char decryptedtext[BS];

  printf("0x%s\n", ss);

  // Server
  if (flag)
  {
    t = read(sock, ciphertext, BS);

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, strlen(ciphertext), key, iv,
                                decryptedtext);
    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';
    printf("%s\n", decryptedtext);
  }
  else // client
  {
    // Message 
    //randombytes(msg, NBYTES);

    /* Encrypt the plaintext */
    encrypt(msg, strlen(msg), key, iv, ciphertext);

    // Testing
    //BIO_dump_fp (stdout, (const char *)ciphertext, strlen(ciphertext_len);

    send(sock, ciphertext, strlen(ciphertext), 0);
  }

  return;
}
/****** AES <- ******/

void safe_channel(int sock, int flag)
{
  unsigned char ss[CRYPTO_BYTES_NH];
  // Shared key
  if (newhope1(sock, flag, ss))
  { return; }

  // File or message
  unsigned char msg[NBYTES] = "Hola mundo (client)";

  if (flag == 0)
  {
    // Message 
    randombytes(msg, BS);
  }

  symmetric_enc_dec(sock, flag, ss, msg);  
}

/****** -> TLS ******/
void TLS(int sock, char *opt, int opt2, int flag)
{
  //opt2 = 0 no sign || opt2 = 1 server cert verify || opt2 = 2 both verify
  if (opt2 == 0)//no sign
  {
    safe_channel(sock, flag);
  }
  else if (opt2 == 1 || flag == 0)//verificacion server cert
  {
    if (dilithium1(sock, flag))
    {
      return;
    }
    safe_channel(sock, flag);
  }
  else if (opt2 == 1 || flag ==1) // Both
  {
    if (dilithium1(sock, flag) || dilithium1(sock, ~flag))
    {
      return;
    }
    safe_channel(sock, flag);
  }
  else
  { }

  return;
}
/****** TLS <- ******/
