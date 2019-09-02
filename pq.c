// Lib PQ

#include <unistd.h> 
#include <sys/socket.h> 

#define NBYTES  1024

/****** -> NewHope ******/
#include "newhope/rngnh.h"
#include "newhope/apinh.h"
/****** NewHope <- ******/

/****** -> Dilithium ******/
#include "dilithium1aes/randombytes.h"
#include "dilithium1aes/params.h"
#include "dilithium1aes/sign.h"

#define MLEN 59

// opt = 0: KeyGen, Sign; opt = 1: Verification
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

    // Verification
    if (opt)
    {
        read(sock, pk, CRYPTO_PUBLICKEYBYTES_DILI);
        read(sock, &smlen, sizeof(smlen));
        read(sock, sm, smlen);
        read(sock, m, MLEN);

        // Verification
        ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);

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
    else
    {
        randombytes(m, MLEN);

        crypto_sign_keypair(pk, sk);

        crypto_sign(sm, &smlen, m, MLEN, sk);

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

    return;
}
/****** Dilithium <- ******/

/****** New Hope <- ******/
void newhopekeygen(unsigned char pk, unsigned char sk)
{
    int flag;
    
    if (flag = crypto_kem_keypair(pk, sk) !=0)
    {
        printf("crypto_kem_keypair returned <%d>\n", flag);
    }
}

void newhope_enc (unsigned char ct, unsigned char ss, unsigned char pk)
{
    int flag;
    
    if (flag = crypto_kem_enc(ct, ss, pk) != 0)
    {
        printf("crypto_kem_enc returned <%d>\n", flag);
    }
}

void newhope_dec(unsigned char ss1, unsigned char ct, unsigned char pk)
{
    int flag;
    
    if (flag = crypto_kem_dec(ss1, ct, sk) != 0)
    {
        printf("crypto_kem_dec returned <%d>\n", flag);
    }
}
void newhope1(int sock, int opt)
{
       
}
/****** New Hope <- ******/

/****** -> TLS ******/
void TLS(int sock, char *opt, int flag)
{
    unsigned char sk[CRYPTO_SECRETKEYBYTES_NH]CRYPTO_BYTES_NH, pk[CRYPTO_PUBLICKEYBYTES_NH];
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES_NH], ss[CRYPTO_BYTES_NH], ss1[CRYPTO_BYTES_NH];
    
    // Algorithms
    if(strcmp(opt, "NEWHOPE") == 0 || strcmp(opt, "newhope") == 0)
    {
        if(strcmp(opt_nh, "keygen") == 0 || strcm(opt_nh, "KEYGEN") == 0)
        {
            //KeyGen
            newhopekeygen(unsigned char pk, unsigned char sk);
        }
        else if(opt_nh,)
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
