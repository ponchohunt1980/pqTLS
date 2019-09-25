#ifndef OPENSSL_AES_H
#define OPENSSL_AES_H

// This is important
#define BS 4092

void handleErrors(void);
void encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);

#endif
