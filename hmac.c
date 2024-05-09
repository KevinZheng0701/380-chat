#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "prf.h"
#include "rsa.h"
#include "hmac.h"

#define RSALEN 128                                // 128 byte length for rsa key
#define HMACKEYLEN 32                             // 32 byte length for the hmac key
#define KDFKEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I" // KDF key

// Generates a hmackey, if entropy is given apply the KDF key
int hmacKeyGen(unsigned char *hmacKey, unsigned char *entropy, size_t len)
{
    if (entropy != NULL)
        HMAC(EVP_sha256(), KDFKEY, 32, entropy, len, hmacKey, NULL);
    else
        randBytes(hmacKey, len);
    return 0;
}

// Performs the hashing with the hmackey
void sha256_hash(unsigned char *in, unsigned char *out, unsigned char *hmacKey, size_t len)
{
    HMAC(EVP_sha256(), hmacKey, HMACKEYLEN, in, len, out, NULL);
}

// Generates a hmackey and stores in a file
void generateHmacKey(const char *hmacfile, const char *public)
{
    // Create entropy
    unsigned char entropy[HMACKEYLEN];
    randBytes(entropy, HMACKEYLEN);
    // Generate hmackey
    unsigned char buf[HMACKEYLEN];
    hmacKeyGen(buf, entropy, HMACKEYLEN);
    // Encrypt hmac key
    unsigned char encrypted[RSALEN];
    size_t encryptedLen = rsaEncrypt(public, (const unsigned char *)buf, HMACKEYLEN, encrypted);
    if (encryptedLen != RSALEN)
    {
        fprintf(stderr, "RSA encryption failed.\n");
        return;
    }
    // Open file to write the hmackey to
    FILE *file = fopen(hmacfile, "wb");
    if (file == NULL)
    {
        fprintf(stderr, "Unable to open or create the file.\n");
        return;
    }
    // Write the encrypted key to file
    size_t bytes_written = fwrite(encrypted, 1, RSALEN, file);
    fclose(file);
    if (bytes_written != RSALEN)
    {
        fprintf(stderr, " Failed to write shared key to file.\n");
        return;
    }
    return;
}

// Read hmac key from file and write to buffer
void readHmacKey(const char *hmacfile, unsigned char *out, const char *private)
{
    // Open file to read hmackey
    FILE *file = fopen(hmacfile, "rb");
    if (file == NULL)
    {
        fprintf(stderr, "Unable to open and read the file.\n");
        return;
    }
    // Write key to buffer
    unsigned char buf[RSALEN];
    size_t bytes_read = fread(buf, 1, RSALEN, file);
    fclose(file);
    if (bytes_read != RSALEN)
    {
        fprintf(stderr, "Failed to read hmackey to file.\n");
        return;
    }
    // Decrypt the key
    size_t decryptedLen = rsaDecrypt(private, (const unsigned char *)buf, RSALEN, out);
    if (decryptedLen != HMACKEYLEN)
    {
        fprintf(stderr, "RSA decryption failed.\n");
        return;
    }
    return;
}