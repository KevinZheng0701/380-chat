#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "prf.h"
#include "rsa.h"

#define RSALEN 128                                // 128 byte length for rsa key
#define HMACKEYLEN 32                             // 32 byte length for the hmac key
#define KDFKEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I" // KDF key

// Generates a hmackey, if entropy is given apply the KDF key
int hmacKeyGen(unsigned char *hmacKey, unsigned char *entropy, size_t len)
{
    if (entropy != NULL)
        HMAC(EVP_sha256(), KDFKEY, strlen(KDFKEY), entropy, len, hmacKey, NULL);
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
void generateHmacKey(const char *hmacfile, RSA_KEY *K)
{
    // Create entropy
    unsigned char entropy[HMACKEYLEN];
    int random = randBytes(entropy, HMACKEYLEN);
    if (random != 0)
    {
        fprintf(stderr, "Error: Failed generating hmac key.\n");
        return;
    }
    // Generate hmackey
    unsigned char buf[HMACKEYLEN];
    hmacKeyGen(buf, NULL, HMACKEYLEN);
    // Encrypt hmac key
    unsigned char encrypted[RSALEN];
    size_t encryptedLen = rsa_encrypt(encrypted, buf, HMACKEYLEN, K);
    if (encryptedLen != RSALEN)
    {
        fprintf(stderr, "Error: RSA encryption failed.\n");
        return;
    }
    // Open file to write the hmackey to
    FILE *file = fopen(hmacfile, "w+b");
    if (file == NULL)
    {
        fprintf(stderr, "Error: Unable to open or create the file.\n");
        return;
    }
    // Write the encrypted key to file
    size_t bytes_written = fwrite(encrypted, 1, RSALEN, file);
    fclose(file);
    if (bytes_written != RSALEN)
    {
        fprintf(stderr, "Error: Failed to write shared key to file.\n");
        return;
    }
    return;
}

// Read hmac key from file and write to buffer
void readHmacKey(const char *hmacfile, unsigned char *out, RSA_KEY *K)
{
    // Open file to read hmackey
    FILE *file = fopen(hmacfile, "rb");
    if (file == NULL)
    {
        fprintf(stderr, "Error: Unable to open and read the file.\n");
        return;
    }
    // Write key to buffer
    unsigned char buf[RSALEN];
    size_t bytes_read = fread(buf, 1, RSALEN, file);
    fclose(file);
    if (bytes_read != RSALEN)
    {
        fprintf(stderr, "Error: Failed to read hmackey to file.\n");
        return;
    }
    // Decrypt the key
    size_t decryptedLen = rsa_decrypt(out, buf, RSALEN, K);
    if (decryptedLen != HMACKEYLEN)
    {
        fprintf(stderr, "Error: RSA decryption failed.\n");
        return;
    }
    return;
}