#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <gmp.h>
#include "rsa.h"
#include "prf.h"
#include "dh.h"
#include "keys.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define KEYLEN 16 // 16 byte length for random key
#define RSALEN 64 // 64 byte length for rsa key
#define SIDLEN 16 // 16 byte length for session ID

/*
Message Encryption(RSA with HMAC):

The process for encrypting messages involves the following steps:
    1. A pseudo-random key is generated and encrypted using RSA to be used as the shared key for symmetric encryption.
    2. The encrypted shared key is sent to the other party.
    3. Encrypt the message using RSA.
    4. Compute the ciphertext as the following: c = ENC(message) HMAC(sessionID | random key).
*/

// Generates a 256 bit random key and writes it to a file
void generateSharedKey(const char *shared_file, RSA_KEY *K)
{
    // Generate random key
    unsigned char buf[KEYLEN];
    int random = randBytes(buf, KEYLEN);
    if (random != 0)
    {
        fprintf(stderr, "Error: Failed generating share key.\n");
        return;
    }
    // Encrypt the pseudo-random key
    unsigned char encrypted[RSALEN];
    size_t encryptedLen = rsa_encrypt(encrypted, buf, KEYLEN, K);
    if (encryptedLen != RSALEN)
    {
        fprintf(stderr, "Error: RSA encryption failed.\n");
        return;
    }
    // Open file to write shared key to
    FILE *file = fopen(shared_file, "w+b");
    if (file == NULL)
    {
        fprintf(stderr, "Error: Unable to open or create the file.\n");
        return;
    }
    // Write key to file
    size_t bytes_written = fwrite(encrypted, 1, RSALEN, file);
    fclose(file);
    if (bytes_written != RSALEN)
    {
        fprintf(stderr, "Error: Failed to write shared key to file.\n");
        return;
    }
    return;
}

// Read shared key from file and write to buffer
void readSharedKey(const char *shared_file, unsigned char *out, RSA_KEY *K)
{
    // Open file to read shared key
    FILE *file = fopen(shared_file, "rb");
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
        fprintf(stderr, "Error: Failed to read shared key to file.\n");
        return;
    }
    // Decrypt the key
    size_t decryptedLen = rsa_decrypt(out, buf, RSALEN, K);
    if (decryptedLen != KEYLEN)
    {
        fprintf(stderr, "Error: RSA decryption failed.\n");
        return;
    }
    return;
}

// Generates the RSA keys and write to public and private files
void generateRSAKeys(const char *public, const char *private)
{
    // Generate the RSA keys
    RSA_KEY K;
    rsa_initKey(&K);
    rsa_keyGen(RSALEN * 8, &K);
    // Open and write public keys to public file
    FILE *pub_file = fopen(public, "w+b");
    if (!pub_file)
    {
        fprintf(stderr, "Failed to open public key file for writing.\n");
        return;
    }
    rsa_writePublic(pub_file, &K);
    fclose(pub_file);
    // Open write private keys to private file
    FILE *pri_file = fopen(private, "w+b");
    if (!pri_file)
    {
        fprintf(stderr, "Failed to open private key file for writing.\n");
        return;
    }
    rsa_writePrivate(pri_file, &K);
    fclose(pri_file);
    // Clean up the key structure
    rsa_shredKey(&K);
}

// Read public key from file
void readPubKeys(const char *public, RSA_KEY *K)
{
    FILE *pub_file = fopen(public, "rb");
    if (!pub_file)
    {
        fprintf(stderr, "Failed to open public key file for reading.\n");
        return;
    }
    rsa_readPublic(pub_file, K);
    fclose(pub_file);
    return;
}

// Read private key from file
void readPriKeys(const char *private, RSA_KEY *K)
{
    FILE *pri_file = fopen(private, "rb");
    if (!pri_file)
    {
        fprintf(stderr, "Failed to open private key file for reading.\n");
        return;
    }
    rsa_readPrivate(pri_file, K);
    fclose(pri_file);
    return;
}

int main()
{
    generateRSAKeys("public.bin", "private.bin");
    RSA_KEY public;
    RSA_KEY private;
    readPubKeys("public.bin", &public);
    readPriKeys("private.bin", &private);
    const char *shared_key_file_path = "shared_key.bin";
    generateSharedKey(shared_key_file_path, &public);
    unsigned char shared_key_read[KEYLEN];
    readSharedKey(shared_key_file_path, shared_key_read, &private);
    printf("Shared key read from file: ");
    for (int i = 0; i < KEYLEN; i++)
    {
        printf("%02X", shared_key_read[i]);
    }
    printf("\n");

    return 0;
}
// gcc -o test protocol.c keys.c dh.c rsa.c prf.c -I/opt/homebrew/Cellar/gmp/6.3.0/include -L/opt/homebrew/Cellar/gmp/6.3.0/lib -lgmp -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
