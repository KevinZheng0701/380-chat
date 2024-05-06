#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <gmp.h>
#include "rsa.h"
#include "prf.h"
#include "dh.h"
#include "keys.h"
#include "hmac_sha.h"

#define KEYLEN 16     // 16 byte length for random key
#define RSALEN 128    // 128 byte length for rsa key
#define SIDLEN 16     // 16 byte length for session ID
#define HMACKEYLEN 32 // 32 byte length for the hmac key

/*
Message Encryption(RSA with HMAC):

The process for encrypting messages involves the following steps:
    1. A pseudo-random key is generated and encrypted using RSA to be used as the shared key for symmetric encryption.
    2. The encrypted shared key is sent to the other party.
    3. Encrypt the message using RSA.
    4. Compute the ciphertext as the following: c = ENC(message) HMAC(sessionID | random key).
*/

// Generates a 128 bit random key and writes the encrypted version to a file
void generateSharedKey(const char *shared_file, RSA_KEY *K)
{
    // Generate random key
    unsigned char buf[KEYLEN];
    if (randBytes(buf, KEYLEN) != 0)
    {
        fprintf(stderr, "Error: Failed generating shared key.\n");
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
        printf("failed");
        fprintf(stderr, "Failed to open private key file for reading.\n");
        return;
    }
    rsa_readPrivate(pri_file, K);
    fclose(pri_file);
    return;
}

// Set up rsa key files
void rsaSetup(const char *public, const char *private, RSA_KEY *publicKey, RSA_KEY *privateKey)
{
    generateRSAKeys(public, private);
    readPubKeys(public, publicKey);
    readPriKeys(private, privateKey);
}

// Set up hmackey in a file
void hmacSetup(const char *hmacfile, RSA_KEY *K)
{
    generateHmacKey(hmacfile, K);
}

// Compute the hmac on sessionID and random key
void computeHMAC(unsigned char *out, unsigned char *sessionID, const char *shared_file, unsigned char *hmacKey, RSA_KEY *K)
{
    // Obtain shared key
    unsigned char sharedKey[KEYLEN];
    readSharedKey(shared_file, sharedKey, K);
    // Concat the session id with the random key
    unsigned char concat[KEYLEN + SIDLEN];
    memcpy(concat, sessionID, SIDLEN);
    memcpy(concat + SIDLEN, sharedKey, KEYLEN);
    // Compute the hmac
    sha256_hash(concat, out, hmacKey, KEYLEN + SIDLEN);
}

// Perform the entire message encryption
void encryptMsg(const char *shared_file, const char *hmacfile, const char *public, const char *private, const char *msg, unsigned char *out, unsigned char *sessionID)
{
    // Generate encrypted shared key
    RSA_KEY publicKey;
    readPubKeys(public, &publicKey);
    generateSharedKey(shared_file, &publicKey);
    // Perform encryption on the message
    unsigned char encrypted[RSALEN];
    rsa_encrypt(encrypted, (unsigned char *)msg, strlen(msg), &publicKey);
    rsa_shredKey(&publicKey);
    // Obtain private key to decrypt hmackey
    RSA_KEY privateKey;
    readPriKeys(private, &privateKey);
    // Obtain hmackey
    unsigned char hmackey[HMACKEYLEN];
    readHmacKey(hmacfile, hmackey, &privateKey);
    // Compute the hmac
    unsigned char hmac[HMACKEYLEN];
    computeHMAC(hmac, sessionID, shared_file, hmackey, &privateKey);
    rsa_shredKey(&privateKey);
    // Form the ciphertext
    memcpy(out, encrypted, RSALEN);
    memcpy(out + RSALEN, hmac, HMACKEYLEN);
    return;
}

// Perform the entire message decryption
void decryptMsg(const char *shared_file, const char *hmacfile, const char *private, const char *ciphertext, unsigned char *out, unsigned char *sessionID)
{
    // Break the ciphertext into two parts
    unsigned char encrypted[RSALEN];
    unsigned char incominghmac[HMACKEYLEN];
    memcpy(encrypted, ciphertext, RSALEN);
    memcpy(incominghmac, ciphertext + RSALEN, HMACKEYLEN);
    // Read the private key
    RSA_KEY privateKey;
    readPriKeys(private, &privateKey);
    // Read the shared key
    unsigned char shared[KEYLEN];
    readSharedKey(shared_file, shared, &privateKey);
    // Read the HMAC key
    unsigned char hmackey[HMACKEYLEN];
    readHmacKey(hmacfile, hmackey, &privateKey);
    // Compute the HMAC to ensure message integrity
    unsigned char computedhmac[HMACKEYLEN];
    computeHMAC(computedhmac, sessionID, shared_file, hmackey, &privateKey);
    // Verify the computed HMAC with the received HMAC
    if (memcmp(incominghmac, computedhmac, HMACKEYLEN) != 0)
    {
        fprintf(stderr, "Error: HMAC verification failed.\n");
        rsa_shredKey(&privateKey);
        return;
    }
    // Perform decryption on the message
    rsa_decrypt(out, encrypted, RSALEN, &privateKey);
    // Clear the private key from memory
    rsa_shredKey(&privateKey);
}

/*
The process for encrypting messages involves the following steps:
    1. A pseudo-random key is generated and encrypted using RSA to be used as the shared key for symmetric encryption.
    2. The encrypted shared key is sent to the other party.
    3. Encrypt the message using RSA.
    4. Compute the ciphertext as the following: c = ENC(message) HMAC(sessionID | random key).

    Decryption of messages involves the following steps:
    1. The ciphertext is broken up into the encrypted message and the HMAC.
    2. Decrpyt the secret key to get the pseudo-random key from the other party.
    3. Compute the hash along with the other party's sessionID.
    4. Verify that the hash is consisent with the received HMAC.
    5. Once verified, decrpyt the message using RSA.
*/

int main()
{
    const char *shared_file = "shared_key.bin";
    const char *hmac_file = "hmac.bin";
    const char *public_key_file = "public.bin";
    const char *private_key_file = "private.bin";
    generateRSAKeys(public_key_file, private_key_file);
    RSA_KEY public;
    RSA_KEY private;
    readPubKeys(public_key_file, &public);
    readPriKeys(private_key_file, &private);

    unsigned char sessionID[SIDLEN];
    // Set a random session ID
    if (randBytes(sessionID, SIDLEN) != 0)
    {
        fprintf(stderr, "Error: Failed generating session ID.\n");
        return 1;
    }
    hmacSetup("hmac.bin", &public);

    unsigned char pt[] = "Hello world this is so cool.";
    unsigned char ct[RSALEN];
    // Ensure enough space for the null terminator
    unsigned char dt[strlen(pt)];

    // printf("Plaintext: %s\n", pt);

    printf("\n");
    // Encrypt the plaintext
    encryptMsg(shared_file, hmac_file, public_key_file, private_key_file, pt, ct, sessionID);

    // Decrypt the ciphertext
    decryptMsg(shared_file, hmac_file, private_key_file, ct, dt, sessionID);

    // printf("Decryption: %s\n", dt);

    return 0;
}
// gcc -o test protocol.c hmac_sha.c keys.c dh.c rsa.c prf.c -I/opt/homebrew/Cellar/gmp/6.3.0/include -L/opt/homebrew/Cellar/gmp/6.3.0/lib -lgmp -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
