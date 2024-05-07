#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <gmp.h>
#include "protocol.h"
#include "rsa.h"
#include "prf.h"
#include "hmac.h"

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
    4. Compute the hmac section using the generated hmackey on the sessionID and the shared key.
    4. Compute the ciphertext as the following: c = ENC(message) HMAC(sessionID | random key).

Message Decryption:

Decryption of messages involves the following steps:
    1. The ciphertext is broken up into the encrypted message and the HMAC.
    2. Decrpyt the secret key to get the pseudo-random key from the other party.
    3. Compute the hash along with the other party's sessionID.
    4. Verify that the hash is consisent with the received HMAC.
    5. Once verified, decrypt the message using RSA.
*/

// Generates a 128 bit random key and writes the encrypted version to a file
void generateSharedKey(const char *shared_file, const char *public)
{
    // Generate random key
    unsigned char buf[KEYLEN];
    if (randBytes(buf, KEYLEN) != 0)
    {
        fprintf(stderr, "Failed generating shared key.\n");
        return;
    }
    // Encrypt the pseudo-random key
    unsigned char encrypted[RSALEN];
    size_t encryptedLen = rsaEncrypt(public, buf, KEYLEN, encrypted);
    if (encryptedLen != RSALEN)
    {
        fprintf(stderr, "RSA encryption failed.\n");
        return;
    }
    // Open file to write shared key to
    FILE *file = fopen(shared_file, "wb");
    if (file == NULL)
    {
        fprintf(stderr, "Unable to open or create the file.\n");
        return;
    }
    // Write key to file
    size_t bytes_written = fwrite(encrypted, 1, RSALEN, file);
    fclose(file);
    if (bytes_written != RSALEN)
    {
        fprintf(stderr, "Failed to write shared key to file.\n");
        return;
    }
}

// Read shared key from file and write to buffer
void readSharedKey(const char *shared_file, unsigned char *out, const char *private)
{
    // Open file to read shared key
    FILE *file = fopen(shared_file, "rb");
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
        fprintf(stderr, "Failed to read shared key to file.\n");
        return;
    }
    // Decrypt the key
    size_t decryptedLen = rsaDecrypt(private, buf, RSALEN, out);
    if (decryptedLen != KEYLEN)
    {
        fprintf(stderr, "RSA decryption failed.\n");
        return;
    }
    return;
}

// Compute the hmac on sessionID and random key
void computeHMAC(unsigned char *out, unsigned char *sessionID, const char *shared_file, unsigned char *hmacKey, const char *private)
{
    // Obtain shared key
    unsigned char sharedKey[KEYLEN];
    readSharedKey(shared_file, sharedKey, private);
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
    // Generate the shared key
    generateSharedKey(shared_file, public);
    // Perform encryption on the message
    unsigned char encrypted[RSALEN];
    size_t encryptedLen = rsaEncrypt(public, msg, strlen(msg), encrypted);
    if (encryptedLen != RSALEN)
    {
        fprintf(stderr, "RSA encryption failed.\n");
        return;
    }
    // Obtain hmackey
    unsigned char hmackey[HMACKEYLEN];
    readHmacKey(hmacfile, hmackey, private);
    // Compute the hmac
    unsigned char hmac[HMACKEYLEN];
    computeHMAC(hmac, sessionID, shared_file, hmackey, private);
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
    // Read the shared key
    unsigned char shared[KEYLEN];
    readSharedKey(shared_file, shared, private);
    // Read the HMAC key
    unsigned char hmackey[HMACKEYLEN];
    readHmacKey(hmacfile, hmackey, private);
    // Compute the HMAC to ensure message integrity
    unsigned char computedhmac[HMACKEYLEN];
    computeHMAC(computedhmac, sessionID, shared_file, hmackey, private);
    // Verify the computed HMAC with the received HMAC
    if (memcmp(incominghmac, computedhmac, HMACKEYLEN) != 0)
    {
        fprintf(stderr, "HMAC verification failed.\n");
        return;
    }
    // Perform decryption on the message
    size_t decryptedLen = rsaDecrypt(private, ciphertext, RSALEN, out);
    if (decryptedLen == 0)
    {
        fprintf(stderr, "RSA decryption failed.\n");
        return;
    }
    return;
}

/*
int main()
{
    const char *shared_file = "shared_key.pem";
    const char *hmac_file = "hmac_key.pem";
    const char *public_key_file = "public_key.pem";
    const char *private_key_file = "private_key.pem";
    printf("Generating rsa keys\n");
    generateRSAKeys(public_key_file, private_key_file);
    printf("Keys generated\n");
    printf("Generating hmackey\n");
    generateHmacKey(hmac_file, public_key_file);
    printf("Sucessful generation of hmackey\n");
    unsigned char hmackey[HMACKEYLEN];
    readHmacKey(hmac_file, hmackey, private_key_file);
    printf("Generating session token.\n");
    unsigned char sessionID[SIDLEN];
    randBytes(sessionID, SIDLEN);
    printf("Sucessfully session token.\n");
    unsigned char pt[] = "Hello world this is so cool LOLOLOLOL.";
    unsigned char ct[RSALEN];
    unsigned char dt[strlen((const char *)pt) + 1];
    printf("Plaintext: %s\n", pt);
    printf("\n");
    encryptMsg(shared_file, hmac_file, public_key_file, private_key_file, (const char *)pt, ct, sessionID);
    decryptMsg(shared_file, hmac_file, private_key_file, (const char *)ct, dt, sessionID);
    printf("Decryption: %s\n", dt);
    return 0;
}
*/

// gcc -o test protocol.c hmac_sha.c keys.c dh.c rsa_ssl.c prf.c -I/opt/homebrew/Cellar/gmp/6.3.0/include -L/opt/homebrew/Cellar/gmp/6.3.0/lib -lgmp -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
