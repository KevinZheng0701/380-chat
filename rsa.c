#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "rsa.h"

#define RSALEN 128

int generateRSAKeys(const char *public, const char *private)
{
    RSA *keys = RSA_new();
    if (!keys)
    {
        fprintf(stderr, "Failed to create RSA object.\n");
        return 0;
    }
    BIGNUM *e = BN_new();
    if (!e)
    {
        fprintf(stderr, "Failed to create BIGNUM object.\n");
        RSA_free(keys);
        return 0;
    }
    BN_set_word(e, RSA_F4); /* e = 65537 */
    int r = RSA_generate_key_ex(keys, RSALEN * 8, e, NULL);
    if (r != 1)
    {
        fprintf(stderr, "Failed to generate RSA key pair.\n");
        RSA_free(keys);
        BN_free(e);
        return 0;
    }
    FILE *pub_file = fopen(public, "wb");
    if (!pub_file)
    {
        fprintf(stderr, "Failed to open public key file for writing\n");
        RSA_free(keys);
        BN_free(e);
        return 0;
    }
    PEM_write_RSAPublicKey(pub_file, keys);
    fclose(pub_file);
    FILE *priv_file = fopen(private, "wb");
    if (!priv_file)
    {
        fprintf(stderr, "Failed to open private key file for writing\n");
        RSA_free(keys);
        BN_free(e);
        return 0;
    }
    PEM_write_RSAPrivateKey(priv_file, keys, NULL, NULL, 0, NULL, NULL);
    fclose(priv_file);
    RSA_free(keys);
    BN_free(e);
    return 1;
}

// Encrypt a message using RSA public key
size_t rsaEncrypt(const char *public, const unsigned char *in, size_t inLen,
                  unsigned char *out)
{
    FILE *file = fopen(public, "rb");
    if (!file)
    {
        fprintf(stderr, "Failed to open public key file for reading.\n");
        return 0;
    }
    RSA *key = PEM_read_RSAPublicKey(file, NULL, NULL, NULL);
    fclose(file);
    if (!key)
    {
        fprintf(stderr, "Failed to read public key.\n");
        return 0;
    }
    size_t maxEncryptSize = RSALEN - 42; // Max size for RSA with OAEP
    if (inLen > maxEncryptSize)
    {
        fprintf(stderr, "Input data size exceeds the maximum allowed for RSA encryption.\n");
        return 0;
    }
    size_t outLen = RSA_public_encrypt(inLen, in, out, key, RSA_PKCS1_OAEP_PADDING);
    if (outLen == -1)
    {
        fprintf(stderr, "Failed to encrypt message.\n");
        RSA_free(key);
        return 0;
    }
    RSA_free(key);
    return outLen;
}

// Decrypt a message using RSA private key
size_t rsaDecrypt(const char *private, const unsigned char *in, size_t inLen,
                  unsigned char *out)
{
    FILE *file = fopen(private, "rb");
    if (!file)
    {
        fprintf(stderr, "Failed to open private key file for reading.\n");
        return 0;
    }
    RSA *key = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
    fclose(file);
    if (!key)
    {
        fprintf(stderr, "Failed to read private key.\n");
        return 0;
    }
    size_t outLen = RSA_private_decrypt(inLen, in, out, key, RSA_PKCS1_OAEP_PADDING);
    if (outLen == -1)
    {
        fprintf(stderr, "Failed to decrypt message.\n");
        RSA_free(key);
        return 0;
    }
    RSA_free(key);
    return outLen;
}