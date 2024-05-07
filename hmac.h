#pragma once
#include <stddef.h>

// This file includes HMAC key generation and hashing using sha256
int hmacKeyGen(unsigned char *hmacKey, unsigned char *entropy, size_t len);
void sha256_hash(unsigned char *in, unsigned char *out, unsigned char *hmacKey, size_t len);
void generateHmacKey(const char *hmacfile, const char *public);
void readHmacKey(const char *hmacfile, unsigned char *out, const char *private);