#pragma once
#include <stddef.h>

int generateRSAKeys(const char *public, const char *private);
size_t rsaEncrypt(const char *public, const unsigned char *in, size_t inLen, unsigned char *out);
size_t rsaDecrypt(const char *private, const unsigned char *in, size_t inLen, unsigned char *out);