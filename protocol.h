#pragma once

void generateSharedKey(const char *shared_file, const char *public);
void readSharedKey(const char *shared_file, unsigned char *out, const char *private);
void computeHMAC(unsigned char *out, unsigned char *sessionID, const char *shared_file, unsigned char *hmacKey, const char *private);
void encryptMsg(const char *shared_file, const char *hmacfile, const char *public, const char *private, const char *msg, unsigned char *out, unsigned char *sessionID);
void decryptMsg(const char *shared_file, const char *hmacfile, const char *private, const char *ciphertext, unsigned char *out, unsigned char *sessionID);