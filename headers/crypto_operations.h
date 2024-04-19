#ifndef CRYPTO_OPERATIONS_H
#define CRYPTO_OPERATIONS_H

#include <stdio.h>
#include <tss2/tss2_fapi.h>
#include <string.h>

int encryptData(FAPI_CONTEXT* fapiContext, TSS2_RC* rc, const char* dataToEncrypt, const char* keyPath, uint8_t** cipherText, size_t* cipherTextSize);
int decryptData(FAPI_CONTEXT* fapiContext, TSS2_RC* rc, const uint8_t* cipherText, size_t cipherTextSize, const char* keyPath);

#endif 