#ifndef SIGNING_H
#define SIGNING_H

#include <tss2/tss2_fapi.h>  // Assuming TSS2_RC and FAPI_CONTEXT are defined here
#include <openssl/sha.h>  // Include OpenSSL's SHA header
#include <string.h> // Add this line
#include <stdio.h>
#include <iostream>
#include <exception>

// Function prototype for signData
int signData(FAPI_CONTEXT* fapiContext, TSS2_RC rc, const char* keyPath, const char* dataToSign);

#endif // SIGNING_H
