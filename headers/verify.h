#ifndef VERIFY_H
#define VERIFY_H

#include <tss2/tss2_fapi.h>  // Assuming TSS2_RC and FAPI_CONTEXT are defined here
#include <openssl/sha.h>  // Include OpenSSL's SHA header
#include <string.h> // Add this line
#include <stdio.h>
#include <fstream>   // For file operations
#include <cstdint>   // For uint8_t
#include <iostream>  // For std::cerr


// Function prototype for signData
int verifyData(FAPI_CONTEXT* fapiContext, TSS2_RC rc, const char* keyPath, const char* dataToVerify);

#endif // VERIFY_H
