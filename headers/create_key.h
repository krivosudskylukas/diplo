#ifndef CREATE_KEY_H
#define CREATE_KEY_H

#include <tss2/tss2_fapi.h>  
#include <openssl/sha.h>  
#include <string.h>
#include <stdio.h>

int createKey(FAPI_CONTEXT* fapiContext, TSS2_RC rc, const char* rsaKeyPath, const char* policy);
int deleteKey(FAPI_CONTEXT* fapiContext, TSS2_RC rc);

#endif 