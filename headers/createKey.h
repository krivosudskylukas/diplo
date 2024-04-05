#ifndef SIGNING_H
#define SIGNING_H

#include <tss2/tss2_fapi.h>  
#include <openssl/sha.h>  
#include <string.h>
#include <stdio.h>

int createKey(FAPI_CONTEXT* fapiContext, TSS2_RC rc);

#endif // SIGNING_H