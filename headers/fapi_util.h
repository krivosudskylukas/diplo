#ifndef FAPI_UTIL_H
#define FAPI_UTIL_H
#include <tss2/tss2_fapi.h>
#include <string.h>
#include <stdio.h>


int initProvisioning(FAPI_CONTEXT* fapiContext, TSS2_RC rc);
int printAllStoredObjects(FAPI_CONTEXT* fapiContext, TSS2_RC rc);
int getTpmInfo(FAPI_CONTEXT* fapiContext, TSS2_RC rc);
TSS2_RC initFapiContext(FAPI_CONTEXT** fapiContext);


#endif // FAPI_UTIL_H