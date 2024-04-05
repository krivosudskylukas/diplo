#include "../headers/createKey.h"


int createKey(FAPI_CONTEXT* fapiContext,
    TSS2_RC rc){

    // Path where the RSA key will be stored in the TPM
    const char* rsaKeyPath = "/HS/SRK/myRsaKey";

    rc = Fapi_CreateKey(fapiContext, rsaKeyPath, NULL, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to create RSA key: 0x%x\n", rc);
        Fapi_Finalize(&fapiContext);
        return 1;
    }

    printf("RSA key created successfully at path: %s\n", rsaKeyPath);
        Fapi_Finalize(&fapiContext);




    // Define the key type and policy (if any)
    //const char* keyType = "{\"type\":\"ecc\",\"curve\":\"NIST_P256\"}";
    const char* keyType = "{\"type\":\"ecc\",\"curve\":\"NIST_P256\",\"usage\":\"sign\"}";
    const char* keyPath = "/HS/SRK/myEccKey";
    const char* policy = NULL; // No policy, but you can define one as needed

    // Create the ECC key
    rc = Fapi_CreateKey(fapiContext, keyPath, NULL, NULL, policy);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to create ECC key: 0x%x\n", rc);
        Fapi_Finalize(&fapiContext);
        return 1;
    }

    if(rc == TSS2_RC_SUCCESS){
    printf("ECC Key created successfully at path: %s\n", keyPath);
    }

    if(rc == TSS2_FAPI_RC_PATH_ALREADY_EXISTS){
    printf("ECC Key exist at path: %s\n", keyPath);
    }
        
    return 0;
}