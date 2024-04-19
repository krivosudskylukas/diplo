#include "../headers/create_key.h"
#include "../headers/fapi_util.h"

// Authentication callback function
TSS2_RC key_callback(FAPI_CONTEXT *context, const char *description, char **auth, void *userData) {
    (void)(context); // Unused parameter
    (void)(description); // Unused parameter
    *auth = strdup((char *)userData); // Set the authentication value
    return TSS2_RC_SUCCESS;
}

int createKey(FAPI_CONTEXT* fapiContext,
    TSS2_RC rc){

    // Path where the RSA key will be stored in the TPM
    const char* rsaKeyPath = "/HS/SRK/myRsaKeyToDelete";
    const char* policy = NULL; // No policy, but you can define one as needed
    //const char* policy = "{ \"description\": \"Password policy\", \"policy\": { \"type\": \"AuthValue\" } }";

    // Password for the key
    //const char* password = "ShortPassword"; // Replace with your actual password

    // Set the password callback function
    //Fapi_SetAuthCB(fapiContext, (Fapi_CB_Auth)key_callback, (void*)password);


    rc = Fapi_CreateKey(fapiContext, rsaKeyPath, NULL, NULL, policy);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to create RSA key: 0x%x\n", rc);
        Fapi_Finalize(&fapiContext);
        return 1;
    }

    if(rc == TSS2_RC_SUCCESS){
    printf("RSA Key created successfully at path: %s\n", rsaKeyPath);
    }

    if(rc == TSS2_FAPI_RC_PATH_ALREADY_EXISTS){
    printf("RSA Key exist at path: %s\n", rsaKeyPath);
    }

    Fapi_Finalize(&fapiContext);

    return 0;
}


int deleteKey(FAPI_CONTEXT* fapiContext, TSS2_RC rc) {

    // Path where the RSA key is stored in the TPM
    const char* rsaKeyPath = "/HS/SRK/myRsaKeyToDelete";

    rc = Fapi_Delete(fapiContext, rsaKeyPath);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to delete RSA key: 0x%x\n", rc);
        Fapi_Finalize(&fapiContext);
        return 1;
    }

    printf("RSA key deleted successfully from path: %s\n", rsaKeyPath);
    Fapi_Finalize(&fapiContext);

    return 0;
}