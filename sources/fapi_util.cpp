#include "../headers/fapi_util.h"

// Authentication callback function
TSS2_RC auth_callback(FAPI_CONTEXT *context, const char *description, char **auth, void *userData) {
    (void)(context); // Unused parameter
    (void)(description); // Unused parameter
    *auth = strdup((char *)userData); // Set the authentication value
    return TSS2_RC_SUCCESS;
}

int initProvisioning(FAPI_CONTEXT* fapiContext,
    TSS2_RC rc){
    // Provision the TPM
    rc = Fapi_Provision(fapiContext, "asdfasdfg", "asdfasdfg", "asdfasdfg");
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to provision TPM: 0x%x\n", rc);
        Fapi_Finalize(&fapiContext);
        return 1;
    }
    return 0;
}

int printAllStoredObjects(FAPI_CONTEXT* fapiContext,
    TSS2_RC rc){
    char* objectList;
    size_t objectCount;
    rc = Fapi_List(fapiContext, "/", &objectList);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to list objects: 0x%x\n", rc);
        Fapi_Finalize(&fapiContext);
        return 1;
    }

    printf("List of objects:\n");
    char* object = strtok(objectList, "\n");
    
    while (object != NULL) {
    printf("%s\n", object);
    object = strtok(NULL, "\n");
    }
    
    // Free the object list
    Fapi_Free(objectList);
    return 0;
}


int getTpmInfo(FAPI_CONTEXT* fapiContext,
    TSS2_RC rc){
    // Get information about the TPM
    char* info;
    rc = Fapi_GetInfo(fapiContext, &info);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to get TPM information: 0x%x\n", rc);
        Fapi_Finalize(&fapiContext);
        return 1;
    }

    printf("TPM Information:\n%s\n", info);
    return 0;
}

TSS2_RC initFapiContext(FAPI_CONTEXT** fapiContext){

    TSS2_RC rc;

    // Initialize the FAPI context
    rc = Fapi_Initialize(fapiContext, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to initialize FAPI context: 0x%x\n", rc);
        return 1;
    }

    // Set the authentication callback
    /*rc = Fapi_SetAuthCB(*fapiContext, (Fapi_CB_Auth)auth_callback, (void*)"asdfasdfg");
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to set authentication callback: 0x%x\n", rc);
        Fapi_Finalize(fapiContext);
        return 1;
    }*/

    return rc;
}