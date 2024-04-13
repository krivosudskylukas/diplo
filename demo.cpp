#include <stdio.h>
#include <tss2/tss2_fapi.h>
#include <string.h> // Add this line
#include <openssl/sha.h>  // Include OpenSSL's SHA header

#include "headers/sign.h"
#include "headers/create_key.h"
#include "headers/verify.h"
#include "headers/create_file.h"

using json = nlohmann::json;


// Authentication callback function
TSS2_RC auth_callback(FAPI_CONTEXT *context, const char *description, char **auth, void *userData) {
    (void)(context); // Unused parameter
    (void)(description); // Unused parameter
    *auth = strdup((char *)userData); // Set the authentication value
    return TSS2_RC_SUCCESS;
}

static const char* runCmd = "gcc -o myApp demo.cpp -L/usr/local/lib -ltss2-fapi -lssl -lcrypto";
static const char* runCmd2 = "g++ -o myApp demo.cpp -L/usr/local/lib sources/sign.cpp -ltss2-fapi -lssl -lcrypto";


int init(FAPI_CONTEXT* fapiContext,
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




int allObjects(FAPI_CONTEXT* fapiContext,
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

int getInfo(FAPI_CONTEXT* fapiContext,
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


TSS2_RC initFapiContext(FAPI_CONTEXT* fapiContext){

    TSS2_RC rc;

    // Initialize the FAPI context
    rc = Fapi_Initialize(&fapiContext, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to initialize FAPI context: 0x%x\n", rc);
        return 1;
    }

    // Set the authentication callback
    rc = Fapi_SetAuthCB(fapiContext, (Fapi_CB_Auth)auth_callback, (void*)"asdfasdfg");
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to set authentication callback: 0x%x\n", rc);
        Fapi_Finalize(&fapiContext);
        return 1;
    }

    return rc;
}


int main() {
    /*FAPI_CONTEXT* fapiContext;
    TSS2_RC rc;

    rc = Fapi_Initialize(&fapiContext, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to initialize FAPI context: 0x%x\n", rc);
        return 1;
    }

    // Set the authentication callback
    rc = Fapi_SetAuthCB(fapiContext, (Fapi_CB_Auth)auth_callback, (void*)"asdfasdfg");
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to set authentication callback: 0x%x\n", rc);
        Fapi_Finalize(&fapiContext);
        return 1;
    }

    const char* data = "Secret data no one knows";
    const char* keyPath = "/HS/SRK/myRsaKey";
    uint8_t *cipherText = NULL; 
    size_t cipherTextSize = 0;

    printf("Data to be encrypted: %s\n", data);

    rc = Fapi_Encrypt(fapiContext, keyPath, (uint8_t*)data, strlen(data), &cipherText, &cipherTextSize);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to encrypt data: 0x%x\n", rc);
        Fapi_Finalize(&fapiContext);
        return 1;
    }
    //printf("Operation completed successfully.\n");

    printf("Encrypted data: %s\n", cipherText);

    signData(fapiContext, rc, keyPath, (const char*)cipherText);
    verifyData(fapiContext, rc, keyPath, (const char*)cipherText);*/
    string name = "Test";
    time_t startDate = time(0);
    time_t expirationDate = createExpirationDate(19,2,2025);
    vector<string> functionality{ "Scan","Xray","Messages" };

    createJsonFile(name, startDate, expirationDate, functionality);
    
    json j = loadJsonFile("licenseFile.json");

    try {
        createJsonFile(name, startDate, expirationDate, functionality);
    }
    catch(const invalid_argument &e){
        cout << e.what();
    }

    return 0;
}