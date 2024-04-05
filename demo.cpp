#include <stdio.h>
#include <tss2/tss2_fapi.h>
#include <string.h> // Add this line
#include <openssl/sha.h>  // Include OpenSSL's SHA header

#include "headers/sign.h"

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


/*int signData(FAPI_CONTEXT* fapiContext,
    TSS2_RC rc, const char* keyPath, const char* dataToSign ){
    // Define the data to sign
    unsigned char hash[SHA256_DIGEST_LENGTH];  // Buffer to store SHA-256 hash

    // Hash the data using SHA-256
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, dataToSign, strlen(dataToSign));
    SHA256_Final(hash, &sha256);

    // Sign the hashed data
    uint8_t* signature;
    size_t signatureSize;
    rc = Fapi_Sign(fapiContext, keyPath, NULL, hash, sizeof(hash),  &signature, &signatureSize, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to sign data: 0x%x\n", rc);
        Fapi_Finalize(&fapiContext);
        return 1;
    }

    // Print the signature
    printf("Signature:\n");
    for (size_t i = 0; i < signatureSize; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");

    // Verify the signature
    rc = Fapi_VerifySignature(fapiContext, keyPath, hash, sizeof(hash), signature, signatureSize);
    if (rc == TSS2_RC_SUCCESS) {
        printf("Signature is valid.\n");
    } else if (rc == TSS2_FAPI_RC_SIGNATURE_VERIFICATION_FAILED) {
        printf("Signature is not valid.\n");
    } else {
        fprintf(stderr, "Failed to verify signature: 0x%x\n", rc);
        Fapi_Finalize(&fapiContext);
        return 1;
    }

    // Free the signature
    Fapi_Free(signature);

    return 0;
}
*/

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





int main() {
   FAPI_CONTEXT* fapiContext;
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

    return 0;
}