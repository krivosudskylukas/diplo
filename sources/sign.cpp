#include "../headers/sign.h"

int signData(FAPI_CONTEXT* fapiContext,
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