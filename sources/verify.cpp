#include "../headers/verify.h"
#include <openssl/evp.h>


int verifyData(FAPI_CONTEXT* fapiContext,
    TSS2_RC rc, const char* keyPath, const char* dataToVerify){
    // Define the data to sign
    //unsigned char hash[SHA256_DIGEST_LENGTH];  // Buffer to store SHA-256 hash

    // Sign the hashed data
    //uint8_t* signature;
    size_t signatureSize;

    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    OpenSSL_add_all_digests();

    md = EVP_get_digestbyname("sha256");

    if(!md) {
        printf("Unknown message digest\n");
        exit(1);
    }
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, dataToVerify, strlen(dataToVerify));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);



    const char* filename = "signature.bin";
    std::ifstream file(filename, std::ios::binary);

    // Check if the file was successfully opened
    if (!file) {
        fprintf(stderr,"Error opening file for reading: %s\n", filename);
        return 1;
    }
    
    // Determine the file size
    file.seekg(0, std::ios::end);
    signatureSize = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    // Allocate memory for the signature
    uint8_t* signature = new uint8_t[signatureSize];

    // Read the file into the signature array
    file.read(reinterpret_cast<char*>(signature), signatureSize);

    // Close the file
    file.close();

     // Print the signature
    printf("Signature:\n");
    for (size_t i = 0; i < signatureSize; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");



    // Verify the signature
    rc = Fapi_VerifySignature(fapiContext, keyPath, md_value, md_len, signature, signatureSize);
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