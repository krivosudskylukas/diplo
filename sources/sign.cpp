#include "../headers/sign.h"
#include <openssl/evp.h>


int signData(FAPI_CONTEXT* fapiContext,
    TSS2_RC rc, const char* keyPath, const char* dataToSign){
    // Define the data to sign
    //unsigned char hash[SHA256_DIGEST_LENGTH];  // Buffer to store SHA-256 hash



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
    EVP_DigestUpdate(mdctx, dataToSign, strlen(dataToSign));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);


    // Hash the data using SHA-256
    /*SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, dataToSign, strlen(dataToSign));
    SHA256_Final(hash, &sha256);*/

    // Sign the hashed data
    uint8_t* signature;
    size_t signatureSize;
    rc = Fapi_Sign(fapiContext, keyPath, NULL, md_value, md_len,  &signature, &signatureSize, NULL, NULL);
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
    
    const char* filename = "signature.bin";
    std::ofstream file(filename, std::ios::binary);

    // Check if the file was successfully opened
    if (!file) {
        //std::cerr <<  << filename << std::endl;
        fprintf(stderr, "Error opening file for writing: %s\n", filename);
        return 1;
    }

    // Write the signature to the file
    for (size_t i = 0; i < signatureSize; ++i) {
        file.put(static_cast<char>(signature[i]));
    }

    // Close the file
    file.close();

    // Free the signature
    Fapi_Free(signature);

    return 0;
}