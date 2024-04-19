#include "../headers/crypto_operations.h"

int encryptData(FAPI_CONTEXT* fapiContext, TSS2_RC* rc, const char* dataToEncrypt, const char* keyPath, uint8_t** cipherText, size_t* cipherTextSize){

  
    *rc = Fapi_Encrypt(fapiContext, keyPath, (uint8_t*)dataToEncrypt, strlen(dataToEncrypt), cipherText, cipherTextSize);
    if (*rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to encrypt data: 0x%x\n", *rc);
        Fapi_Finalize(&fapiContext);
        return 1;
    }

    return 0;
}

int decryptData(FAPI_CONTEXT* fapiContext,TSS2_RC* rc, const uint8_t* cipherText, size_t cipherTextSize, const char* keyPath, uint8_t** decryptedText, size_t* decryptedTextSize){
        
        *rc = Fapi_Decrypt(fapiContext, keyPath, cipherText, cipherTextSize, decryptedText, decryptedTextSize);
        if (*rc != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Failed to decrypt data: 0x%x\n", *rc);
            Fapi_Finalize(&fapiContext);
            return 1;
        }
    
        return 0;
}