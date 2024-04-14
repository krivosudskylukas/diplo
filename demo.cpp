#include <stdio.h>
#include <tss2/tss2_fapi.h>
#include <string.h>
#include <openssl/sha.h>  // Include OpenSSL's SHA header

#include "headers/sign.h"
#include "headers/create_key.h"
#include "headers/verify.h"
#include "headers/file_util.h"
#include "headers/fapi_util.h"

#include <ctime>
#include <ratio>
#include <chrono>
using namespace std::chrono;

using json = nlohmann::json;




static const char* runCmd = "gcc -o myApp demo.cpp -L/usr/local/lib -ltss2-fapi -lssl -lcrypto";
static const char* runCmd2 = "g++ -o myApp demo.cpp -L/usr/local/lib sources/sign.cpp -ltss2-fapi -lssl -lcrypto";




int main() {
    FAPI_CONTEXT* fapiContext;
    TSS2_RC rc;

    rc = initFapiContext(&fapiContext);


    string jsonFileContent = loadJsonFile("licenseFile.json").dump();
    const char* data = jsonFileContent.c_str();
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
    printf("Operation completed successfully.\n");

    printf("Encrypted data: %s\n", cipherText);

    signData(fapiContext, rc, keyPath, (const char*)cipherText);
    verifyData(fapiContext, rc, keyPath, (const char*)cipherText);
    
    return 0;
}