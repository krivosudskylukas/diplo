#include <stdio.h>
#include <tss2/tss2_fapi.h>
#include <string.h>
#include <openssl/sha.h>  // Include OpenSSL's SHA header

#include "headers/sign.h"
#include "headers/create_key.h"
#include "headers/verify.h"
#include "headers/file_util.h"
#include "headers/fapi_util.h"
#include "headers/crypto_operations.h"

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

    //createKey(fapiContext, rc);
    //printAllStoredObjects(fapiContext, rc);
    //deleteKey(fapiContext, rc);
    //printAllStoredObjects(fapiContext, rc);

    string jsonFileContent = loadJsonFile("licenseFile.json").dump();
    const char* data = jsonFileContent.c_str();
    const char* keyPath = "/HS/SRK/myRsaKeyToDelete";
    uint8_t *cipherText = NULL; 
    size_t cipherTextSize = 0;

    printf("Data to be encrypted: %s\n", data);

    encryptData(fapiContext, &rc, data, keyPath, &cipherText, &cipherTextSize);
    decryptData(fapiContext, &rc, cipherText, cipherTextSize, keyPath);

    signData(fapiContext, rc, keyPath, (const char*)cipherText);
    
    verifyData(fapiContext, rc, keyPath, (const char*)cipherText);
    
    //rc = Fapi_Decrypt(fapiContext, keyPath, cipherText, cipherTextSize, &cipherText, &cipherTextSize);
    /*printf("Operation completed successfully.\n");

    printf("Encrypted data: %s\n", cipherText);

    
    v*/
    
    return 0;
}