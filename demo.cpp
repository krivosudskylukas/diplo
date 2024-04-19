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
void printExpirationDate(std::time_t expirationDate) {
    // Convert the timestamp to a tm struct
    std::tm* timeStruct = std::localtime(&expirationDate);

    // Format the tm struct as a string
    char buffer[100];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeStruct);

    // Print the date and time
    std::cout << "Expiration Date: " << buffer << std::endl;
}

bool isNotExpired(FAPI_CONTEXT* fapiContext, TSS2_RC* rc ,const std::string& filename);

int main() {
    FAPI_CONTEXT* fapiContext;
    TSS2_RC rc;

    rc = initFapiContext(&fapiContext);


    // Part one encrypt and sign data
    /*string jsonFileContent = loadJsonFile("licenseFile.json").dump();
    const char* data = jsonFileContent.c_str();
    const char* keyPath = "/HS/SRK/myRsaKeyToDelete";
    uint8_t *cipherText = NULL; 
    size_t cipherTextSize = 0;

    encryptData(fapiContext, &rc, data, keyPath, &cipherText, &cipherTextSize);

    signData(fapiContext, rc, keyPath, (const char*)cipherText);

    std::string cipherTextString(reinterpret_cast<char*>(cipherText), cipherTextSize);
    writeStringFile("licenseFile.json", cipherTextString);*/



    // Part two verify and decrypt data
    bool notExpired = isNotExpired(fapiContext, &rc, "licenseFile.json");
    cout << "Not expired:" << boolalpha << notExpired << endl;


/*
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

bool isNotExpired(FAPI_CONTEXT* fapiContext, TSS2_RC* rc ,const std::string& filename) {
    
    
    ifstream file(filename);
    if (!file) {
        throw runtime_error("Could not open file: " + filename);
    }

    string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    uint8_t* cipherText = reinterpret_cast<uint8_t*>(content.data());
    size_t cipherTextSize = content.size();
    const char* keyPath = "/HS/SRK/myRsaKeyToDelete";
    uint8_t* decryptedText = nullptr; // Add decryptedText parameter
    size_t decryptedTextSize = 0;

    verifyData(fapiContext, *rc, keyPath, (const char*)cipherText);

    decryptData(fapiContext, rc, cipherText, cipherTextSize, keyPath, &decryptedText, &decryptedTextSize); // Add decryptedText as parameter

    cout<< decryptedText << endl;
    json jsonData = json::parse(decryptedText);
    // Get the current time
    std::time_t now = std::time(nullptr);

    printExpirationDate(jsonData["Expiration_Date"]);
    // Get the expiration date from the JSON data
    std::time_t expirationDate = jsonData["Expiration_Date"];

    // Check if the expiration date is after the current time
    return expirationDate > now;
}