#include <stdio.h>
#include <tss2/tss2_fapi.h>
#include <string.h>
#include <openssl/sha.h>  
#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/insert_linebreaks.hpp>
#include <boost/archive/iterators/ostream_iterator.hpp>
#include <sstream>

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


// This function creates base64 encoded string from the given data using boost library
// The function is used to encode data before sending it to the server
std::string base64_encode(const unsigned char* data, size_t length) {
    using namespace boost::archive::iterators;
    using It = insert_linebreaks<base64_from_binary<transform_width<const char *, 6, 8>>, 72>;
    std::stringstream result;
    std::copy(It(data), It(data + length), std::ostream_iterator<char>(result));
    size_t num = (3 - length % 3) % 3;
    for (size_t i = 0; i < num; i++) {
        result.put('=');
    }
    return result.str();
}

// Callback function for reading the response data needed for the REST API call for curl library
size_t callbackFunction(char* ptr, size_t size, size_t nmemb, std::string* data) {
    data->append(ptr, size * nmemb);
    return size * nmemb;
}

// Calling the remote server using rest api to receive new license data
void callVerifyApi(){
    // Variables init
    FAPI_CONTEXT* fapiContext;
    TSS2_RC rc;
    CURL* curl;
    CURLcode res;
    std::string readBuffer;  // holds the response from the server

    rc = initFapiContext(&fapiContext);

    std::string jsonString = createVerificationJson().dump();
    const char* customerVerification = jsonString.c_str();

    const char* keyPath = "/HS/SRK/myRsaKeyToDelete";

    // Generating signature for request
    std::vector<uint8_t> sigi = signDataAndReturnSignature(fapiContext, rc, keyPath, customerVerification);
    size_t sigiSize = sigi.size();
    uint8_t* signatureData = sigi.data();

    //signData(fapiContext, rc, keyPath, customerVerification);


    // Read the signature from the file
    /*size_t signatureSize;

    const char* filename = "signature.bin";
    std::ifstream file(filename, std::ios::binary);

    // Check if the file was successfully opened
    if (!file) {
        fprintf(stderr,"Error opening file for reading: %s\n", filename);
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
    file.close();*/

    curl_global_init(CURL_GLOBAL_DEFAULT); // Initialize global curl settings
    curl = curl_easy_init();  // Initialize a curl handle

    if (curl) {
        
        // Set the URL for the REST API endpoint
        //cout << "Sending request to server...\n";
        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:8084/api/hello");
        
        // Convert the data and signature to JSON
        nlohmann::json j;
        j["data"] = customerVerification;   // Convert jsonFileContent to const unsigned char*
        j["signature"] = base64_encode(signatureData, sigiSize);  // Assuming signature is your signature

        // Convert the JSON to a string
        std::string postData = j.dump();
        
        //cout<< "srandicky" << postData << endl;
        // Set the callback function to receive the data
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callbackFunction);

        // Set the POST data
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());

        // Set the custom pointer to the data string
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        // Set the Content-Type header
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Perform the request, res will get the return code
        res = curl_easy_perform(curl);

        //cout << "Request sent\n";
        // Check for errors
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << '\n';
        } else {
            // Output the response data
            std::cout << "Response: " << readBuffer << '\n';
        }

    
        // Always cleanup
        curl_easy_cleanup(curl);

        // Cleanup the headers list
        curl_slist_free_all(headers);
    }

    curl_global_cleanup();
    verifyDataWithSignatureParam(fapiContext, rc, keyPath, customerVerification, signatureData, sigiSize);
    

    BIO *bio, *b64;
    int decodeLen = readBuffer.size();
    uint8_t* buffer = (uint8_t*)malloc(decodeLen);
    bio = BIO_new_mem_buf(readBuffer.data(), -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    decodeLen = BIO_read(bio, buffer, decodeLen);
    BIO_free_all(bio);

    uint8_t* decryptedText = nullptr; // Add decryptedText parameter
    size_t decryptedTextSize = 0;
    decryptData(fapiContext, &rc, buffer, decodeLen, keyPath, &decryptedText, &decryptedTextSize);
    cout<< "Decrypted text: " << decryptedText << endl;
    cout<< "Buffer: " << buffer << endl;
    cout<< "Decoded len: "<< decodeLen << endl;
    std::string cipherTextString(reinterpret_cast<char*>(buffer), decodeLen);
    writeStringFile("licenseFile.json", cipherTextString);
    signData(fapiContext, rc, keyPath, (const char*)buffer);
}

static const char* runCmd = "gcc -o myApp demo.cpp -L/usr/local/lib -ltss2-fapi -lssl -lcrypto";
static const char* runCmd2 = "g++ -o myApp demo.cpp -L/usr/local/lib sources/sign.cpp -ltss2-fapi -lssl -lcrypto";
static const char* verify = "openssl dgst -sha256 -verify publicKey.pem -signature signature.bin -sigopt rsa_padding_mode:pss licenseFile.json";


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


    /*getTpmInfo(fapiContext, rc);
    printAllStoredObjects(fapiContext, rc);*/
    
    //createJsonFile("License", time(nullptr), time(nullptr) + 60, {"Functionality1", "Functionality2", "Functionality3"});

    // Part one encrypt and sign data
    //string jsonFileContent = loadJsonFile("licenseFile.json").dump();
    //const char* data = jsonFileContent.c_str();
    const char* keyPath = "/HS/SRK/myRsaKeyToDelete";
    /*uint8_t *cipherText = NULL; 
    size_t cipherTextSize = 0;*/

    /*encryptData(fapiContext, &rc, data, keyPath, &cipherText, &cipherTextSize);*/

    //signData(fapiContext, rc, keyPath, data);
    //verifyData(fapiContext, rc, keyPath, data);

    /*std::string cipherTextString(reinterpret_cast<char*>(cipherText), cipherTextSize);*/
    //writeStringFile("licenseFile.json", cipherTextString);

    /*bool notExpired = isNotExpired(fapiContext, &rc, "licenseFile.json");
    cout << "Not expired:" << boolalpha << notExpired << endl;*/
    //printAllStoredObjects(fapiContext, rc);
    callVerifyApi();
    rc = initFapiContext(&fapiContext);

///////////////////////////////////////////    
/*const char* keyPath = "/HS/SRK/myRsaKeyToDelete";
    char* publicKey = nullptr;

    rc = Fapi_ExportKey(fapiContext, keyPath, nullptr, &publicKey);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to export key: 0x%x\n", rc);
        Fapi_Finalize(&fapiContext);
        return 1;
    }

    printf("Key exported successfully.\n");

    std::ofstream file("publicKey.pem");
    if (!file) {
        throw std::runtime_error("Could not open file: public.pem");
    }

    // Write the public key to the file
    nlohmann::json jsonPublicKey;
    
    jsonPublicKey = nlohmann::json::parse(publicKey);

    file << jsonPublicKey["pem_ext_public"].get<std::string>();
    //file << publicKey;

    // Close the file
    file.close();

    printf("Public key: %s.\n", jsonPublicKey["pem_ext_public"].get<std::string>().c_str());*/
    // Part two verify and decrypt data
    /*bool notExpired = isNotExpired(fapiContext, &rc, "licenseFile.json");
    cout << "Not expired:" << boolalpha << notExpired << endl;
    */

/*
    printf("Data to be encrypted: %s\n", data);

    encryptData(fapiContext, &rc, data, keyPath, &cipherText, &cipherTextSize);
    decryptData(fapiContext, &rc, cipherText, cipherTextSize, keyPath);

    signData(fapiContext, rc, keyPath, (const char*)cipherText);
    
    verifyData(fapiContext, rc, keyPath, (const char*)cipherText);
    
    //rc = Fapi_Decrypt(fapiContext, keyPath, cipherText, cipherTextSize, &cipherText, &cipherTextSize);
    //if (rc != TSS2_RC_SUCCESS) {*/

    ifstream file("licenseFile.json");
    if (!file) {
        throw runtime_error("Could not open file: licenseFile.json");
    }

    string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    uint8_t* cipherText = reinterpret_cast<uint8_t*>(content.data());
    size_t cipherTextSize = content.size();
     uint8_t* decryptedText = nullptr; // Add decryptedText parameter
    size_t decryptedTextSize = 0;
    
    decryptData(fapiContext, &rc, cipherText, cipherTextSize, keyPath, &decryptedText, &decryptedTextSize); // Add decryptedText as parameter
    cout << decryptedText << endl;
    cout<< decryptedText << endl;
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