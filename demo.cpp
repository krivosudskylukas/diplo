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

const string URL = "http://localhost:8084/api/hello";
const char* SIGNING_KEY_PATH = "/HS/SRK/signingRsaKey";
const char* ENCRYPTION_KEY_PATH = "/HS/SRK/cryptographyRsaKey";

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
    std::string readBuffer;  
    nlohmann::json jsonResponse;


    rc = initFapiContext(&fapiContext);

    std::string jsonString = createVerificationJson().dump();
    const char* customerVerification = jsonString.c_str();

    // Generating signature for request
    std::vector<uint8_t> signature = signDataAndReturnSignature(fapiContext, rc, SIGNING_KEY_PATH, customerVerification);
    
    if(signature.empty()) {
        throw std::runtime_error("Failed to sign the data");
    }

    size_t signatureSize = signature.size();
    uint8_t* signatureData = signature.data();

    // Initialize curl neccessities
    curl_global_init(CURL_GLOBAL_DEFAULT); 
    curl = curl_easy_init();  

    if (curl) {
        
        // Set the URL for the REST API endpoint
        curl_easy_setopt(curl, CURLOPT_URL, URL.c_str());
        
        // Create the request body
        nlohmann::json j;
        j["data"] = customerVerification;  
        j["signature"] = base64_encode(signatureData, signatureSize);

        // Convert the JSON to a string
        std::string postData = j.dump();
        
        cout << postData << endl;
        // Set curl options
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callbackFunction);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        // Set the Content-Type header
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Perform the request, res will get the return code
        res = curl_easy_perform(curl);

        // Check for errors
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << '\n';
        } else {
            // Output the response data
            std::cout << "Response: " << readBuffer << '\n';
            jsonResponse = nlohmann::json::parse(readBuffer);

        }

        if(jsonResponse["status"] == 500){
            throw std::runtime_error("Invalid signature");
        }
    
        // Always cleanup
        curl_easy_cleanup(curl);

        // Cleanup the headers list
        curl_slist_free_all(headers);

        curl_global_cleanup();
    //verifyDataWithSignatureParam(fapiContext, rc, SIGNING_KEY_PATH, customerVerification, signatureData, signatureSize);
    
    // Decode the base64 encoded response into a binary
    /*BIO *bio, *b64;
    int decodeLen = jsonResponse["encryptedResponse"].size();
    std::string encryptedResponse = jsonResponse["encryptedResponse"];

    uint8_t* buffer = (uint8_t*)malloc(decodeLen);
    bio = BIO_new_mem_buf(encryptedResponse.data(), -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    decodeLen = BIO_read(bio, buffer, decodeLen);
    BIO_free_all(bio);*/

    // Calculate the maximum possible length of the decoded data
    std::string encryptedResponse = jsonResponse["encryptedResponse"];
    int decodeLen = 3 * (encryptedResponse.size() / 4);

    // Allocate memory for the decoded buffer
    std::vector<uint8_t> buffer(decodeLen); // Using vector for automatic memory management

    // Setup BIO for decoding
    BIO *bio, *b64;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(encryptedResponse.data(), encryptedResponse.length());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int actualDecodeLen = BIO_read(bio, buffer.data(), buffer.size());

    buffer.resize(actualDecodeLen);  // Resize buffer to actual data length
    BIO_free_all(bio);

    cout<< encryptedResponse << endl;
    cout<< "Buffer: " << buffer.data() << endl;

    // Print out the decoded data
    uint8_t* decryptedText = nullptr; 
    size_t decryptedTextSize = 0;
    decryptData(fapiContext, &rc, buffer.data(), actualDecodeLen, ENCRYPTION_KEY_PATH, &decryptedText, &decryptedTextSize);
    cout<< "Decrypted text: " << decryptedText << endl;
    //cout<< "Buffer: " << buffer.data() << endl;
    cout<< "Decoded len: "<< decodeLen << endl;

    // Write the decoded data to a file and generate a signature
    //std::string cipherTextString(reinterpret_cast<char*>(buffer.data()), decodeLen);

    ofstream file("licenseFile.json",std::ios::binary);
    if (!file) {
        throw runtime_error("Could not open file: ");
    }

    //writeStringFile("licenseFile.json", cipherTextString);
    file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    file.close();

    signData(fapiContext, rc, SIGNING_KEY_PATH, reinterpret_cast<char*>(buffer.data()));
    
    //decryptData(fapiContext, &rc, reinterpret_cast<const uint8_t*>(cipherTextString.c_str()), actualDecodeLen, ENCRYPTION_KEY_PATH, &decryptedText, &decryptedTextSize);
    cout<< "Decrypted text: " << decryptedText << endl;


    std::string encryptedSignature = jsonResponse["signature"];
    int decodeLenSignature = 3 * (encryptedSignature.size() / 4);

    // Allocate memory for the decoded buffer
    std::vector<uint8_t> bufferSignature(decodeLenSignature); // Using vector for automatic memory management

    // Setup BIO for decoding central signature
    BIO *bioSignature, *b64Signature;
    b64Signature = BIO_new(BIO_f_base64());
    bioSignature = BIO_new_mem_buf(encryptedResponse.data(), encryptedSignature.length());
    bioSignature = BIO_push(b64Signature, bioSignature);
    BIO_set_flags(bioSignature, BIO_FLAGS_BASE64_NO_NL);
    int actualDecodeLenSignature = BIO_read(bioSignature, bufferSignature.data(), bufferSignature.size());

    bufferSignature.resize(actualDecodeLenSignature);  // Resize buffer to actual data length
    BIO_free_all(bioSignature);

    ofstream fileSignature("centralServerSignature.bin",std::ios::binary);
    if (!file) {
        throw runtime_error("Could not open file: ");
    }

    //writeStringFile("licenseFile.json", cipherTextString);
    fileSignature.write(reinterpret_cast<const char*>(bufferSignature.data()), bufferSignature.size());
    fileSignature.close();

    /*size_t signatureSize1;


    std::ifstream file1("licenseFile.json", std::ios::binary);

    // Check if the file was successfully opened
    if (!file1) {
        fprintf(stderr,"Error opening file for reading: %s\n","as");
    }

    // Determine the file size
    file1.seekg(0, std::ios::end);
    signatureSize1 = static_cast<size_t>(file1.tellg());
    file1.seekg(0, std::ios::beg);

    // Allocate memory for the signature
    uint8_t* signature1 = new uint8_t[signatureSize];

    // Read the file into the signature array
    file1.read(reinterpret_cast<char*>(signature1), signatureSize1);

    // Close the file
    file1.close();

    decryptData(fapiContext, &rc, signature1, signatureSize1, ENCRYPTION_KEY_PATH, &decryptedText, &decryptedTextSize); // Add decryptedText as parameter

    cout<< "Decrypted text: " << decryptedText << endl;

    verifyData(fapiContext, rc, SIGNING_KEY_PATH, (const char*)signature1);
    */
    }

    
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
void exportPublicKey(FAPI_CONTEXT* fapiContext, TSS2_RC rc, const char* keyPath, const char* keyFile);

int main() {
    FAPI_CONTEXT* fapiContext;
    TSS2_RC rc;

    //const char* keyPath = "/HS/SRK/myRsaKeyToDelete";
    callVerifyApi();
    rc = initFapiContext(&fapiContext);
    //isNotExpired(fapiContext, &rc, "licenseFile.json");


    size_t signatureSize1;
    uint8_t* decryptedText = nullptr; // Add decryptedText parameter
    size_t decryptedTextSize = 0;

    std::ifstream file1("licenseFile.json", std::ios::binary);

    // Check if the file was successfully opened
    if (!file1) {
        fprintf(stderr,"Error opening file for reading: %s\n","as");
    }

    // Determine the file size
    file1.seekg(0, std::ios::end);
    signatureSize1 = static_cast<size_t>(file1.tellg());
    file1.seekg(0, std::ios::beg);

    // Allocate memory for the signature
    uint8_t* signature1 = new uint8_t[signatureSize1];

    // Read the file into the signature array
    file1.read(reinterpret_cast<char*>(signature1), signatureSize1);

    // Close the file
    file1.close();

    decryptData(fapiContext, &rc, signature1, signatureSize1, ENCRYPTION_KEY_PATH, &decryptedText, &decryptedTextSize); // Add decryptedText as parameter

    cout<< "Decrypted text: " << decryptedText << endl;

    verifyData(fapiContext, rc, SIGNING_KEY_PATH, (const char*)signature1);


    //createKey(fapiContext, rc, SIGNING_KEY_PATH, NULL);
    //createKey(fapiContext, rc, ENCRYPTION_KEY_PATH, NULL);
    //exportPublicKey(fapiContext, rc, SIGNING_KEY_PATH, "publicKey.pem");
    //    exportPublicKey(fapiContext, rc, ENCRYPTION_KEY_PATH, "publicEncryptionKey.pem");
    //exportPublicKey(fapiContext, rc, ENCRYPTION_KEY_PATH, "licenseFile.json");
    //exportPublicKey(fapiContext, rc, "/HS/SRK/myRsaKeyToDelete", "oldPublicKey.pem");

    return 0;
}

bool isNotExpired(FAPI_CONTEXT* fapiContext, TSS2_RC* rc ,const std::string& filename) {

    size_t signatureSize;
    std::ifstream file1("licenseFile.json", std::ios::binary);

    // Check if the file was successfully opened
    if (!file1) {
        fprintf(stderr,"Error opening file for reading: %s\n","as");
    }

    // Determine the file size
    file1.seekg(0, std::ios::end);
    signatureSize = static_cast<size_t>(file1.tellg());
    file1.seekg(0, std::ios::beg);

    // Allocate memory for the signature
    uint8_t* signature = new uint8_t[signatureSize];

    // Read the file into the signature array
    file1.read(reinterpret_cast<char*>(signature), signatureSize);

    // Close the file
    file1.close();




    /*ifstream file(filename);
    if (!file) {
        throw runtime_error("Could not open file: " + filename);
    }

    string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    uint8_t* cipherText = reinterpret_cast<uint8_t*>(content.data());
    size_t cipherTextSize = content.size();

    cout<< cipherText << endl;
    cout<< cipherTextSize << endl;*/


    uint8_t* decryptedText = nullptr; // Add decryptedText parameter
    size_t decryptedTextSize = 0;
    verifyData(fapiContext, *rc, SIGNING_KEY_PATH, (const char*)signature);


    //decryptData(fapiContext, rc, cipherText, cipherTextSize, ENCRYPTION_KEY_PATH, &decryptedText, &decryptedTextSize); // Add decryptedText as parameter
    decryptData(fapiContext, rc, signature, signatureSize, ENCRYPTION_KEY_PATH, &decryptedText, &decryptedTextSize); // Add decryptedText as parameter

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

void exportPublicKey(FAPI_CONTEXT* fapiContext, TSS2_RC rc, const char* keyPath, const char* keyFile){
    char* publicKey = nullptr;

    rc = Fapi_ExportKey(fapiContext, keyPath, nullptr, &publicKey);

    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to export key: 0x%x\n", rc);
        Fapi_Finalize(&fapiContext);
    }

    printf("Key exported successfully.\n");

    std::ofstream file(keyFile);
    if (!file) {
        throw std::runtime_error("Could not open file: public.pem");
    }

    // Write the public key to the file
    nlohmann::json jsonPublicKey;
    
    jsonPublicKey = nlohmann::json::parse(publicKey);

    cout << jsonPublicKey << endl;

    //file << jsonPublicKey["pem_ext_public"].get<std::string>();
    //file << publicKey;

    // Close the file
    file.close();

    printf("Public key: %s.\n", jsonPublicKey["pem_ext_public"].get<std::string>().c_str());
}