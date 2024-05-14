#include <curl/curl.h>
#include <iostream>
#include <cstring>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <fstream>
#include <vector>   
#include <nlohmann/json.hpp>    
#include <openssl/bio.h>
#include <tss2/tss2_fapi.h>
#include "../code/diplo/headers/fapi_util.h"
#include "../code/diplo/headers/file_util.h"
#include "../code/diplo/headers/verify.h"
#include "../code/diplo/headers/crypto_operations.h"

using json = nlohmann::json;

const char* SIGNING_KEY_PATH = "/HS/SRK/signingRsaKey";
const string licenseFile = "/home/lukas/diplo/code/diplo/licenseFile.json";



// Callback function for reading the response data from request
size_t callbackFunction(char* ptr, size_t size, size_t nmemb, std::string* data) {
    data->append(ptr, size * nmemb);
    return size * nmemb;
}

void callVerifyApi(const string &filename){
    FAPI_CONTEXT* fapiContext;
    TSS2_RC rc;

    size_t fileSize;
    rc = initFapiContext(&fapiContext);

    std::ifstream file1(licenseFile, std::ios::binary);

    // Check if the file was successfully opened
    if (!file1) {
        fprintf(stderr,"Error opening file for reading: %s\n","as");
    }

    // Determine the file size
    file1.seekg(0, std::ios::end);
    fileSize = static_cast<size_t>(file1.tellg());
    file1.seekg(0, std::ios::beg);

    // Allocate memory for the signature
    uint8_t* fileContent = new uint8_t[fileSize];

    // Read the file into the signature array
    file1.read(reinterpret_cast<char*>(fileContent), fileSize);

    // Close the file
    file1.close();
    /*ifstream file(filename);
    if (!file) {
        throw runtime_error("Could not open file: " + filename);
    }

    string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    uint8_t* cipherText = reinterpret_cast<uint8_t*>(content.data());
    size_t cipherTextSize = content.size();*/


    // Read the signature from the file
    const char* signatureFilename = "/home/lukas/diplo/code/diplo/signature.bin";
    std::ifstream signatureFile(signatureFilename, std::ios::binary);
    size_t signatureSize;

    // Check if the file was successfully opened
    if (!signatureFile) {
        fprintf(stderr,"Error opening file for reading: %s\n", signatureFilename);
        throw std::runtime_error("Error opening file for reading");
    }
    
    // Determine the file size
    signatureFile.seekg(0, std::ios::end);
    signatureSize = static_cast<size_t>(signatureFile.tellg());
    signatureFile.seekg(0, std::ios::beg);

    // Allocate memory for the signature
    uint8_t* signature = new uint8_t[signatureSize];

    // Read the file into the signature array
    signatureFile.read(reinterpret_cast<char*>(signature), signatureSize);

    // Close the file
    signatureFile.close();


    int respo = verifyDataWithSignatureParam(fapiContext, rc, SIGNING_KEY_PATH, (const char*)fileContent,  signature, signatureSize);

    if (respo != 0)
    {

        CURL* curl;
	    CURLcode res;
	    std::string readBuffer;  // String to hold the response

	    curl_global_init(CURL_GLOBAL_DEFAULT); // Initialize global curl settings
	    curl = curl_easy_init();  // Initialize a curl handle

	    if (curl) {
		
		// Set the URL for the REST API endpoint
		cout << "Sending request to server...\n";
		curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:8084/api/hello");
		

		nlohmann::json j;
		j["customerId"] = 1;
		j["customerName"] = "Kramare";

		// Convert the JSON to a string
		std::string postData = j.dump();
		
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

		cout << "Request sent\n";
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
    }
    else
    {
        auto now = std::chrono::system_clock::now();
        std::time_t now_time = std::chrono::system_clock::to_time_t(now);
        std::cout << "Timestamp: " << std::ctime(&now_time) << "Signature check job ended successfully.\n";    
    }
}


int main() {
    callVerifyApi(licenseFile);
    return 0;
}
