#include <cstring> 
#include <iostream> 
#include <fstream>
#include <tss2/tss2_fapi.h>
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <unistd.h> 
#include <sstream>
#include "../code/diplo/headers/crypto_operations.h"
#include "../code/diplo/headers/verify.h"

//  g++ -o serverApp server.cpp ../code/diplo/sources/crypto_operations.cpp ../code/diplo/sources/verify.cpp -L/usr/local/lib -ltss2-fapi -lssl -lcrypto -lcurl

using namespace std; 

const char* ENCRYPTION_KEY_PATH = "/HS/SRK/cryptographyRsaKey";
const char* SIGNING_KEY_PATH = "/HS/SRK/signingRsaKey";

struct Request {
    string method;
    string path;
    // Add other fields as needed
};

Request deserializeRequest(const string& str) {
    istringstream iss(str);
    Request req;
    iss >> req.method >> req.path;
    // Deserialize other fields as needed
    return req;
}

int main() 
{ 
    FAPI_CONTEXT* fapiContext;
    TSS2_RC rc;

    // Initialize the FAPI context
    rc = Fapi_Initialize(&fapiContext, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to initialize FAPI context: 0x%x\n", rc);
        return 1;
    }

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0); 
    if (serverSocket == -1) {
        cerr << "Failed to create socket";
        return 1;
    }

    const string licenseFile = "/home/lukas/diplo/code/diplo/licenseFile.json";
    const string key = "/home/lukas/diplo/code/diplo/publicTest.pem";
    const string sig = "/home/lukas/diplo/code/diplo/base64Signature.bin";

    
   // Construct the command string
    std::string command = "openssl dgst -sha256 -verify " + key +
                          " -signature " + sig + " " + licenseFile;

    int result = system(command.c_str());
    if (result == 0) {
        std::cout << "Command executed successfully.\n";
    } else {
        std::cout << "Command execution failed with code: " << result << "\n";
    }


    ifstream file(licenseFile);
    if (!file) {
        throw runtime_error("Could not open file: " + licenseFile);
    }

    string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    uint8_t* cipherText = reinterpret_cast<uint8_t*>(content.data());
    size_t cipherTextSize = content.size();


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
    signatureSize = static_cast<size_t>(file.tellg());
    signatureFile.seekg(0, std::ios::beg);

    // Allocate memory for the signature
    uint8_t* signature = new uint8_t[signatureSize];

    // Read the file into the signature array
    signatureFile.read(reinterpret_cast<char*>(signature), signatureSize);

    // Close the file
    signatureFile.close();



    int respo = verifyDataWithSignatureParam(fapiContext, rc, 
    SIGNING_KEY_PATH, (const char*)cipherText,  signature, signatureSize);

    if (respo != 0) {
        throw std::runtime_error("Signature verification failed");
    } 

    sockaddr_in serverAddress; 
    serverAddress.sin_family = AF_INET; 
    serverAddress.sin_port = htons(8095); 
    serverAddress.sin_addr.s_addr = INADDR_ANY; 

    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
        cerr << "Failed to bind socket";
        return 1;
    }

    if (listen(serverSocket, 5) == -1) {
        cerr << "Failed to listen on socket";
        return 1;
    }

    int clientSocket;
    while ((clientSocket = accept(serverSocket, nullptr, nullptr)) != -1)
    {
        cout << "Client connected" << endl;
        //write(clientSocket, "Response", 9);

        char buffer[1024] = { 0 }; 
        recv(clientSocket, buffer, sizeof(buffer), 0); 

        Request req = deserializeRequest(buffer);
        cout << "Received request: " << req.method << " " << req.path << endl;

        // Add code to handle the request
        ifstream file("/home/lukas/diplo/code/diplo/licenseFile.json");
        if (!file) {
            throw runtime_error("Could not open file: licenseFile.json");
        }

        string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

        uint8_t* cipherText = reinterpret_cast<uint8_t*>(content.data());
        size_t cipherTextSize = content.size();
        uint8_t* decryptedText = nullptr; // Add decryptedText parameter
        size_t decryptedTextSize = 0;
        
        decryptData(fapiContext, &rc, cipherText, cipherTextSize, ENCRYPTION_KEY_PATH, &decryptedText, &decryptedTextSize); // Add decryptedText as parameter
        cout << decryptedText << endl;


        size_t bodyLength = string(reinterpret_cast<char*>(decryptedText)).size(); // ensure decryptedText is valid
        string httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + to_string(bodyLength) + "\r\n\r\n" + string(reinterpret_cast<char*>(decryptedText));


        write(clientSocket, decryptedText, bodyLength);

        close(clientSocket);

        } 

    if (clientSocket == -1) {
        cerr << "Failed to accept connection";
        return 1;
    }

    close(serverSocket); 

    return 0; 
}
