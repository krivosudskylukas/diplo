#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdexcept>
#include <vector>

const int PORT = 8095;
const int BUFFER_SIZE = 1024;

class NetworkException : public std::runtime_error {
public:
    NetworkException(const std::string& message)
        : std::runtime_error(message) {}
};

int main() {

    // Create a socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        
        std::cerr << "Cannot create socket" << std::endl;
        return 1;
    }

    // Define the server address to connect to
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        throw NetworkException("Connection failed");
    }

    std::cout << "Connected to server." << std::endl;

    // Send data to the server, for knowing who is connected
    std::string message = "ComputerId: 1234";
    if (send(sock, message.c_str(), message.length(), 0) < 0) {
        close(sock);
        throw NetworkException("Failed to send message");
    }

    // Read response from the server
    //char buffer[BUFFER_SIZE] = {0};

    //int bytesReceived = recv(sock, buffer, sizeof(buffer), 0);

    std::vector<char> buffer;
    char tempBuffer[BUFFER_SIZE] = {0};
    ssize_t bytesReceived = 0;

    do {
        bytesReceived = recv(sock, tempBuffer, sizeof(tempBuffer), 0);
        if (bytesReceived == -1) {
            throw std::runtime_error("Error in receiving data");
        } else if (bytesReceived == 0) {
            std::cout << "Server closed the connection" << std::endl;
        } else {    
            buffer.insert(buffer.end(), tempBuffer, tempBuffer + bytesReceived);
        }
    } while (bytesReceived > 0);


    if (buffer.empty()) {
        std::cout << "Server closed the connection" << std::endl;
    } else {
        std::string receivedData(buffer.begin(), buffer.end());
        std::cout << "Received: " << receivedData << std::endl;
    }

    // Close the socket
    close(sock);

    return 0;
}
