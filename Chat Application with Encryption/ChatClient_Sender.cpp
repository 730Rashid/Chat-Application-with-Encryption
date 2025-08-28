#include "ChatClient_Sender.h"
#include <ws2tcpip.h>

ChatClient::ChatClient(const std::string& ipAddress, int port) {
    serverIP = ipAddress;
    serverPort = port;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

ChatClient::~ChatClient() {
    WSACleanup();
}

void ChatClient::connectToServer() {
    SOCKET clientSocket;
    struct sockaddr_in serverAddr;

    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed!" << std::endl;
        return;
    }

    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr);
    serverAddr.sin_port = htons(serverPort);

    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Connection failed!" << std::endl;
        return;
    }

    std::cout << "Connected to server at " << serverIP << ":" << serverPort << std::endl;

    // Receive the public key from the server
    char keyBuffer[2048];
    int keySize = recv(clientSocket, keyBuffer, sizeof(keyBuffer), 0);
    publicKey = std::string(keyBuffer, keySize);
    std::cout << "Received Public Key:\n" << publicKey << std::endl;

    std::string message;
    while (true) {
        std::cout << "Enter message: ";
        std::getline(std::cin, message);

        std::string encryptedMessage = rsa.encrypt(publicKey, message);
        send(clientSocket, encryptedMessage.c_str(), encryptedMessage.length(), 0);

        // Receive server's response
        char buffer[2048];
        int recvSize = recv(clientSocket, buffer, sizeof(buffer), 0);
        std::cout << "Server's encrypted echo: " << std::string(buffer, recvSize) << std::endl;

        if (message == "exit") break;
    }

    closesocket(clientSocket);
}
