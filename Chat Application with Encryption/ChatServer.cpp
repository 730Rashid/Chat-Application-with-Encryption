#include "ChatServer.h"
#include <ws2tcpip.h>

ChatServer::ChatServer(const std::string& ipAddress, int port) {
    serverIP = ipAddress;
    serverPort = port;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    rsa.generateKeys();
    privateKey = rsa.getPrivateKey();
}

ChatServer::~ChatServer() {
    WSACleanup();
}

void ChatServer::start() {
    SOCKET serverSocket;
    struct sockaddr_in serverAddr, clientAddr;
    int clientAddrLen = sizeof(clientAddr);

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed!" << std::endl;
        return;
    }

    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr);
    serverAddr.sin_port = htons(serverPort);

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed!" << std::endl;
        return;
    }

    listen(serverSocket, 3);

    std::cout << "Server listening on " << serverIP << ":" << serverPort << "..." << std::endl;

    SOCKET clientSocket;
    while ((clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen)) != INVALID_SOCKET) {
        std::cout << "Client connected!" << std::endl;
        std::thread(&ChatServer::handleClient, this, clientSocket).detach();
    }
}

void ChatServer::handleClient(SOCKET clientSocket) {
    std::string publicKey = rsa.getPublicKey();
    send(clientSocket, publicKey.c_str(), publicKey.length(), 0);

    char buffer[2048]; // Increased buffer size for encrypted data
    int recvSize;
    while ((recvSize = recv(clientSocket, buffer, sizeof(buffer), 0)) > 0) {
        std::string encryptedMessage(buffer, recvSize);
        std::string decryptedMessage = rsa.decrypt(privateKey, encryptedMessage);
        std::cout << "Received encrypted message: " << encryptedMessage << std::endl;
        std::cout << "Decrypted message: " << decryptedMessage << std::endl;

        // Echo back the encrypted message
        send(clientSocket, encryptedMessage.c_str(), encryptedMessage.length(), 0);
    }
    std::cout << "Client disconnected." << std::endl;
    closesocket(clientSocket);
}
