#include "ChatServer.h"

ChatServer::ChatServer(const std::string& ipAddress, int port) {
    serverIP = ipAddress;
    serverPort = port;
    WSAStartup(MAKEWORD(2, 2), &wsaData);  // Initialize Winsock
}

ChatServer::~ChatServer() {
    WSACleanup();  // Cleanup Winsock
}

void ChatServer::start() {
    SOCKET serverSocket;
    struct sockaddr_in serverAddr, clientAddr;
    int clientAddrLen = sizeof(clientAddr);

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);  // Create socket
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed!" << std::endl;
        return;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(serverIP.c_str());
    serverAddr.sin_port = htons(serverPort);

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed!" << std::endl;
        return;
    }

    listen(serverSocket, 3);  // Listen for incoming connections

    std::cout << "Server listening on " << serverIP << ":" << serverPort << "..." << std::endl;

    // Accept and handle client connections
    SOCKET clientSocket;
    while ((clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen)) != INVALID_SOCKET) {
        std::cout << "Client connected!" << std::endl;
        std::thread(&ChatServer::handleClient, this, clientSocket).detach();
    }
}

void ChatServer::handleClient(SOCKET clientSocket) {
    char buffer[1024];
    int recvSize;
    while ((recvSize = recv(clientSocket, buffer, sizeof(buffer), 0)) > 0) {
        buffer[recvSize] = '\0';
        std::cout << "Received message: " << buffer << std::endl;

        // Simple echo back to the client
        send(clientSocket, buffer, recvSize, 0);
    }
    std::cout << "Client disconnected." << std::endl;
    closesocket(clientSocket);
}
