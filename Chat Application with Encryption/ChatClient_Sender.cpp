#include "ChatClient_Sender.h"

ChatClient::ChatClient(const std::string& ipAddress, int port) {
    serverIP = ipAddress;
    serverPort = port;
    WSAStartup(MAKEWORD(2, 2), &wsaData);  // Initialize Winsock
}

ChatClient::~ChatClient() {
    WSACleanup();  // Cleanup Winsock
}

void ChatClient::connectToServer() {
    SOCKET clientSocket;
    struct sockaddr_in serverAddr;

    clientSocket = socket(AF_INET, SOCK_STREAM, 0);  // Create socket
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed!" << std::endl;
        return;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(serverIP.c_str());
    serverAddr.sin_port = htons(serverPort);

    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Connection failed!" << std::endl;
        return;
    }

    std::cout << "Connected to server at " << serverIP << ":" << serverPort << std::endl;

    // Send message
    std::string message;
    while (true) {
        std::cout << "Enter message: ";
        std::getline(std::cin, message);
        send(clientSocket, message.c_str(), message.length(), 0);

        // Receive server's response
        char buffer[1024];
        int recvSize = recv(clientSocket, buffer, sizeof(buffer), 0);
        buffer[recvSize] = '\0';
        std::cout << "Server says: " << buffer << std::endl;

        if (message == "exit") break;  // Exit condition
    }

    closesocket(clientSocket);
}

