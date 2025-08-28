#ifndef CHATSERVER_H
#define CHATSERVER_H

#include <string>
#include <winsock2.h>
#include <windows.h>
#include <thread>
#include <iostream>
#include "MyRSA.h"

#pragma comment(lib, "ws2_32.lib")

class ChatServer {
public:
    ChatServer(const std::string& ipAddress, int port);
    ~ChatServer();

    void start();

private:
    std::string serverIP;
    int serverPort;
    WSADATA wsaData;
    MyRSA rsa;
    std::string privateKey;

    void handleClient(SOCKET clientSocket);
};

#endif // CHATSERVER_H
