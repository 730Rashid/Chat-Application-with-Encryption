#ifndef CHATCLIENT_SENDER_H
#define CHATCLIENT_SENDER_H

#include <string>
#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include "MyRSA.h"

#pragma comment(lib, "ws2_32.lib")

class ChatClient {
public:
    ChatClient(const std::string& ipAddress, int port);
    ~ChatClient();

    void connectToServer();

private:
    std::string serverIP;
    int serverPort;
    WSADATA wsaData;
    MyRSA rsa;
    std::string publicKey;
};

#endif // CHATCLIENT_SENDER_H
