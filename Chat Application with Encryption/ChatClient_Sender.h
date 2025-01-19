#ifndef CHATCLIENT_H
#define CHATCLIENT_H

#include <string>
#include <winsock2.h>
#include <windows.h>
#include <iostream>

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
};

#endif // SECURE_CHAT_CLIENT_H

