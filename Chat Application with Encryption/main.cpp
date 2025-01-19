#include <iostream>
#include <thread>
#include "ChatServer.h"
#include "ChatClient_Sender.h"

int main() {
    int port = 54000;
    std::string ip = "127.0.0.1";  // Localhost

    ChatServer server(ip, port);
    std::thread serverThread(&ChatServer::start, &server);

    ChatClient client(ip, port);
    std::this_thread::sleep_for(std::chrono::seconds(1));  // Allow server to start
    client.connectToServer();

    serverThread.join();  // Wait for server to finish
    return 0;
}
