#include "ChatServer.h"

int main() {
    int port = 54000;
    std::string ip = "127.0.0.1";

    ChatServer server(ip, port);
    server.start();

    return 0;
}
