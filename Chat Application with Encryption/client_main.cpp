#include "ChatClient_Sender.h"

int main() {
    int port = 54000;
    std::string ip = "127.0.0.1";

    ChatClient client(ip, port);
    client.connectToServer();

    return 0;
}
