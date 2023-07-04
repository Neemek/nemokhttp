#include <iostream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include "http.hpp"
using namespace std;

#define METHOD "GET"


int main(int argc, char* argv[])
{
    if (argc != 4) {
        cout << "Need 3 arguments (got "<< argc-1 <<"). HOST PORT ROUTE" << endl;
        return -1;
    }
    
    char* HOST = argv[1], *ROUTE = argv[3];
    int PORT = stoi(argv[2]);

    cout << "Fetching " << HOST << " route " << ROUTE << " port " << PORT << " with " << METHOD << endl;
    
    int sock_fd = open_socket(HOST, PORT);

    char* message = "GET / HTTP/1.1\r\nHost: ";
    strcat(message, HOST);
    strcat(message, "\r\n\r\n");

    send(sock_fd, message, strlen(message), 0);
    char* buffer[8192] = { 0 };
    read(sock_fd, buffer, 8192);

    printf("%s\n", buffer);

    close(sock_fd);
    return 0;
}
