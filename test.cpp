#include "http.hpp"
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
using namespace HTTP;

int main()
{
    Client client("www.google.com");
    std::cout << "Initialized client :P" << std::endl;

    ResponsePayload res = client.get("/");
    std::cout << "Fetched route" << std::endl;
    std::cout << serialize_http_payload(res);

    return 0;
}
