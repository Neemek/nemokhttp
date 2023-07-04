#include "http.hpp"
#include <iostream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <sstream>
#include <unistd.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
using namespace std;

int HTTP::open_socket(char *host, int port)
{
    int sock_fd, status;
    struct sockaddr_in serv_addr;

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        cout << "Error creating socket" << endl;
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    serv_addr.sin_addr = **(in_addr **)gethostbyname(host)->h_addr_list;

    // cout << "Got address " << inet_ntoa(serv_addr.sin_addr) << endl;

    if ((status = connect(sock_fd, (sockaddr *)&serv_addr, sizeof(serv_addr))) < 0)
    {
        cout << "Couldn't connect " << status << endl;
        return -1;
    }

    return sock_fd;
}

template <typename Enumeration>
auto as_integer(Enumeration const value)
    -> typename std::underlying_type<Enumeration>::type
{
    return static_cast<typename std::underlying_type<Enumeration>::type>(value);
}
// The payload should already have Content-Length header if body is present
std::string HTTP::serialize_http_payload(HTTP::Payload payload)
{
    stringstream serialized;

    for (std::string header : payload.headers)
    {
        serialized << header << "\r\n";
    }
    serialized << "\r\n";

    if (payload.body.size() > 0)
    {
        serialized << payload.body << "\r\n\r\n";
    }

    auto str = serialized.str();
    return str;
};

std::string HTTP::serialize_http_payload(HTTP::RequestPayload payload)
{
    stringstream serialized;

    serialized << HTTP::method_to_string(payload.method) << " " << payload.address.c_str() << " HTTP/1.1\r\n";

    Payload reg_payload;
    reg_payload.headers = payload.headers;
    reg_payload.body = payload.body;

    serialized << serialize_http_payload(reg_payload);

    auto str = serialized.str();
    return str;
};

std::string HTTP::serialize_http_payload(HTTP::ResponsePayload payload)
{
    stringstream serialized;

    serialized << "HTTP/1.1 " << std::to_string(as_integer(payload.status)).c_str() << " " << payload.readableStatus.c_str() << "\r\n";

    HTTP::Payload reg_payload;
    reg_payload.headers = payload.headers;
    reg_payload.body = payload.body;

    serialized << serialize_http_payload(reg_payload);

    auto str = serialized.str();
    return str;
};

HTTP::Payload HTTP::parse_http_payload(const char *payload)
{
    bool parsing_body = false;
    std::vector<std::string> headers;
    stringstream tmp;

    bool prev_was_newline = false;

    for (int i = 0; i < strlen(payload); i++)
    {
        char c = payload[i];
        if (!parsing_body)
        {
            if (c == '\r')
                continue;
            if (c == '\n' && !prev_was_newline)
            {
                prev_was_newline = true;
                auto str = tmp.str();
                headers.push_back(str);
                tmp.str(std::string());
                continue;
            }
            prev_was_newline = false;
        }

        tmp << c;
    }

    struct Payload data;

    auto str = tmp.str();
    data.body = str;
    data.headers = headers;

    return data;
};

HTTP::RequestPayload HTTP::parse_http_request_payload(char *payload)
{
    HTTP::RequestPayload data;
    char *fields[3] = {};
    int spaces = 0;
    char *tmp = "";

    int status = 0;

    for (int i = 0; i < strlen(payload); i++)
    {
        char c = payload[i];
        if (c == '\r')
            continue;

        if (c == '\n')
        {
            std::string as_string = std::string(payload);
            HTTP::Payload reg_data = HTTP::parse_http_payload((char *)as_string.substr(i + 1).c_str());

            data.body = reg_data.body;
            data.headers = reg_data.headers;
            break;
        }

        if (c == ' ')
        {
            fields[spaces++] = tmp;
            tmp = "";
            continue;
        }

        strcat(tmp, (char *)c);
    }

    data.address = fields[1];
    data.method = method_from_string(fields[0]);

    return data;
};

HTTP::ResponsePayload HTTP::parse_http_response_payload(char *payload)
{
    HTTP::ResponsePayload data;
    std::string fields[3] = {};
    int spaces = 0;
    stringstream tmp;

    for (int i = 0; i < strlen(payload); i++)
    {
        char c = payload[i];
        if (c == '\r')
            continue;

        if (c == '\n')
        {
            std::string as_string = std::string(payload);
            HTTP::Payload reg_data = HTTP::parse_http_payload((char *)as_string.substr(i + 1).c_str());

            data.body = reg_data.body;
            data.headers = reg_data.headers;
            break;
        }

        if (c == ' ' && spaces < 2)
        {
            auto str = tmp.str();
            fields[spaces++] = str;
            tmp.str(std::string());
            continue;
        }

        tmp << c;
    }

    data.statusCode = stoi(fields[1]);
    data.status = static_cast<HTTP::Status>(data.statusCode);
    auto str = tmp.str();
    data.readableStatus = (char *)str.c_str();

    return data;
};

HTTP::ResponsePayload HTTP::perform_http(char *host, int port, RequestPayload payload)
{
    return perform_http(host, port, payload, 2 << 11);
}

HTTP::ResponsePayload HTTP::perform_http(char *host, int port, HTTP::RequestPayload payload, int nBytes)
{
    int sock_fd = HTTP::open_socket(host, port);

    bool hasHost = false;
    for (int i = 0; i < payload.headers.size(); i++)
    {
        if (payload.headers.at(i).rfind("Host:", 0) == 0)
        {
            hasHost = true;
            break;
        }
    }

    if (!hasHost)
    {
        payload.headers.push_back(((string) "Host: ") + (string)host);
    }

    std::string serialized_payload = HTTP::serialize_http_payload(payload);
    write(sock_fd, serialized_payload.c_str(), strlen(serialized_payload.c_str()));

    char buffer[nBytes] = {0};
    read(sock_fd, &buffer, nBytes);

    close(sock_fd);

    HTTP::ResponsePayload parsed = HTTP::parse_http_response_payload(buffer);

    return parsed;
};

SSL_CTX *create_ssl_context()
{
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (ctx == nullptr)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

HTTP::ResponsePayload HTTP::perform_https(SSL_CTX *ctx, char *host, int port, RequestPayload payload)
{
    return HTTP::perform_https(ctx, host, port, payload, 2 << 11);
}

HTTP::ResponsePayload HTTP::perform_https(SSL_CTX *ctx, char *host, int port, HTTP::RequestPayload payload, int nBytes)
{
    std::cout << "Doing https" << std::endl;
    int sock_fd = HTTP::open_socket(host, port);
    std::cout << "Opened socket" << std::endl;
    SSL *ssl = SSL_new(ctx);

    if (ssl == nullptr)
    {
        std::cout << "ssl was nullptr" << std::endl;
        ERR_print_errors_fp(stdout);
        exit(EXIT_FAILURE);
    }

    std::cout << "set fd" << std::endl;
    SSL_set_fd(ssl, sock_fd);

    int status;
    if ((status = SSL_connect(ssl)) != 1)
    {
        HTTP::ResponsePayload res;
        return res;
    }
    std::cout << "Connected" << std::endl;

    bool hasHost = false;
    for (int i = 0; i < payload.headers.size(); i++)
    {
        if (payload.headers.at(i).rfind("Host:", 0) == 0)
        {
            hasHost = true;
            break;
        }
    }

    if (!hasHost)
    {
        payload.headers.push_back(((string) "Host: ") + (string)host);
    }

    printf("fixed headers\n");

    std::string serialized_payload = serialize_http_payload(payload);
    SSL_write(ssl, serialized_payload.c_str(), strlen(serialized_payload.c_str()));

    char buffer[nBytes] = {0};
    SSL_read(ssl, &buffer, nBytes);

    HTTP::ResponsePayload parsed = parse_http_response_payload(buffer);

    SSL_free(ssl);
    close(sock_fd);

    return parsed;
};

const char *HTTP::method_to_string(HTTP::Method m)
{
    switch (m)
    {
    case HTTP::Method::GET:
        return "GET";
    case HTTP::Method::HEAD:
        return "HEAD";
    case HTTP::Method::POST:
        return "POST";
    case HTTP::Method::PUT:
        return "PUT";
    case HTTP::Method::DELETE:
        return "DELETE";
    case HTTP::Method::CONNECT:
        return "CONNECT";
    case HTTP::Method::OPTIONS:
        return "OPTIONS";
    case HTTP::Method::TRACE:
        return "TRACE";
    case HTTP::Method::PATCH:
        return "PATCH";
    default:
        return "NONE";
    }
};

HTTP::Method HTTP::method_from_string(const char *m)
{
    const char *methods[] = {
        "GET",
        "HEAD",
        "POST",
        "PUT",
        "DELETE",
        "CONNECT",
        "OPTIONS",
        "TRACE"};

    for (int i = 0; i < sizeof(methods); i++)
    {
        if (methods[i] == m)
            return static_cast<HTTP::Method>(i);
    }

    return HTTP::Method::GET;
};

HTTP::Client::Client(char *host)
{
    this->targetHost = host;
    this->ctx = create_ssl_context();
}

HTTP::Client::~Client()
{
    SSL_CTX_free(this->ctx);
}

void HTTP::Client::clear_headers()
{
    this->headers.clear();
}

void HTTP::Client::set_header(char *name, char *value)
{
    this->headers[name] = value;
}

HTTP::ResponsePayload HTTP::Client::request(RequestPayload payload)
{
    return this->request(this->targetHost, payload);
}

HTTP::ResponsePayload HTTP::Client::request(char *host, RequestPayload payload)
{
    return this->request(this->targetHost, this->determine_port(), payload);
}

HTTP::ResponsePayload HTTP::Client::request(char *host, int port, RequestPayload payload)
{
    if (this->secure)
        return perform_https(this->ctx, host, port, payload);
    else
        return perform_http(host, port, payload);
}

HTTP::ResponsePayload HTTP::Client::request(char *host, int port, char *address, Method method)
{
    return this->request(host, port, address, method, "");
}

HTTP::ResponsePayload HTTP::Client::request(char *host, int port, char *address, Method method, char *body)
{
    RequestPayload payload;

    payload.address = address;
    payload.method = method;
    payload.body = body;

    for (auto const &h : this->headers)
    {
        stringstream combined;

        combined << h.first << ": " << h.second;

        auto str = combined.str();
        payload.headers.push_back((char *)str.c_str());
    }

    return this->request(host, port, payload);
}

int HTTP::Client::determine_port()
{
    return this->secure ? 443 : 80;
}

HTTP::ResponsePayload HTTP::Client::get(char *address)
{
    return this->get(address, this->targetHost);
}

HTTP::ResponsePayload HTTP::Client::get(char *address, char *host)
{
    return this->get(address, host, this->determine_port());
}

HTTP::ResponsePayload HTTP::Client::get(char *address, char *host, int port)
{
    return this->request(host, port, address, Method::GET);
}

HTTP::ResponsePayload HTTP::Client::head(char *address)
{
    return this->head(address, this->targetHost);
}

HTTP::ResponsePayload HTTP::Client::head(char *address, char *host)
{
    return this->head(address, host);
}

HTTP::ResponsePayload HTTP::Client::head(char *address, char *host, int port)
{
    return this->request(host, port, address, Method::HEAD);
}

// the Content-Length header should not be set
HTTP::ResponsePayload HTTP::Client::post(char *address, char *body)
{
    return this->post(address, body, this->targetHost);
}

// the Content-Length header should not be set
HTTP::ResponsePayload HTTP::Client::post(char *address, char *body, char *host)
{
    return this->post(address, body, host, this->determine_port());
}

// the Content-Length header should not be set
HTTP::ResponsePayload HTTP::Client::post(char *address, char *body, char *host, int port)
{
    return this->request(host, port, address, Method::POST, body);
}

// the Content-Length header should not be set
HTTP::ResponsePayload HTTP::Client::put(char *address, char *body)
{
    return this->put(address, body, this->targetHost);
}

// the Content-Length header should not be set
HTTP::ResponsePayload HTTP::Client::put(char *address, char *body, char *host)
{
    return this->put(address, body, host, this->determine_port());
}

// the Content-Length header should not be set
HTTP::ResponsePayload HTTP::Client::put(char *address, char *body, char *host, int port)
{
    return this->request(host, port, address, Method::PUT, body);
}

HTTP::ResponsePayload HTTP::Client::delet(char *address)
{
    return this->delet(address, this->targetHost);
}

HTTP::ResponsePayload HTTP::Client::delet(char *address, char *host)
{
    return this->delet(address, host, this->determine_port());
}

HTTP::ResponsePayload HTTP::Client::delet(char *address, char *host, int port)
{
    return this->request(host, port, address, Method::DELETE);
}

HTTP::ResponsePayload HTTP::Client::connect(char *address)
{
    return this->connect(address, this->targetHost);
}

HTTP::ResponsePayload HTTP::Client::connect(char *address, char *host)
{
    return this->connect(address, host, this->determine_port());
}

HTTP::ResponsePayload HTTP::Client::connect(char *address, char *host, int port)
{
    return this->request(host, port, address, Method::CONNECT);
}

HTTP::ResponsePayload HTTP::Client::options(char *address)
{
    return this->options(address, this->targetHost);
}

HTTP::ResponsePayload HTTP::Client::options(char *address, char *host)
{
    return this->options(address, host, this->determine_port());
}

HTTP::ResponsePayload HTTP::Client::options(char *address, char *host, int port)
{
    return this->request(host, port, address, Method::OPTIONS);
}

HTTP::ResponsePayload HTTP::Client::trace(char *address)
{
    return this->trace(address, this->targetHost);
}

HTTP::ResponsePayload HTTP::Client::trace(char *address, char *host)
{
    return this->trace(address, host, this->determine_port());
}

HTTP::ResponsePayload HTTP::Client::trace(char *address, char *host, int port)
{
    return this->request(host, port, address, Method::TRACE);
}

// the Content-Length header should not be set
HTTP::ResponsePayload HTTP::Client::patch(char *address, char *body)
{
    return this->patch(address, body, this->targetHost);
}

// the Content-Length header should not be set
HTTP::ResponsePayload HTTP::Client::patch(char *address, char *body, char *host)
{
    return this->patch(address, body, host, this->determine_port());
}

// the Content-Length header should not be set
HTTP::ResponsePayload HTTP::Client::patch(char *address, char *body, char *host, int port)
{
    return this->request(host, port, address, Method::PATCH, body);
}
