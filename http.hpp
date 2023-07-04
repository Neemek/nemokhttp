#ifndef HTTPLIB_H_INCLUDED
#define HTTPLIB_H_INCLUDED

#include <vector>
#include <string.h>
#include <map>
#include <openssl/ssl.h>

enum HTTPMethod
{
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    PATCH
};

// Official standardised status codes
enum HTTPStatus
{
    Continue = 100,           // Informational response
    SwitchingProtocols = 101, // Informational response
    Processing = 102,         // Informational response
    EarlyHints = 103,         // Informational response

    OK = 200,                        // Success
    Created = 201,                   // Success
    Accepted = 202,                  // Success
    NonAuthoritiveInformation = 203, // Success
    NoContent = 204,                 // Success
    ResetContent = 205,              // Success
    PartialContent = 206,            // Success
    MultiStatus = 207,               // Success
    AlreadyReported = 208,           // Success
    IMUsed = 226,                    // Success

    MultipleChoices = 300,   // Redirection
    MovedPermanently = 301,  // Redirection
    Found = 302,             // Redirection - Previously "Moved Temporarily"
    SeeOther = 303,          // Redirection
    NotModified = 304,       // Redirection
    UseProxy = 305,          // Redirection
    SwitchProxy = 306,       // Redirection
    TemporaryRedirect = 307, // Redirection
    PermanentRedirect = 308, // Redirection

    BadRequest = 400,                  // Client error
    Unauthorized = 401,                // Client error
    PaymentRequired = 402,             // Client error
    Forbidden = 403,                   // Client error
    NotFound = 404,                    // Client error
    MethodNotAllowed = 405,            // Client error
    NotAcceptable = 406,               // Client error
    ProxyAuthenticationRequired = 407, // Client error
    RequestTimeout = 408,              // Client error
    Conflict = 409,                    // Client error
    Gone = 410,                        // Client error
    LengthRequired = 411,              // Client error
    PreconditionFailed = 412,          // Client error
    PayloadTooLarge = 413,             // Client error
    URITooLong = 414,                  // Client error
    UnsupportedMediaType = 415,        // Client error
    RangeNotSatisfiable = 416,         // Client error
    ExpectationFailed = 417,           // Client error
    ImATeapot = 418,                   // Client error
    MisdirectedRequest = 421,          // Client error
    UnprocessableEntity = 422,         // Client error
    Locked = 423,                      // Client error
    FailedDependency = 424,            // Client error
    TooEarly = 425,                    // Client error
    UpgradeRequired = 426,             // Client error
    PreconditionRequired = 428,        // Client error
    TooManyRequests = 429,             // Client error
    RequestHeaderFieldsTooLarge = 431, // Client error
    UnavailableForLegalReasons = 451,  // Client error

    InternalServerError = 500,          // Server error
    NotImplemented = 501,               // Server error
    BadGateway = 502,                   // Server error
    ServiceUnavailable = 503,           // Server error
    GatewayTimeout = 504,               // Server error
    HTTPVersionNotSupported = 505,      // Server error
    VariantAlsoNegotiates = 506,        // Server error
    InsufficientStorage = 507,          // Server error
    LoopDetected = 508,                 // Server error
    NotExtended = 510,                  // Server error
    NetworkAuthenticationRequired = 511 // Server error
};

struct HTTPPayload
{
    std::string body;
    std::vector<std::string> headers;
};

struct HTTPResponsePayload : HTTPPayload
{
    int statusCode;
    HTTPStatus status; // for standardized codes
    std::string readableStatus;
};

struct HTTPRequestPayload : HTTPPayload
{
    HTTPMethod method;
    std::string address;
};

int open_socket(char *host, int port);

const char *method_to_string(HTTPMethod m);
HTTPMethod method_from_string(const char *m);

HTTPResponsePayload perform_http(char *host, int port, HTTPRequestPayload payload, int nBytes);
HTTPResponsePayload perform_http(char *host, int port, HTTPRequestPayload payload);

SSL_CTX *create_ssl_context(void);
HTTPResponsePayload perform_https(SSL_CTX *ctx, char *host, int port, HTTPRequestPayload payload, int nBytes);
HTTPResponsePayload perform_https(SSL_CTX *ctx, char *host, int port, HTTPRequestPayload payload);

HTTPPayload parse_http_payload(const char *payload);
HTTPRequestPayload parse_http_request_payload(const char *payload);
HTTPResponsePayload parse_http_response_payload(const char *payload);

std::string serialize_http_payload(HTTPPayload payload);
std::string serialize_http_payload(HTTPRequestPayload payload);
std::string serialize_http_payload(HTTPResponsePayload payload);

class HTTPClient
{
public:
    HTTPClient(char *host);
    ~HTTPClient();

    void clear_headers();
    void set_header(char *name, char *value);

    int determine_port();

    char *targetHost;
    bool secure = true;

    HTTPResponsePayload request(HTTPRequestPayload payload);
    HTTPResponsePayload request(char *host, HTTPRequestPayload requestData);               // does not change target
    HTTPResponsePayload request(char *host, int port, HTTPRequestPayload requestData);               // does not change target
    HTTPResponsePayload request(char *host, int port, char *address, HTTPMethod method);             // does not change target
    HTTPResponsePayload request(char *host, int port, char *address, HTTPMethod method, char *body); // does not change target

    HTTPResponsePayload get(char *address);
    HTTPResponsePayload get(char *address, char *host);
    HTTPResponsePayload get(char *address, char *host, int port);
    HTTPResponsePayload head(char *address);
    HTTPResponsePayload head(char *address, char *host);
    HTTPResponsePayload head(char *address, char *host, int port);
    HTTPResponsePayload post(char *address, char *body);                       // the Content-Length header should not be set
    HTTPResponsePayload post(char *address, char *body, char *host);           // the Content-Length header should not be set
    HTTPResponsePayload post(char *address, char *body, char *host, int port); // the Content-Length header should not be set
    HTTPResponsePayload put(char *address, char *body);
    HTTPResponsePayload put(char *address, char *body, char *host);
    HTTPResponsePayload put(char *address, char *body, char *host, int port);
    HTTPResponsePayload delet(char *address);
    HTTPResponsePayload delet(char *address, char *host);
    HTTPResponsePayload delet(char *address, char *host, int port);
    HTTPResponsePayload connect(char *address);
    HTTPResponsePayload connect(char *address, char *host);
    HTTPResponsePayload connect(char *address, char *host, int port);
    HTTPResponsePayload options(char *address);
    HTTPResponsePayload options(char *address, char *host);
    HTTPResponsePayload options(char *address, char *host, int port);
    HTTPResponsePayload trace(char *address);
    HTTPResponsePayload trace(char *address, char *host);
    HTTPResponsePayload trace(char *address, char *host, int port);
    HTTPResponsePayload patch(char *address, char *body);
    HTTPResponsePayload patch(char *address, char *body, char *host);
    HTTPResponsePayload patch(char *address, char *body, char *host, int port);

private:
    std::map<std::string, std::string> headers;

    SSL_CTX *ctx;
};

#endif