#ifdef _WIN32

#define _WIN32_WINNT 0x0601

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")

#else

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <curl/curl.h>

#define SOCKET int
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)

#endif

#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <sstream>

#define ll long long

using namespace std;

const string VT_API_KEY =
    "03982ccb3228d389f284ba569850736c2f340eddcc0b0e11be5460b9cb1ab3f4";

#ifdef _WIN32

string vtRequest(string domain)
{
    HINTERNET hSession = WinHttpOpen(
        L"CyberGuard/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!hSession)
        return "";

    string path =
        "/api/v3/domains/" + domain;

    wstring wpath(
        path.begin(),
        path.end()
    );

    HINTERNET hConnect = WinHttpConnect(
        hSession,
        L"www.virustotal.com",
        INTERNET_DEFAULT_HTTPS_PORT,
        0
    );

    if (!hConnect)
    {
        WinHttpCloseHandle(hSession);
        return "";
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        wpath.c_str(),
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );

    if (!hRequest)
    {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    string header =
        "x-apikey: " + VT_API_KEY + "\r\n";

    wstring wheader(
        header.begin(),
        header.end()
    );

    BOOL ok = WinHttpAddRequestHeaders(
        hRequest,
        wheader.c_str(),
        -1,
        WINHTTP_ADDREQ_FLAG_ADD
    );

    string result;

    if (ok &&
        WinHttpSendRequest(
            hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            WINHTTP_NO_REQUEST_DATA,
            0,
            0,
            0
        ) &&
        WinHttpReceiveResponse(
            hRequest,
            NULL
        ))
    {
        DWORD size = 0;

        do
        {
            if (!WinHttpQueryDataAvailable(
                    hRequest,
                    &size))
                break;

            if (size == 0)
                break;

            char *buffer =
                new char[size + 1];

            DWORD read = 0;

            if (WinHttpReadData(
                    hRequest,
                    buffer,
                    size,
                    &read))
            {
                buffer[read] = '\0';
                result += buffer;
            }

            delete[] buffer;

        } while (size > 0);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return result;
}

#else

size_t writeCallback(
    void *contents,
    size_t size,
    size_t nmemb,
    void *userp
)
{
    size_t total =
        size * nmemb;

    string *result =
        (string *)userp;

    result->append(
        (char *)contents,
        total
    );

    return total;
}

string vtRequest(string domain)
{
    CURL *curl =
        curl_easy_init();

    if (!curl)
        return "";

    string url =
        "https://www.virustotal.com/api/v3/domains/" +
        domain;

    string result;

    struct curl_slist *headers =
        NULL;

    string apiHeader =
        "x-apikey: " + VT_API_KEY;

    headers =
        curl_slist_append(
            headers,
            apiHeader.c_str()
        );

    curl_easy_setopt(
        curl,
        CURLOPT_URL,
        url.c_str()
    );

    curl_easy_setopt(
        curl,
        CURLOPT_HTTPHEADER,
        headers
    );

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEFUNCTION,
        writeCallback
    );

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEDATA,
        &result
    );

    curl_easy_setopt(
        curl,
        CURLOPT_TIMEOUT,
        20L
    );

    CURLcode res =
        curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK)
        return "";

    return result;
}

#endif

string getDomain(string url)
{
    size_t p =
        url.find("domain=");

    if (p == string::npos)
        return "";

    string domain =
        url.substr(p + 7);

    size_t end =
        domain.find("&");

    if (end != string::npos)
        domain =
            domain.substr(0, end);

    return domain;
}

int getMalicious(string data)
{
    string key =
        "\"malicious\":";

    size_t p =
        data.find(key);

    if (p == string::npos)
        return -1;

    p += key.length();

    while (
        p < data.size() &&
        (data[p] == ' ' ||
         data[p] == '\t')
    )
    {
        p++;
    }

    string number;

    while (
        p < data.size() &&
        data[p] >= '0' &&
        data[p] <= '9'
    )
    {
        number += data[p];
        p++;
    }

    if (number.empty())
        return -1;

    return atoi(number.c_str());
}

string makeResponse(
    string domain,
    int malicious
)
{
    stringstream ss;

    ss << "{"
       << "\"domain\":\""
       << domain
       << "\","
       << "\"malicious\":"
       << malicious
       << "}";

    return ss.str();
}

void closeSocket(SOCKET s)
{
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}

bool sendAll(
    SOCKET client,
    string data
)
{
    int sent = 0;
    int total =
        (int)data.size();

    while (sent < total)
    {
        int n =
            send(
                client,
                data.c_str() + sent,
                total - sent,
                0
            );

        if (n <= 0)
            return false;

        sent += n;
    }

    return true;
}

int main()
{
#ifdef _WIN32

    WSADATA wsa;

    if (WSAStartup(
            MAKEWORD(2, 2),
            &wsa
        ) != 0)
    {
        cout << "WSAStartup failed\n";
        return 1;
    }

#endif

#ifndef _WIN32

    curl_global_init(
        CURL_GLOBAL_DEFAULT
    );

#endif

    const char *portEnv =
        getenv("PORT");

    int port = 8080;

    if (portEnv != NULL)
        port = atoi(portEnv);

    SOCKET server =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

    if (server == INVALID_SOCKET)
    {
        cout << "Cannot create socket\n";
        return 1;
    }

    int opt = 1;

    setsockopt(
        server,
        SOL_SOCKET,
        SO_REUSEADDR,
        (char *)&opt,
        sizeof(opt)
    );

    sockaddr_in address;

    memset(
        &address,
        0,
        sizeof(address)
    );

    address.sin_family =
        AF_INET;

    address.sin_addr.s_addr =
        htonl(INADDR_ANY);

    address.sin_port =
        htons(port);

    if (bind(
            server,
            (sockaddr *)&address,
            sizeof(address)
        ) == SOCKET_ERROR)
    {
        cout << "Bind failed\n";

        closeSocket(server);

#ifdef _WIN32
        WSACleanup();
#else
        curl_global_cleanup();
#endif

        return 1;
    }

    if (listen(server, 20)
        == SOCKET_ERROR)
    {
        cout << "Listen failed\n";

        closeSocket(server);

#ifdef _WIN32
        WSACleanup();
#else
        curl_global_cleanup();
#endif

        return 1;
    }

    cout <<
        "CyberGuard Backend running on port "
        << port << "\n";

    while (true)
    {
        sockaddr_in clientAddress;

#ifdef _WIN32
        int clientSize =
            sizeof(clientAddress);
#else
        socklen_t clientSize =
            sizeof(clientAddress);
#endif

        SOCKET client =
            accept(
                server,
                (sockaddr *)&clientAddress,
                &clientSize
            );

        if (client == INVALID_SOCKET)
            continue;

        char buffer[8192];

        memset(
            buffer,
            0,
            sizeof(buffer)
        );

        int received =
            recv(
                client,
                buffer,
                sizeof(buffer) - 1,
                0
            );

        if (received <= 0)
        {
            closeSocket(client);
            continue;
        }

        string request(
            buffer,
            received
        );

        if (
            request.find(
                "GET /scan?domain="
            ) == string::npos
        )
        {
            string body =
                "{\"error\":\"Invalid endpoint\"}";

            string response =
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Type: application/json\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Content-Length: " +
                to_string(body.size()) +
                "\r\n\r\n" +
                body;

            sendAll(
                client,
                response
            );

            closeSocket(client);
            continue;
        }

        size_t start =
            request.find(
                "GET /scan?domain="
            );

        start +=
            strlen("GET /scan?domain=");

        size_t end =
            request.find(
                " ",
                start
            );

        string domain =
            request.substr(
                start,
                end - start
            );

        size_t amp =
            domain.find("&");

        if (amp != string::npos)
            domain =
                domain.substr(
                    0,
                    amp
                );

        cout <<
            "Scanning: "
            << domain
            << "\n";

        string vt =
            vtRequest(domain);

        int malicious =
            getMalicious(vt);

        string body;

        if (malicious < 0)
        {
            body =
                "{\"error\":\"VirusTotal request failed\"}";
        }
        else
        {
            body =
                makeResponse(
                    domain,
                    malicious
                );
        }

        string response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Methods: GET\r\n"
            "Content-Length: " +
            to_string(body.size()) +
            "\r\n"
            "Connection: close\r\n"
            "\r\n" +
            body;

        sendAll(
            client,
            response
        );

        closeSocket(client);
    }

    closeSocket(server);

#ifdef _WIN32

    WSACleanup();

#else

    curl_global_cleanup();

#endif

    return 0;
}