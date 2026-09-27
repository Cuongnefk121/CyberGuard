#ifdef _WIN32

#define _WIN32_WINNT 0x0600

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")

typedef SOCKET socket_t;

#else

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <curl/curl.h>

typedef int socket_t;

#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)

#endif

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>

#define ll long long

using namespace std;


/* =========================================
   API KEY
   ========================================= */

string GetAPIKey()
{
    return "03982ccb3228d389f284ba569850736c2f340eddcc0b0e11be5460b9cb1ab3f4";
}


/* =========================================
   PORT
   ========================================= */

int GetPort()
{
    const char* p = getenv("PORT");

    if (p != NULL)
    {
        int port = atoi(p);

        if (port > 0)
            return port;
    }

    return 8080;
}


/* =========================================
   URL DECODE
   ========================================= */

string UrlDecode(string s)
{
    string res = "";

    for (int i = 0; i < (int)s.size(); i++)
    {
        if (
            s[i] == '%' &&
            i + 2 < (int)s.size()
        )
        {
            char h1 = s[i + 1];
            char h2 = s[i + 2];

            int a = 0;
            int b = 0;

            if (h1 >= '0' && h1 <= '9')
                a = h1 - '0';
            else if (h1 >= 'A' && h1 <= 'F')
                a = h1 - 'A' + 10;
            else if (h1 >= 'a' && h1 <= 'f')
                a = h1 - 'a' + 10;

            if (h2 >= '0' && h2 <= '9')
                b = h2 - '0';
            else if (h2 >= 'A' && h2 <= 'F')
                b = h2 - 'A' + 10;
            else if (h2 >= 'a' && h2 <= 'f')
                b = h2 - 'a' + 10;

            res += (char)(a * 16 + b);

            i += 2;
        }
        else if (s[i] == '+')
        {
            res += ' ';
        }
        else
        {
            res += s[i];
        }
    }

    return res;
}


/* =========================================
   GET MALICIOUS
   ========================================= */

int GetMalicious(string response)
{
    size_t statsPos =
        response.find(
            "\"last_analysis_stats\""
        );

    if (statsPos == string::npos)
    {
        cout << "[ERROR] last_analysis_stats not found."
             << endl;

        return -1;
    }

    size_t maliciousPos =
        response.find(
            "\"malicious\"",
            statsPos
        );

    if (maliciousPos == string::npos)
    {
        cout << "[ERROR] malicious not found."
             << endl;

        return -1;
    }

    maliciousPos =
        response.find(
            ":",
            maliciousPos
        );

    if (maliciousPos == string::npos)
        return -1;

    maliciousPos++;

    while (
        maliciousPos < response.size() &&
        (
            response[maliciousPos] == ' ' ||
            response[maliciousPos] == '\t'
        )
    )
    {
        maliciousPos++;
    }

    int malicious = 0;

    while (
        maliciousPos < response.size() &&
        response[maliciousPos] >= '0' &&
        response[maliciousPos] <= '9'
    )
    {
        malicious =
            malicious * 10 +
            (
                response[maliciousPos] - '0'
            );

        maliciousPos++;
    }

    return malicious;
}


#ifdef _WIN32


/* =========================================
   VIRUSTOTAL - WINDOWS
   ========================================= */

int CheckVirusTotal(string domain)
{
    string apiKey =
        GetAPIKey();

    HINTERNET hSession =
        WinHttpOpen(
            L"CyberGuard",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );

    if (hSession == NULL)
        return -1;

    HINTERNET hConnect =
        WinHttpConnect(
            hSession,
            L"www.virustotal.com",
            INTERNET_DEFAULT_HTTPS_PORT,
            0
        );

    if (hConnect == NULL)
    {
        WinHttpCloseHandle(hSession);
        return -1;
    }

    string path =
        "/api/v3/domains/" +
        domain;

    wstring wpath(
        path.begin(),
        path.end()
    );

    HINTERNET hRequest =
        WinHttpOpenRequest(
            hConnect,
            L"GET",
            wpath.c_str(),
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE
        );

    if (hRequest == NULL)
    {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        return -1;
    }

    string header =
        "x-apikey: " +
        apiKey;

    wstring wheader(
        header.begin(),
        header.end()
    );

    if (
        !WinHttpAddRequestHeaders(
            hRequest,
            wheader.c_str(),
            (DWORD)-1,
            WINHTTP_ADDREQ_FLAG_ADD
        )
    )
    {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        return -1;
    }

    if (
        !WinHttpSendRequest(
            hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            WINHTTP_NO_REQUEST_DATA,
            0,
            0,
            0
        )
    )
    {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        return -1;
    }

    if (
        !WinHttpReceiveResponse(
            hRequest,
            NULL
        )
    )
    {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        return -1;
    }

    string response = "";

    DWORD size = 0;

    while (
        WinHttpQueryDataAvailable(
            hRequest,
            &size
        )
    )
    {
        if (size == 0)
            break;

        vector<char> buffer(
            size + 1
        );

        DWORD downloaded = 0;

        if (
            !WinHttpReadData(
                hRequest,
                &buffer[0],
                size,
                &downloaded
            )
        )
        {
            break;
        }

        buffer[downloaded] = '\0';

        response +=
            &buffer[0];
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return GetMalicious(
        response
    );
}


#else


/* =========================================
   CURL WRITE CALLBACK
   ========================================= */

size_t WriteCallback(
    void* contents,
    size_t size,
    size_t nmemb,
    void* userp
)
{
    size_t total =
        size * nmemb;

    string* response =
        (string*)userp;

    response->append(
        (char*)contents,
        total
    );

    return total;
}


/* =========================================
   VIRUSTOTAL - LINUX / RENDER
   ========================================= */

int CheckVirusTotal(string domain)
{
    string apiKey =
        GetAPIKey();

    string url =
        "https://www.virustotal.com/api/v3/domains/" +
        domain;

    CURL* curl =
        curl_easy_init();

    if (curl == NULL)
        return -1;

    string response = "";

    struct curl_slist* headers =
        NULL;

    string apiHeader =
        "x-apikey: " +
        apiKey;

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
        WriteCallback
    );

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEDATA,
        &response
    );

    curl_easy_setopt(
        curl,
        CURLOPT_TIMEOUT,
        30L
    );

    CURLcode result =
        curl_easy_perform(
            curl
        );

    curl_slist_free_all(
        headers
    );

    curl_easy_cleanup(
        curl
    );

    if (
        result !=
        CURLE_OK
    )
    {
        cout <<
            "[ERROR] VirusTotal request failed: "
            << curl_easy_strerror(result)
            << endl;

        return -1;
    }

    return GetMalicious(
        response
    );
}

#endif


/* =========================================
   MAIN SERVER
   ========================================= */

int main()
{
#ifdef _WIN32

    WSADATA wsa;

    if (
        WSAStartup(
            MAKEWORD(2, 2),
            &wsa
        ) != 0
    )
    {
        cout <<
            "[ERROR] WSAStartup failed."
            << endl;

        return 1;
    }

#else

    curl_global_init(
        CURL_GLOBAL_DEFAULT
    );

#endif


    int port =
        GetPort();


    /* =====================================
       CREATE SOCKET
       ===================================== */

    socket_t server =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

    if (server == INVALID_SOCKET)
    {
        cout <<
            "[ERROR] Cannot create socket."
            << endl;

#ifdef _WIN32
        WSACleanup();
#else
        curl_global_cleanup();
#endif

        return 1;
    }


    /* =====================================
       REUSE PORT
       ===================================== */

    int opt = 1;

    setsockopt(
        server,
        SOL_SOCKET,
        SO_REUSEADDR,
        (char*)&opt,
        sizeof(opt)
    );


    /* =====================================
       SERVER ADDRESS
       ===================================== */

    sockaddr_in serverAddr;

    memset(
        &serverAddr,
        0,
        sizeof(serverAddr)
    );

    serverAddr.sin_family =
        AF_INET;

    serverAddr.sin_addr.s_addr =
        INADDR_ANY;

    serverAddr.sin_port =
        htons(port);


    /* =====================================
       BIND
       ===================================== */

    if (
        bind(
            server,
            (sockaddr*)&serverAddr,
            sizeof(serverAddr)
        ) == SOCKET_ERROR
    )
    {
        cout <<
            "[ERROR] Bind failed."
            << endl;

#ifdef _WIN32
        closesocket(server);
        WSACleanup();
#else
        close(server);
        curl_global_cleanup();
#endif

        return 1;
    }


    /* =====================================
       LISTEN
       ===================================== */

    if (
        listen(
            server,
            10
        ) == SOCKET_ERROR
    )
    {
        cout <<
            "[ERROR] Listen failed."
            << endl;

#ifdef _WIN32
        closesocket(server);
        WSACleanup();
#else
        close(server);
        curl_global_cleanup();
#endif

        return 1;
    }


    cout <<
        "===================================="
        << endl;

    cout <<
        "        CYBERGUARD BACKEND"
        << endl;

    cout <<
        "===================================="
        << endl;

    cout <<
        "Server running on port "
        << port
        << endl;

    cout <<
        "Endpoint:"
        << endl;

    cout <<
        "/scan?domain=example.com"
        << endl;

    cout <<
        "===================================="
        << endl;


    /* =====================================
       SERVER LOOP
       ===================================== */

    while (true)
    {
        sockaddr_in clientAddr;

#ifdef _WIN32

        int clientLen =
            sizeof(clientAddr);

#else

        socklen_t clientLen =
            sizeof(clientAddr);

#endif

        socket_t client =
            accept(
                server,
                (sockaddr*)&clientAddr,
                &clientLen
            );

        if (client == INVALID_SOCKET)
        {
            continue;
        }


        /* =================================
           RECEIVE REQUEST
           ================================= */

        char buffer[8192];

        memset(
            buffer,
            0,
            sizeof(buffer)
        );

#ifdef _WIN32

        int received =
            recv(
                client,
                buffer,
                sizeof(buffer) - 1,
                0
            );

#else

        int received =
            recv(
                client,
                buffer,
                sizeof(buffer) - 1,
                0
            );

#endif

        if (received <= 0)
        {
#ifdef _WIN32
            closesocket(client);
#else
            close(client);
#endif

            continue;
        }

        string request =
            string(
                buffer,
                received
            );


        cout <<
            "[REQUEST] "
            << request.substr(
                0,
                request.find("\r\n")
            )
            << endl;


        /* =================================
           CORS
           ================================= */

        string responseBody;


        /* =================================
           CHECK OPTIONS
           ================================= */

        if (
            request.find(
                "OPTIONS"
            ) == 0
        )
        {
            responseBody =
                "";
        }
        else
        {
            /* =============================
               GET /scan?domain=
               ============================= */

            size_t scanPos =
                request.find(
                    "GET /scan?domain="
                );

            if (
                scanPos == string::npos
            )
            {
                responseBody =
                    "{\"error\":\"Invalid endpoint\"}";
            }
            else
            {
                size_t start =
                    scanPos +
                    strlen(
                        "GET /scan?domain="
                    );

                size_t end =
                    request.find(
                        " ",
                        start
                    );

                if (
                    end == string::npos
                )
                {
                    responseBody =
                        "{\"error\":\"Invalid request\"}";
                }
                else
                {
                    string domain =
                        request.substr(
                            start,
                            end - start
                        );

                    domain =
                        UrlDecode(
                            domain
                        );


                    /* =====================
                       REMOVE EXTRA QUERY
                       ===================== */

                    size_t q =
                        domain.find(
                            "&"
                        );

                    if (
                        q != string::npos
                    )
                    {
                        domain =
                            domain.substr(
                                0,
                                q
                            );
                    }


                    /* =====================
                       REMOVE PATH
                       ===================== */

                    q =
                        domain.find(
                            "/"
                        );

                    if (
                        q != string::npos
                    )
                    {
                        domain =
                            domain.substr(
                                0,
                                q
                            );
                    }


                    cout <<
                        "[SCAN] "
                        << domain
                        << endl;


                    /* =====================
                       CHECK DOMAIN
                       ===================== */

                    int malicious =
                        CheckVirusTotal(
                            domain
                        );


                    if (
                        malicious < 0
                    )
                    {
                        responseBody =
                            "{\"error\":\"VirusTotal request failed\"}";
                    }
                    else
                    {
                        cout <<
                            "[RESULT] "
                            << domain
                            << " -> malicious = "
                            << malicious
                            << endl;


                        /* =================
                           CYBERGUARD RULE
                           ================= */

                        if (
                            malicious >= 3
                        )
                        {
                            cout <<
                                "[WARNING] "
                                << domain
                                << " is potentially dangerous."
                                << endl;
                        }
                        else
                        {
                            cout <<
                                "[SAFE] "
                                << domain
                                << endl;
                        }


                        responseBody =
                            "{\"domain\":\"" +
                            domain +
                            "\",\"malicious\":" +
                            to_string(
                                malicious
                            ) +
                            "}";
                    }
                }
            }
        }


        /* =================================
           HTTP RESPONSE
           ================================= */

        string httpResponse =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Methods: GET, OPTIONS\r\n"
            "Access-Control-Allow-Headers: *\r\n"
            "Content-Length: " +
            to_string(
                responseBody.size()
            ) +
            "\r\n"
            "Connection: close\r\n"
            "\r\n" +
            responseBody;


        send(
            client,
            httpResponse.c_str(),
            (int)httpResponse.size(),
            0
        );


#ifdef _WIN32

        closesocket(client);

#else

        close(client);

#endif
    }


    /* =====================================
       CLEANUP
       ===================================== */

#ifdef _WIN32

    closesocket(server);
    WSACleanup();

#else

    close(server);

    curl_global_cleanup();

#endif

    return 0;
}
