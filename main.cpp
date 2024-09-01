#include <iostream>
#include <string>
#include <map>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <vector>
#include <sstream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

using namespace std;

#define BUFFER_SIZE 8192

// Global data structures for cookie management and logging
unordered_map<string, map<string, string>> sessionCookieCache; // Cache to store cookies per session
unordered_map<string, int> domainAccessCounter;                // Tracks access frequency for each domain
unordered_map<string, unordered_map<string, int>> domainCookieCounter; // Tracks cookie frequency per domain
mutex cacheMutex;                                              // Mutex for thread-safe cache access
mutex logMutex;                                                // Mutex for thread-safe logging access

// Function to generate a session identifier based on the client socket
string generate_session_id(SOCKADDR_IN client_addr) {
    stringstream ss;
    ss << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port);
    return ss.str();
}

// Initialize OpenSSL
void initialize_ssl()
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

// Clean up OpenSSL
void cleanup_ssl()
{
    EVP_cleanup();
}

// Create SSL context
SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method(); // Use SSL/TLS
    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        cerr << "Unable to create SSL context" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Configure the context with your certificate and private key
void configure_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

// Function to parse and store cookies for a specific session
void parse_and_store_cookies(const string& response, const string& session_id, const string& host) {
    if (host.find("www.google.com") == string::npos) {
        return; // Only process cookies for www.google.com
    }

    size_t pos = 0;
    string set_cookie = "Set-Cookie: ";
    while ((pos = response.find(set_cookie, pos)) != string::npos) {
        size_t end = response.find("\r\n", pos);
        string cookie_line = response.substr(pos + set_cookie.length(), end - (pos + set_cookie.length()));

        // Extract cookie name and value
        size_t separator = cookie_line.find("=");
        if (separator == string::npos) continue; // Invalid cookie format

        string cookie_name = cookie_line.substr(0, separator);
        string cookie_value = cookie_line.substr(separator + 1);
        cookie_value = cookie_value.substr(0, cookie_value.find(";")); // Remove attributes after the value

        // Store the cookie in the session's cache
        {
            lock_guard<mutex> lock(cacheMutex);
            sessionCookieCache[session_id][cookie_name] = cookie_value;
            domainCookieCounter[host][cookie_name]++; // Increment cookie count for the domain
        }

        // Move to the next "Set-Cookie" header
        pos = end;
    }

    // Debugging: Print stored cookies for the session
    lock_guard<mutex> lock(cacheMutex);
    cout << "Cookies stored for session " << session_id << ":" << endl;
    for (const auto& [name, value] : sessionCookieCache[session_id]) {
        cout << name << "=" << value << endl;
    }
}

// Function to add stored cookies to a request for a specific session
void add_cookies_to_request(string& request, const string& session_id, const string& host) {
    if (host.find("www.google.com") != string::npos) {
        lock_guard<mutex> lock(cacheMutex);
        if (sessionCookieCache.find(session_id) != sessionCookieCache.end()) {
            string cookies = "Cookie: ";
            for (const auto& [name, value] : sessionCookieCache[session_id]) {
                cookies += name + "=" + value + "; ";
            }
            cookies += "\r\n";
            size_t pos = request.find("\r\n\r\n");
            if (pos != string::npos) {
                request.insert(pos + 2, cookies); // Insert cookies before the end of headers
            }
        }
    }
}

// Function to handle DNS resolution for the host
bool resolve_host(const string &host, sockaddr_in &server_addr)
{
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), "80", &hints, &result) != 0)
    {
        cerr << "Error: No such host found: " << host << endl;
        return false;
    }

    memcpy(&server_addr, result->ai_addr, result->ai_addrlen);
    freeaddrinfo(result);
    return true;
}

// logging
void log_request(const string &client_ip, const string &host, const string &request, const string &response)
{
    lock_guard<mutex> lock(logMutex);
    cout << "Client IP: " << client_ip << ", Host: " << host << endl;
    cout << "Request: " << request << endl;
    cout << "Response: " << response.substr(0, 100) << "..." << endl; // Only show the first 100 characters
}

// Function to handle client requests
void handle_client(SOCKET client_socket)
{
    SOCKADDR_IN client_addr;
    int client_addr_len = sizeof(client_addr);
    getpeername(client_socket, (SOCKADDR*)&client_addr, &client_addr_len);

    // Generate a session ID based on the client's IP and port
    string session_id = generate_session_id(client_addr);

    char buffer[BUFFER_SIZE];
    string request;
    int bytes_received;

    while ((bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0)) > 0)
    {
        request.append(buffer, bytes_received);
        if (request.find("\r\n\r\n") != string::npos)
            break; // End of headers
    }

    if (bytes_received < 0)
    {
        cerr << "Error receiving from client: " << WSAGetLastError() << endl;
        closesocket(client_socket);
        return;
    }

    cout << "Received request: " << request << endl; // Debugging line

    size_t pos = request.find(" ");
    if (pos == string::npos)
        return;
    string method = request.substr(0, pos);
    if (method != "GET")
        return;
    size_t host_start = request.find("Host: ") + 6;
    size_t host_end = request.find("\r\n", host_start);
    string host = request.substr(host_start, host_end - host_start);

    // Increment domain access counter
    {
        lock_guard<mutex> lock(cacheMutex);
        domainAccessCounter[host]++;
    }

    cout<<"Adding cookies to request"<<endl;
    add_cookies_to_request(request, session_id, host);
    cout << "Modified Request Headers with Cookies for " << host << ":" << endl;
    cout << request << endl; // Print the full modified request headers to console
    sockaddr_in server_addr;

    if (!resolve_host(host, server_addr))
    {
        cerr << "Could not resolve host: " << host << endl; // Debugging line
        closesocket(client_socket);
        return;
    }

    SOCKET server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET)
    {
        cerr << "Error: Unable to create socket. Error: " << WSAGetLastError() << endl;
        closesocket(client_socket);
        return;
    }
    cout << "Connecting to server: " << host << endl; // Debugging line
    if (connect(server_socket, (sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
    {
        cerr << "Error: Failed to connect to the server. Error: " << WSAGetLastError() << endl;
        closesocket(server_socket);
        closesocket(client_socket);
        return;
    }
    cout << "Connected to server: " << host << endl; // Debugging line
    cout << "sending request" << endl;
    int bytes_sent = send(server_socket, request.c_str(), request.length(), 0);
    if (bytes_sent == SOCKET_ERROR)
    {
        cerr << "Error sending request to server: " << WSAGetLastError() << endl;
        closesocket(server_socket);
        closesocket(client_socket);
        return;
    }
    cout << "Sent request" << endl;

    string response;
    int cnt = 0;
    while ((bytes_received = recv(server_socket, buffer, BUFFER_SIZE, 0)) > 0)
    {
        response.append(buffer, bytes_received);
        if (response.find("\r\n\r\n") != string::npos)
        {
            cout << "Empty headers: exiting the loop" << endl;
            break; // Read headers
        }
        cout << "Received response part " << ++cnt << endl; // Debugging line
    }
    cout << "Response: "<< response << endl;
    cout << "Parsing cookies" << endl;
    parse_and_store_cookies(response, session_id, host);
    cout<<"Parsed cookies"<<endl;

    if (bytes_received == SOCKET_ERROR)
    {
        cerr << "Error receiving response from server: " << WSAGetLastError() << endl;
        closesocket(server_socket);
        closesocket(client_socket);
        return;
    }
    // Check for redirection
    if (response.find("HTTP/1.1 301") != string::npos || response.find("HTTP/1.1 302") != string::npos)
    {
        size_t location_pos = response.find("Location: ");
        if (location_pos != string::npos)
        {
            size_t location_end = response.find("\r\n", location_pos);
            string redirect_url = response.substr(location_pos + 10, location_end - (location_pos + 10));
            cout << "Redirect URL: " << redirect_url << endl; // Debugging line

            // Optional: Handle redirection or send a response to the client
            string redirect_message = "HTTP/1.1 302 Found\r\nLocation: " + redirect_url + "\r\n\r\n";

            cout << "redirect message: " << redirect_message << endl;
            send(client_socket, redirect_message.c_str(), redirect_message.length(), 0);
        }
    }
    else
    {
        // Continue to read the rest of the response body
        while ((bytes_received = recv(server_socket, buffer, BUFFER_SIZE, 0)) > 0)
        {
            response.append(buffer, bytes_received);
        }
    }
    log_request("Client IP Placeholder", host, request, response);

    cout << "Received full response from server" << endl; // Debugging line

    int total_bytes_sent = 0;
    int response_length = response.length();
    while (total_bytes_sent < response_length)
    {
        bytes_sent = send(client_socket, response.c_str() + total_bytes_sent, response_length - total_bytes_sent, 0);
        if (bytes_sent == SOCKET_ERROR)
        {
            cerr << "Error sending response to client: " << WSAGetLastError() << endl;
            break;
        }
        total_bytes_sent += bytes_sent;
    }
    cout << "Sent response" << endl;

    closesocket(server_socket);
    closesocket(client_socket);
}

// Function to report analytics
void reportAnalytics() {
    lock_guard<mutex> lock(cacheMutex);

    // Report most frequently accessed domains
    cout << "\n--- Domain Access Frequency ---" << endl;
    for (const auto& [domain, count] : domainAccessCounter) {
        cout << domain << ": " << count << " accesses" << endl;
    }

    // Report cookie patterns for www.google.com
    cout << "\n--- Cookie Patterns for www.google.com ---" << endl;
    const string google_domain = "www.google.com";
    if (domainCookieCounter.find(google_domain) != domainCookieCounter.end()) {
        for (const auto& [cookie, count] : domainCookieCounter[google_domain]) {
            cout << cookie << ": " << count << " times set" << endl;
        }
    } else {
        cout << "No cookie data available for www.google.com" << endl;
    }
}

int main()
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        cerr << "WSAStartup failed." << endl;
        return 1;
    }

    SOCKET proxy_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_socket == INVALID_SOCKET)
    {
        cerr << "Error creating socket." << endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in proxy_addr;
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = INADDR_ANY;
    proxy_addr.sin_port = htons(8080);

    if (bind(proxy_socket, (sockaddr *)&proxy_addr, sizeof(proxy_addr)) == SOCKET_ERROR)
    {
        cerr << "Binding failed." << endl;
        closesocket(proxy_socket);
        WSACleanup();
        return -1;
    }
    if (listen(proxy_socket, 10) == SOCKET_ERROR)
    {
        cerr << "Listening failed." << endl;
        closesocket(proxy_socket);
        WSACleanup();
        return -1;
    }
    cout << "Proxy server listening on port 8080..." << endl;

    // Periodically call the analytics report function (e.g., every 60 seconds)
    thread([] {
        while (true) {
            this_thread::sleep_for(chrono::seconds(60));
            reportAnalytics();
        }
    }).detach();

    while (true)
    {
        SOCKET client_socket = accept(proxy_socket, nullptr, nullptr);
        if (client_socket == INVALID_SOCKET)
        {
            cerr << "Failed to accept client connection." << endl;
            continue;
        }

        // Handle each client in a separate thread
        thread(handle_client, client_socket).detach();
    }

    closesocket(proxy_socket);
    WSACleanup();
    return 0;
}
