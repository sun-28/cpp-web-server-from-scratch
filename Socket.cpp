
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <curl/curl.h>
#include <unistd.h>

#define PORT 8080
// #define FILE_PATH "index.html" // The local HTML file to server

// This is for loading already hosted website
/*
// Callback function for handling data received by libcurl
size_t write_callback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t total_size = size * nmemb;
    output->append((char*)contents, total_size);
    return total_size;
}

// Function to fetch webpage content using cURL
std::string fetch_webpage(const std::string& url) {
    CURL* curl;
    CURLcode res;
    std::string response;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); // Follow redirects
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return response;
}
*/

// Function to read the HTML file
std::string read_file(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file) {
        return "<html><body><h1>404 - File Not Found</h1></body></html>";
    }
    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // 1. Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // 2. Bind socket to address & port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // 3. Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    std::cout << "Server running on http://localhost:" << PORT << "/\n";

    // 4. Accept client connections and respond
    while (true) {
        new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        if (new_socket < 0) {
            perror("Accept failed");
            continue;
        }

        std::cout << "New client connected\n";

        // Read the HTML file
        std::string html_content = read_file("/home/parthk/Desktop/WEB DEVELOPEMENT/Web Server/index.html");

        // // Fetch webpage content (e.g., Amazon.com)
        // std::string web_content = fetch_webpage("https://www.amazon.com");
        // if (web_content.empty()) {
        //     web_content = "<html><body><h1>Failed to fetch webpage</h1></body></html>";
        // }

        // Create HTTP response
        std::string http_response =
        "HTTP/1.1 200 OK\n"
        "Content-Type: text/html\n"
        "Connection: close\n\n" +
        html_content;
        // for hosted websites
        // web_content;

        // Send response
        send(new_socket, http_response.c_str(), http_response.size(), 0);
        close(new_socket);
    }

    return 0;
}

