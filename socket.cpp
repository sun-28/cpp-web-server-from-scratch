#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <unordered_map>

#define PORT 8080

// Function to read file contents from the disk
std::string read_file(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file) {
        return "<html><body><h1>404 - File Not Found</h1></body></html>";
    }
    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

// Function to determine the MIME type of a file
std::string get_mime_type(const std::string& file_path) {
    // MIME type mappings
    std::unordered_map<std::string, std::string> mime_types = {
        {".html", "text/html"},
        {".css", "text/css"},
        {".js", "application/javascript"},
        {".png", "image/png"},
        {".jpg", "image/jpeg"},
        {".gif", "image/gif"},
        {".svg", "image/svg+xml"},
        {".ico", "image/x-icon"},
        {".json", "application/json"},
        {".txt", "text/plain"}
    };

    // Find file extension
    for (const auto& mime_type : mime_types) {
        if (file_path.find(mime_type.first) != std::string::npos) {
            return mime_type.second;
        }
    }
    return "application/octet-stream"; // Default for unknown types
}

// Function to generate HTTP response with content
std::string generate_http_response(const std::string& content, const std::string& mime_type) {
    return "HTTP/1.1 200 OK\r\n"
           "Content-Type: " + mime_type + "\r\n"
           "Connection: close\r\n\r\n" + content;
}

// Function to handle the HTTP request and return a response
void handle_request(int new_socket) {
    char buffer[1024] = {0};
    read(new_socket, buffer, 1024);
    std::string request(buffer);

    // Parse the request to extract the requested file path
    size_t pos1 = request.find(" ") + 1;
    size_t pos2 = request.find(" ", pos1);
    std::string file_path = request.substr(pos1, pos2 - pos1);

    // If the file is the root, serve the index.html file
    if (file_path == "/") {
        file_path = "/index.html";
    }

    // Construct full path for the requested file (assuming all files are in the "www" folder)
    std::string full_path = "www" + file_path;

    // Read the requested file from the filesystem
    std::string content = read_file(full_path);

    // Get the MIME type of the requested file
    std::string mime_type = get_mime_type(full_path);

    // Generate and send HTTP response
    std::string response = generate_http_response(content, mime_type);
    send(new_socket, response.c_str(), response.length(), 0);

    // Close the socket after the response is sent
    close(new_socket);
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

        // Handle the request (serve the appropriate file)
        handle_request(new_socket);
    }

    return 0;
}
