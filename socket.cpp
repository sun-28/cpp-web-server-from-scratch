#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h> // Add this line
#include <sys/wait.h> // For waitpid
#include <unordered_map>
#include <thread> // For std::thread
#include <vector>
#include <cstdlib> // For setenv, clearenv, exit
#include <cerrno> // For errno
#include <algorithm> // for std::transform

#define PORT 8080
#define WWW_ROOT "www" // Root directory for static files
#define CGI_BIN_PATH "/cgi-bin/" // Path prefix for CGI scripts relative to WWW_ROOT
#define READ_BUFFER_SIZE 4096 // Increased buffer size


// RUN g++ server.cpp -o server -std=c++11 -pthread

// --- Helper Functions ---

// Basic logging
void log_message(const std::string& msg) {
    std::cerr << msg << std::endl;
}

// Send a standard HTTP error response
void send_error_response(int socket, int status_code, const std::string& status_message, const std::string& body = "") {
    std::ostringstream response_stream;
    response_stream << "HTTP/1.1 " << status_code << " " << status_message << "\r\n";
    response_stream << "Content-Type: text/html\r\n";
    response_stream << "Connection: close\r\n";
    std::string content = body.empty() ? ("<html><body><h1>" + std::to_string(status_code) + " " + status_message + "</h1></body></html>") : body;
    response_stream << "Content-Length: " << content.length() << "\r\n";
    response_stream << "\r\n"; // End of headers
    response_stream << content;

    std::string response = response_stream.str();
    send(socket, response.c_str(), response.length(), 0);
    log_message("Sent Response: " + std::to_string(status_code) + " " + status_message);
}

// Get MIME type (slightly improved)
std::string get_mime_type(const std::string& file_path) {
    std::unordered_map<std::string, std::string> mime_types = {
        {".html", "text/html"}, {".htm", "text/html"},
        {".css", "text/css"},
        {".js", "application/javascript"},
        {".png", "image/png"},
        {".jpg", "image/jpeg"}, {".jpeg", "image/jpeg"},
        {".gif", "image/gif"},
        {".svg", "image/svg+xml"},
        {".ico", "image/x-icon"},
        {".json", "application/json"},
        {".txt", "text/plain"},
        {".pdf", "application/pdf"},
        {".mp4", "video/mp4"},
        // Add more as needed
    };

    size_t dot_pos = file_path.rfind('.');
    if (dot_pos != std::string::npos) {
        std::string ext = file_path.substr(dot_pos);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower); // Convert extension to lowercase
        if (mime_types.count(ext)) {
            return mime_types.at(ext);
        }
    }
    return "application/octet-stream"; // Default
}

// Read static file content
bool read_file_content(const std::string& file_path, std::string& content) {
    std::ifstream file(file_path, std::ios::binary); // Use binary for all file types
    if (!file) {
        log_message("Error: Could not open file: " + file_path);
        return false;
    }
    std::ostringstream ss;
    ss << file.rdbuf();
    content = ss.str();
    return true;
}

// --- Request Parsing ---
struct HttpRequest {
    std::string method;
    std::string path;
    std::string query_string;
    std::string http_version;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
};

bool parse_request(const std::string& raw_request, HttpRequest& request) {
    std::istringstream request_stream(raw_request);
    std::string request_line;

    // 1. Parse Request Line
    if (!std::getline(request_stream, request_line) || request_line.empty() || request_line.back() != '\r') {
        log_message("Error: Invalid request line.");
        return false;
    }
    request_line.pop_back(); // Remove trailing '\r'

    std::istringstream line_stream(request_line);
    if (!(line_stream >> request.method >> request.path >> request.http_version)) {
         log_message("Error: Malformed request line: " + request_line);
        return false;
    }

    // Separate path and query string
    size_t query_pos = request.path.find('?');
    if (query_pos != std::string::npos) {
        request.query_string = request.path.substr(query_pos + 1);
        request.path = request.path.substr(0, query_pos);
    }

    // 2. Parse Headers
    std::string header_line;
    while (std::getline(request_stream, header_line) && !header_line.empty() && header_line != "\r") {
        header_line.pop_back(); // Remove trailing '\r'
        size_t colon_pos = header_line.find(':');
        if (colon_pos != std::string::npos) {
            std::string key = header_line.substr(0, colon_pos);
            std::string value = header_line.substr(colon_pos + 1);
            // Trim leading/trailing whitespace from value
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            request.headers[key] = value;
             // std::cout << "Header: " << key << ": " << value << std::endl; // Debug
        }
    }

    // 3. Store Body (if any - already read into raw_request, find where it starts)
    // Find the end of headers marker (\r\n\r\n)
    size_t body_start_pos = raw_request.find("\r\n\r\n");
    if (body_start_pos != std::string::npos) {
         request.body = raw_request.substr(body_start_pos + 4);
    } else {
        // This might happen if the request was truncated or malformed
         log_message("Warning: Could not find end of headers marker.");
         // We might need more robust reading if body is large/split across reads
    }


    // Optional: If Content-Length header exists, verify body size (basic check)
    if (request.headers.count("Content-Length")) {
        try {
            size_t expected_length = std::stoul(request.headers["Content-Length"]);
            // Note: This simple check assumes the body wasn't truncated during the initial read.
            // A production server would need to read exactly Content-Length bytes *after* headers.
             if (request.body.length() < expected_length) {
                 log_message("Warning: Body length less than Content-Length header.");
                 // Consider reading more data from the socket here if needed
             } else if (request.body.length() > expected_length) {
                 request.body = request.body.substr(0, expected_length); // Trim extra data
             }
        } catch (const std::exception& e) {
            log_message("Error parsing Content-Length: " + std::string(e.what()));
            // Handle error, maybe return 400 Bad Request
        }
    }


    return true;
}


// --- CGI Handling ---

// Execute CGI script
void execute_cgi(int client_socket, const HttpRequest& request, const std::string& script_path_full, const struct sockaddr_in& client_addr) {
    log_message("Executing CGI script: " + script_path_full);

    int pipe_stdin[2];  // Server -> Child (POST Body)
    int pipe_stdout[2]; // Child -> Server (Response)

    // 1. Create pipes
    if (pipe(pipe_stdin) == -1 || pipe(pipe_stdout) == -1) {
        perror("pipe failed");
        send_error_response(client_socket, 500, "Internal Server Error", "Failed to create pipes for CGI.");
        return;
    }

    // 2. Fork the process
    pid_t pid = fork();

    // 3. Handle fork error
    if (pid == -1) {
        perror("fork failed");
        close(pipe_stdin[0]); close(pipe_stdin[1]);
        close(pipe_stdout[0]); close(pipe_stdout[1]);
        send_error_response(client_socket, 500, "Internal Server Error", "Failed to fork process for CGI.");
        return;
    }

    // 4. Child or Parent Logic
    if (pid == 0) { // ==================== CHILD PROCESS ====================
        // --- Essential: Close parent's pipe ends FIRST ---
        close(pipe_stdin[1]);  // Close write end of stdin pipe
        close(pipe_stdout[0]); // Close read end of stdout pipe

        // --- Redirect stdin/stdout ---
        if (dup2(pipe_stdin[0], STDIN_FILENO) == -1) {
             fprintf(stderr, "CHILD FATAL: dup2 stdin failed: %s\n", strerror(errno));
             _exit(EXIT_FAILURE);
        }
        if (dup2(pipe_stdout[1], STDOUT_FILENO) == -1) {
             fprintf(stderr, "CHILD FATAL: dup2 stdout failed: %s\n", strerror(errno));
             _exit(EXIT_FAILURE);
        }

        // --- Close ORIGINAL pipe descriptors AFTER dup2 ---
        close(pipe_stdin[0]);
        close(pipe_stdout[1]);

        // --- Prepare Environment ---
        std::vector<std::string> env_vars_storage;
        std::vector<char*> cgi_env_ptr;
        auto add_env = [&](const std::string& key, const std::string& value) {
            env_vars_storage.push_back(key + "=" + value);
        };

        add_env("GATEWAY_INTERFACE", "CGI/1.1");
        add_env("SERVER_PROTOCOL", request.http_version);
        add_env("REQUEST_METHOD", request.method);
        add_env("SCRIPT_NAME", request.path);
        add_env("SCRIPT_FILENAME", script_path_full);
        add_env("QUERY_STRING", request.query_string);
        add_env("REQUEST_URI", request.path + (request.query_string.empty() ? "" : "?" + request.query_string));
        add_env("DOCUMENT_ROOT", WWW_ROOT);
        add_env("REMOTE_ADDR", inet_ntoa(client_addr.sin_addr));
        add_env("REMOTE_PORT", std::to_string(ntohs(client_addr.sin_port)));
        add_env("SERVER_PORT", std::to_string(PORT));
        add_env("SERVER_SOFTWARE", "SimpleCppServer/0.7"); // Version bump

        // Correctly Add CONTENT_LENGTH and CONTENT_TYPE
        if (!request.body.empty() && (request.method == "POST" || request.method == "PUT")) {
             add_env("CONTENT_LENGTH", std::to_string(request.body.length()));
             fprintf(stderr, "CHILD: Setting CONTENT_LENGTH=%zu\n", request.body.length());
             if (request.headers.count("Content-Type")) {
                 add_env("CONTENT_TYPE", request.headers.at("Content-Type"));
             } else {
                 add_env("CONTENT_TYPE", "application/octet-stream");
             }
        } else {
             fprintf(stderr, "CHILD: Not setting CONTENT_LENGTH (body empty or method != POST/PUT)\n");
        }

        // Add HTTP_ headers
        for (const auto& pair : request.headers) {
            std::string http_header_key = "HTTP_";
            std::string key = pair.first;
            std::replace(key.begin(), key.end(), '-', '_');
            std::transform(key.begin(), key.end(), key.begin(), ::toupper);
            http_header_key += key;
            add_env(http_header_key, pair.second);
        }

        // Convert vector of strings to vector of char* for execve
        cgi_env_ptr.reserve(env_vars_storage.size() + 1);
        for (const auto& s : env_vars_storage) {
            cgi_env_ptr.push_back(const_cast<char*>(s.c_str()));
        }
        cgi_env_ptr.push_back(nullptr);

        // --- CHILD DEBUGGING: Log right before execve ---
        fprintf(stderr, "CHILD: Attempting execve for script: %s\n", script_path_full.c_str());
        fprintf(stderr, "CHILD: REQUEST_METHOD passed to execve: %s\n", request.method.c_str());
        fflush(stderr);

        // --- Execute Script ---
        char* argv[] = {const_cast<char*>(script_path_full.c_str()), nullptr};
        execve(script_path_full.c_str(), argv, cgi_env_ptr.data());

        // --- execve ONLY returns on error ---
        fprintf(stderr, "CHILD FATAL: execve failed for '%s': %s\n", script_path_full.c_str(), strerror(errno));
        perror("CHILD: execve failed (reported by perror)");

        // Try to report error back via stdout (best effort)
        printf("Status: 500 Internal Server Error\r\n");
        printf("Content-Type: text/plain\r\n\r\n");
        printf("Server Error: CGI script execution failed ('%s'). Check server logs.\n", strerror(errno));
        fflush(stdout);

        _exit(EXIT_FAILURE);

    } else { // ==================== PARENT PROCESS ====================
        fprintf(stderr, "PARENT: Child PID: %d\n", pid);

        // --- Crucial: Close unused pipe ends in PARENT ---
        close(pipe_stdin[0]);  // Close READ end of stdin pipe
        close(pipe_stdout[1]); // Close WRITE end of stdout pipe
        fprintf(stderr, "PARENT: Closed unused pipe ends (stdin[0], stdout[1])\n");

        // --- Write request body to child's stdin ---
        if (!request.body.empty()) {
            fprintf(stderr, "PARENT: Writing %zu bytes to child stdin...\n", request.body.length());
            ssize_t bytes_written_total = 0;
            const char* body_ptr = request.body.c_str();
            size_t body_len = request.body.length();
            while (bytes_written_total < body_len) {
                 ssize_t bytes_written = write(pipe_stdin[1], body_ptr + bytes_written_total, body_len - bytes_written_total);
                 if (bytes_written == -1) {
                     if (errno == EINTR) continue;
                     perror("PARENT: write to cgi stdin failed"); break;
                 }
                 bytes_written_total += bytes_written;
            }
             if (bytes_written_total == body_len) fprintf(stderr, "PARENT: Successfully wrote %zd bytes to child stdin.\n", bytes_written_total);
             else fprintf(stderr, "PARENT: Warning - Incomplete write to child stdin (%zd / %zu bytes)\n", bytes_written_total, body_len);
        } else {
             fprintf(stderr, "PARENT: No request body to write.\n");
        }
        // --- Close write end of stdin pipe AFTER writing (signals EOF to child) ---
        fprintf(stderr, "PARENT: Closing write end of stdin pipe (stdin[1]).\n");
        close(pipe_stdin[1]);

        // --- Read ALL output from child's stdout ---
        std::string cgi_output_str;
        char read_buf[READ_BUFFER_SIZE];
        ssize_t bytes_read;
        fprintf(stderr, "PARENT: Starting read loop from child stdout (stdout[0])...\n");
        while ((bytes_read = read(pipe_stdout[0], read_buf, sizeof(read_buf))) > 0) {
            cgi_output_str.append(read_buf, bytes_read);
        }
        fprintf(stderr, "PARENT: Finished read loop. Final bytes_read = %zd.\n", bytes_read);
        if (bytes_read == -1 && errno != EPIPE) { // Ignore EPIPE (Broken pipe is expected if child exits first)
            perror("PARENT: read from cgi stdout failed");
        }
        // --- Close read end of stdout pipe ---
        fprintf(stderr, "PARENT: Closing read end of stdout pipe (stdout[0]).\n");
        close(pipe_stdout[0]);

        fprintf(stderr, "PARENT: Total CGI output size: %zu bytes.\n", cgi_output_str.length());
        if (!cgi_output_str.empty()) {
             fprintf(stderr, "PARENT: CGI Output (first 100 chars): %s\n", cgi_output_str.substr(0, 100).c_str());
        }


        // --- PARSE HEADERS from CGI output ---
        fprintf(stderr, "PARENT: Parsing CGI headers...\n");
        std::string cgi_headers_str;
        std::string cgi_body_str;
        int http_status_code = 200;
        std::string http_status_text = "OK";
        std::unordered_map<std::string, std::string> cgi_headers;

        // --- MODIFIED: Search for both \r\n\r\n and \n\n ---
        size_t header_end_pos = cgi_output_str.find("\r\n\r\n");
        size_t body_start_offset = 4; // Default offset for \r\n\r\n

        if (header_end_pos == std::string::npos) {
            fprintf(stderr, "PARENT: Did not find \\r\\n\\r\\n, trying \\n\\n...\n");
            header_end_pos = cgi_output_str.find("\n\n");
            body_start_offset = 2; // Offset for \n\n
        }
        // --- END MODIFICATION ---

        fprintf(stderr, "PARENT: Found header_end_pos at: %zu (using offset %zu)\n", header_end_pos, body_start_offset);

        if (header_end_pos != std::string::npos) {
            cgi_headers_str = cgi_output_str.substr(0, header_end_pos);
            size_t body_start_pos = header_end_pos + body_start_offset;
            fprintf(stderr, "PARENT: Calculated body_start_pos: %zu\n", body_start_pos);

            if (body_start_pos <= cgi_output_str.length()) {
                 cgi_body_str = cgi_output_str.substr(body_start_pos);
                 // fprintf(stderr, "PARENT: Extracted body (first 100): %s\n", cgi_body_str.substr(0, 100).c_str());
            } else {
                 fprintf(stderr, "PARENT: Warning - body_start_pos is out of bounds (%zu > %zu)! Treating body as empty.\n",
                        body_start_pos, cgi_output_str.length());
                 cgi_body_str = "";
            }
        } else {
            // This block now only runs if NEITHER separator was found
            log_message("ERROR: Could not find ANY header separator (\\r\\n\\r\\n or \\n\\n) in CGI output.");
            cgi_body_str = cgi_output_str; // Treat all as body as a last resort
            cgi_headers["Content-Type"] = "text/plain";
            fprintf(stderr, "PARENT: Treating all CGI output as body due to missing header separator.\n");
            http_status_code = 500; // Indicate an error if we couldn't parse headers
            http_status_text = "Internal Server Error";
        }

        // Parse individual headers from the script's header block
        std::istringstream header_stream(cgi_headers_str);
        std::string header_line;
        while (std::getline(header_stream, header_line)) {
             if (!header_line.empty() && header_line.back() == '\r') header_line.pop_back();
             if (header_line.empty()) continue;
             size_t colon_pos = header_line.find(':');
             if (colon_pos != std::string::npos) {
                 std::string key = header_line.substr(0, colon_pos);
                 std::string value = header_line.substr(colon_pos + 1);
                 value.erase(0, value.find_first_not_of(" \t"));
                 value.erase(value.find_last_not_of(" \t") + 1);
                 if (key == "Status") {
                     size_t space_pos = value.find(' ');
                     if (space_pos != std::string::npos) { try { http_status_code = std::stoi(value.substr(0, space_pos)); http_status_text = value.substr(space_pos + 1); } catch (...) { fprintf(stderr, "PARENT: Warn: Bad Status head val: %s\n", value.c_str());} }
                     else { try { http_status_code = std::stoi(value); http_status_text = "Status " + std::to_string(http_status_code); } catch (...) { fprintf(stderr, "PARENT: Warn: Bad Status head val: %s\n", value.c_str());} }
                 } else { cgi_headers[key] = value; }
             } else { fprintf(stderr, "PARENT: Warning - Malformed header line from CGI: %s\n", header_line.c_str()); }
        }

        fprintf(stderr, "PARENT: Parsing complete. Status=%d, Body Size=%zu\n", http_status_code, cgi_body_str.length());

        // --- Construct and SEND the final HTTP Response ---
        fprintf(stderr, "PARENT: Constructing final HTTP response...\n");
        std::ostringstream response_stream;
        response_stream << "HTTP/1.1 " << http_status_code << " " << http_status_text << "\r\n";
        response_stream << "Server: SimpleCppServer/0.7\r\n";
        response_stream << "Connection: close\r\n";
        bool content_type_sent = false;
        for(const auto& pair : cgi_headers) {
            response_stream << pair.first << ": " << pair.second << "\r\n";
            if (pair.first == "Content-Type") content_type_sent = true;
        }
        if (!content_type_sent) {
             response_stream << "Content-Type: text/html\r\n"; // Default
             fprintf(stderr, "PARENT: Warning - CGI script did not provide Content-Type. Defaulting to text/html.\n");
        }
        response_stream << "Content-Length: " << cgi_body_str.length() << "\r\n";
        response_stream << "\r\n"; // End of server headers
        response_stream << cgi_body_str; // Append the body from CGI
        std::string final_response = response_stream.str();
        fprintf(stderr, "PARENT: Sending final response (%zu bytes)...\n", final_response.length());

        // Use send loop for robustness
        ssize_t bytes_sent_total = 0;
        const char* response_ptr = final_response.c_str();
        size_t response_len = final_response.length();
        while(bytes_sent_total < response_len) {
             ssize_t bytes_sent = send(client_socket, response_ptr + bytes_sent_total, response_len - bytes_sent_total, 0);
             if (bytes_sent == -1) { if (errno == EINTR) continue; perror("PARENT: send final response failed"); break; }
             bytes_sent_total += bytes_sent;
        }
        if (bytes_sent_total == response_len) {
             log_message("Sent Response: " + std::to_string(http_status_code) + " " + http_status_text + " (via CGI)");
             fprintf(stderr, "PARENT: Final response sent successfully.\n");
        } else { fprintf(stderr, "PARENT: Warning - Incomplete send of final response (%zd / %zu bytes)\n", bytes_sent_total, response_len); }


        // --- Wait for child process ---
        fprintf(stderr, "PARENT: Waiting for child PID %d...\n", pid);
        int status;
        waitpid(pid, &status, 0);
        fprintf(stderr, "PARENT: Child PID %d finished.\n", pid);
        if (WIFEXITED(status)) { int exit_code = WEXITSTATUS(status); if (exit_code != 0) log_message("CGI script exited with status: " + std::to_string(exit_code)); }
        else if (WIFSIGNALED(status)) { log_message("CGI script terminated by signal: " + std::to_string(WTERMSIG(status))); fprintf(stderr, "PARENT: Child process %d terminated by signal %d\n", pid, WTERMSIG(status)); }
        else { log_message("CGI script terminated abnormally (unknown reason)."); }
         fprintf(stderr, "PARENT: Exiting execute_cgi for child PID %d.\n", pid);

    } // End parent process block
}

// --- Static File Serving ---
void serve_static_file(int client_socket, const std::string& full_path) {
    log_message("Serving static file: " + full_path);
    std::string content;
    if (!read_file_content(full_path, content)) {
        send_error_response(client_socket, 404, "Not Found");
        return;
    }

    std::string mime_type = get_mime_type(full_path);

    std::ostringstream response_stream;
    response_stream << "HTTP/1.1 200 OK\r\n";
    response_stream << "Content-Type: " << mime_type << "\r\n";
    response_stream << "Content-Length: " << content.length() << "\r\n";
    response_stream << "Connection: close\r\n";
    response_stream << "\r\n"; // End of headers

    // Send headers first
    std::string headers = response_stream.str();
    if (send(client_socket, headers.c_str(), headers.length(), 0) == -1) {
        perror("send headers failed");
        return; // Stop if headers fail
    }
     // Send body
    if (send(client_socket, content.c_str(), content.length(), 0) == -1) {
         perror("send body failed");
    } else {
         log_message("Sent Response: 200 OK");
    }
}


// --- Request Handling Logic ---
void handle_connection(int client_socket, struct sockaddr_in client_addr) {
    log_message("Handling connection from: " + std::string(inet_ntoa(client_addr.sin_addr)));
    char buffer[READ_BUFFER_SIZE] = {0};
    std::string raw_request;

    // Read the request (basic implementation - might need refinement for large requests)
    ssize_t bytes_received = read(client_socket, buffer, sizeof(buffer) - 1);
    if (bytes_received <= 0) {
        if (bytes_received == 0) {
            log_message("Client disconnected before sending data.");
        } else {
            perror("read failed");
        }
        close(client_socket);
        return;
    }
    raw_request.assign(buffer, bytes_received);

    // Trim potential trailing garbage if buffer wasn't full but contained nulls earlier
    raw_request.resize(strnlen(buffer, bytes_received));


    // --- Parse Request ---
    HttpRequest request;
    if (!parse_request(raw_request, request)) {
        send_error_response(client_socket, 400, "Bad Request");
        close(client_socket);
        return;
    }

    log_message("Received Request: " + request.method + " " + request.path + (request.query_string.empty() ? "" : "?" + request.query_string));

    // --- Routing ---
    std::string requested_path = request.path;

    // Default to index.html for root path
    if (requested_path == "/") {
        requested_path = "/index.html";
    }

    // Construct full path (prevent directory traversal)
    std::string full_path = WWW_ROOT + requested_path;

    // Basic security check: Prevent accessing files outside WWW_ROOT using ".."
    if (full_path.find("..") != std::string::npos) {
        log_message("Security Alert: Path traversal attempt detected: " + full_path);
        send_error_response(client_socket, 403, "Forbidden");
        close(client_socket);
        return;
    }

    // Check if it's a CGI request
    bool is_cgi = requested_path.rfind(CGI_BIN_PATH, 0) == 0; // Check if path starts with CGI_BIN_PATH

    if (is_cgi) {
        std::string script_path_relative = requested_path.substr(strlen(CGI_BIN_PATH));
        std::string script_full_path = std::string(WWW_ROOT) + CGI_BIN_PATH + script_path_relative;

        // Check if the CGI script file exists and is executable (basic check)
        if (access(script_full_path.c_str(), X_OK) == 0) {
             execute_cgi(client_socket, request, script_full_path, client_addr);
        } else {
             log_message("Error: CGI script not found or not executable: " + script_full_path + " (" + strerror(errno) + ")");
             send_error_response(client_socket, 404, "Not Found", "CGI script not found or not executable.");
        }
    } else {
        // Serve static file
        serve_static_file(client_socket, full_path);
    }

    // Close the client socket
    close(client_socket);
    log_message("Connection closed for: " + std::string(inet_ntoa(client_addr.sin_addr)));
}

// --- Main Server Loop ---
int main() {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // 1. Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 8080 (optional, avoids "Address already in use" error)
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        // exit(EXIT_FAILURE); // Might be non-critical
    }

    // 2. Bind socket
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // 3. Listen
    if (listen(server_fd, 10) < 0) { // Increased backlog queue size
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    log_message("Server listening on http://localhost:" + std::to_string(PORT) + "/");
    log_message("Serving files from directory: " + std::string(WWW_ROOT));
    log_message("CGI scripts expected in: " + std::string(WWW_ROOT) + CGI_BIN_PATH);


    // 4. Accept and Handle Connections Concurrently
    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_addrlen = sizeof(client_addr);
        int new_socket = accept(server_fd, (struct sockaddr*)&client_addr, &client_addrlen);

        if (new_socket < 0) {
            perror("Accept failed");
            // Don't exit, just log and continue trying to accept
            continue;
        }

        // Create a new thread to handle the connection
        // Pass socket and client address by value (or move if appropriate)
        // Use detach() for simplicity in this example; the thread cleans up itself.
        // For robustness, consider joining threads or using a thread pool.
        std::thread client_thread(handle_connection, new_socket, client_addr);
        client_thread.detach();
    }

    // Cleanup (normally unreachable in this simple loop)
    close(server_fd);
    return 0;
}