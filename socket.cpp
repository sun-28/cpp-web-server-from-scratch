#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> // For inet_ntoa
#include <unistd.h>
#include <sys/wait.h>  // For waitpid
#include <sys/stat.h>  // For stat (needed if you add directory listing)
#include <dirent.h>    // For opendir, readdir (needed if you add directory listing)
#include <unordered_map>
#include <thread>      // For std::thread
#include <mutex>       // For std::mutex
#include <chrono>      // For timestamps
#include <iomanip>     // For put_time, setfill, setw
#include <atomic>      // For atomic counters
#include <cstdlib>     // For exit, _exit, EXIT_FAILURE, EXIT_SUCCESS
#include <cerrno>      // For errno
#include <algorithm>   // For replace, transform
#include <cstdio>      // For fprintf, perror (used mainly in child process debug)


#ifndef _WIN32 // <-- Add this check
#include <fcntl.h> // <-- Include fcntl here for POSIX
#endif 

#define PORT 8080
#define WWW_ROOT "www"
#define CGI_BIN_PATH "/cgi-bin/"
#define READ_BUFFER_SIZE 4096
#define LOG_FILE "server.log"
#define LOG_TAIL_LINES 50 // Number of lines for /logdata


// RUN: g++ socket.cpp -o socket -std=c++11 -pthread

// --- Global Variables for Logging & Stats ---
std::ofstream log_file_stream;
std::mutex log_mutex; // Mutex to protect log file writes

// Simple Status Counters
std::atomic<long long> total_requests_served(0);
std::atomic<long long> static_files_served(0);
std::atomic<long long> cgi_scripts_executed(0);
std::atomic<long> current_active_threads(0); // Basic active thread count

// --- Logging Function ---
void server_log(const std::string& message) {
    try {
        auto now = std::chrono::system_clock::now();
        auto now_c = std::chrono::system_clock::to_time_t(now);
        // Check for potential null pointer from std::localtime
        std::tm now_tm;
        #ifdef _WIN32 // Windows specific localtime_s
                localtime_s(&now_tm, &now_c);
        #else // POSIX localtime_r
                localtime_r(&now_c, &now_tm);
        #endif

        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

        std::ostringstream timestamp_ss;
        timestamp_ss << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S");
        timestamp_ss << '.' << std::setfill('0') << std::setw(3) << now_ms.count();
        std::string timestamp = timestamp_ss.str();

        std::string log_line = "[" + timestamp + "] " + message;

        std::lock_guard<std::mutex> lock(log_mutex);
        std::cerr << log_line << std::endl; // Log to console
        if (log_file_stream.is_open()) {
            log_file_stream << log_line << std::endl; // Log to file
        }
    } catch (const std::exception& e) {
        // Fallback if logging itself fails (e.g., time functions)
        std::lock_guard<std::mutex> lock(log_mutex);
        std::cerr << "[RAW LOG ERROR] " << e.what() << " | Original Msg: " << message << std::endl;
    } catch (...) {
        std::lock_guard<std::mutex> lock(log_mutex);
        std::cerr << "[RAW LOG ERROR] Unknown error | Original Msg: " << message << std::endl;
    }
}


// --- Helper Function Prototypes ---
std::string get_mime_type(const std::string& file_path);
bool read_file_content(const std::string& file_path, std::string& content);
void send_error_response(int socket, int status_code, const std::string& status_message, const std::string& body = "");
struct HttpRequest; // Forward declaration
bool parse_request(const std::string& raw_request, HttpRequest& request);
void serve_static_file(int client_socket, const std::string& full_path);
void execute_cgi(int client_socket, const HttpRequest& request, const std::string& script_path_full, const struct sockaddr_in& client_addr);
std::string get_log_tail(const std::string& filename, int num_lines);
void handle_connection_wrapper(int client_socket, struct sockaddr_in client_addr); // Wrapper for thread


// --- Struct Definition ---
struct HttpRequest {
    std::string method;
    std::string path;
    std::string query_string;
    std::string http_version;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
};


// --- Helper Function Implementations ---

std::string get_mime_type(const std::string& file_path) {
    std::unordered_map<std::string, std::string> mime_types = {
        {".html", "text/html"}, {".htm", "text/html"},
        {".css", "text/css"}, {".js", "application/javascript"},
        {".png", "image/png"}, {".jpg", "image/jpeg"}, {".jpeg", "image/jpeg"},
        {".gif", "image/gif"}, {".svg", "image/svg+xml"}, {".ico", "image/x-icon"},
        {".json", "application/json"}, {".txt", "text/plain"}, {".pdf", "application/pdf"},
        {".mp4", "video/mp4"}, {".log", "text/plain"},
    };
    size_t dot_pos = file_path.rfind('.');
    if (dot_pos != std::string::npos) {
        std::string ext = file_path.substr(dot_pos);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        if (mime_types.count(ext)) return mime_types.at(ext);
    }
    return "application/octet-stream";
}

bool read_file_content(const std::string& file_path, std::string& content) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        // Note: Don't log error here, caller (serve_static_file) will log if needed before 404
        return false;
    }
    std::ostringstream ss;
    ss << file.rdbuf();
    content = ss.str();
    return true;
}

void send_error_response(int socket, int status_code, const std::string& status_message, const std::string& body) {
    std::ostringstream response_stream;
    std::string content;
    std::string content_type = "text/html; charset=utf-8";
    
    if (status_code == 404) {
        std::ifstream gif_file("./www/notfound.gif", std::ios::binary);
        if (gif_file) {
            std::ostringstream gif_base64;
            gif_base64 << "data:image/gif;base64,";
            gif_base64 << std::string((std::istreambuf_iterator<char>(gif_file)), std::istreambuf_iterator<char>());
            
            content = "<html><head><title>404 Not Found</title>"
                      "<style>body { text-align: center; font-family: Arial, sans-serif; margin-top: 10%; }"
                      "img { max-width: 300px; }</style></head>"
                      "<body>"
                      "<h1>404 Not Found</h1>"
                      "<img src=\"./notfound.gif\" alt=\"Not Found\">"
                      "</body></html>";
        } else {
            content = "<html><body style='text-align:center; font-family:Arial, sans-serif; margin-top:10%;'>"
                      "<h1>404 Not Found</h1>"
                      "</body></html>";
        }
    } else {
        content = body.empty() ? ("<html><body><h1>" + std::to_string(status_code) + " " + status_message + "</h1></body></html>") : body;
    }
    
    response_stream << "HTTP/1.1 " << status_code << " " << status_message << "\r\n";
    response_stream << "Content-Type: " << content_type << "\r\n";
    response_stream << "Content-Length: " << content.length() << "\r\n";
    response_stream << "Connection: close\r\n";
    response_stream << "\r\n";
    response_stream << content;

    std::string response = response_stream.str();
    ssize_t sent_bytes = send(socket, response.c_str(), response.length(), 0);
    if (sent_bytes == -1) {
        perror("send error response failed");
        server_log("Error sending " + std::to_string(status_code) + " response: " + strerror(errno));
    } else {
        server_log("Sent Response: " + std::to_string(status_code) + " " + status_message);
    }
}


bool parse_request(const std::string& raw_request, HttpRequest& request) {
    // (Using the robust parsing logic from previous examples)
    std::istringstream request_stream(raw_request);
    std::string request_line;
    if (!std::getline(request_stream, request_line) || request_line.empty()) return false;
    if (request_line.back() == '\r') request_line.pop_back();

    std::istringstream line_stream(request_line);
    if (!(line_stream >> request.method >> request.path >> request.http_version)) return false;

    size_t query_pos = request.path.find('?');
    if (query_pos != std::string::npos) {
        request.query_string = request.path.substr(query_pos + 1);
        request.path = request.path.substr(0, query_pos);
    }

    std::string header_line;
    while (std::getline(request_stream, header_line) && !header_line.empty() && header_line != "\r") {
        if (header_line.back() == '\r') header_line.pop_back();
        size_t colon_pos = header_line.find(':');
        if (colon_pos != std::string::npos) {
            std::string key = header_line.substr(0, colon_pos);
            std::string value = header_line.substr(colon_pos + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            request.headers[key] = value;
        }
    }

    size_t body_start_pos = raw_request.find("\r\n\r\n");
    if (body_start_pos != std::string::npos) {
         request.body = raw_request.substr(body_start_pos + 4);
         // Basic Content-Length check (could be more robust)
         if (request.headers.count("Content-Length")) {
            try {
                size_t expected = std::stoul(request.headers["Content-Length"]);
                if (request.body.length() > expected) request.body.resize(expected);
                // Note: Doesn't handle reading *more* if body was truncated initially
            } catch (...) { /* Ignore parse error */ }
         }
    }
    return true;
}

void serve_static_file(int client_socket, const std::string& full_path) {
    server_log("Serving static file: " + full_path);
    std::string content;
    if (!read_file_content(full_path, content)) {
        server_log("Static file not found: " + full_path); // Log before sending 404
        send_error_response(client_socket, 404, "Not Found");
        return;
    }

    std::string mime_type = get_mime_type(full_path);
    std::ostringstream response_stream;
    response_stream << "HTTP/1.1 200 OK\r\n";
    response_stream << "Content-Type: " << mime_type << "\r\n";
    response_stream << "Content-Length: " << content.length() << "\r\n";
    response_stream << "Connection: close\r\n";
    response_stream << "\r\n";

    std::string headers = response_stream.str();
    if (send(client_socket, headers.c_str(), headers.length(), 0) == -1) {
        perror("send static headers failed");
        server_log("Error sending static headers for " + full_path + ": " + strerror(errno));
        return;
    }
    if (send(client_socket, content.c_str(), content.length(), 0) == -1) {
         perror("send static body failed");
         server_log("Error sending static body for " + full_path + ": " + strerror(errno));
    } else {
         server_log("Sent Response: 200 OK (Static: " + full_path + ")");
    }
}

std::string get_log_tail(const std::string& filename, int num_lines) {
    // Lock mutex for reading the log file as well, to avoid conflicts with writes
    std::lock_guard<std::mutex> lock(log_mutex);
    std::ifstream file(filename);
    if (!file) {
        return "Error: Could not open log file '" + filename + "'";
    }

    std::vector<std::string> lines;
    lines.reserve(num_lines + 10); // Reserve some space
    std::string line;
    while (std::getline(file, line)) {
        lines.push_back(line);
        // Optional: Limit memory usage for very large files
        // if (lines.size() > static_cast<size_t>(num_lines * 2)) { // Keep a bit more than needed
        //     lines.erase(lines.begin(), lines.begin() + lines.size() - num_lines);
        // }
    }

    std::ostringstream result_ss;
    size_t start_index = (lines.size() > static_cast<size_t>(num_lines)) ? (lines.size() - num_lines) : 0;

    for (size_t i = start_index; i < lines.size(); ++i) {
        result_ss << lines[i] << "\n"; // Use \n for text/plain output
    }
    return result_ss.str();
}


// Execute CGI script (incorporating previous fixes)
void execute_cgi(int client_socket, const HttpRequest& request, const std::string& script_path_full, const struct sockaddr_in& client_addr) {
    server_log("Executing CGI script: " + script_path_full); // Use server_log

    int pipe_stdin[2];  // Server -> Child (POST Body)
    int pipe_stdout[2]; // Child -> Server (Response)

    if (pipe(pipe_stdin) == -1 || pipe(pipe_stdout) == -1) {
        perror("pipe failed");
        server_log("Failed to create pipes for CGI: " + std::string(strerror(errno)));
        send_error_response(client_socket, 500, "Internal Server Error", "Failed to create pipes for CGI.");
        return;
    }

    pid_t pid = fork();

    if (pid == -1) {
        perror("fork failed");
        server_log("Failed to fork process for CGI: " + std::string(strerror(errno)));
        close(pipe_stdin[0]); close(pipe_stdin[1]);
        close(pipe_stdout[0]); close(pipe_stdout[1]);
        send_error_response(client_socket, 500, "Internal Server Error", "Failed to fork process for CGI.");
        return;
    }

    if (pid == 0) { // ==================== CHILD PROCESS ====================
        close(pipe_stdin[1]);
        close(pipe_stdout[0]);

        if (dup2(pipe_stdin[0], STDIN_FILENO) == -1) { fprintf(stderr, "CHILD FATAL: dup2 stdin failed: %s\n", strerror(errno)); _exit(EXIT_FAILURE); }
        if (dup2(pipe_stdout[1], STDOUT_FILENO) == -1) { fprintf(stderr, "CHILD FATAL: dup2 stdout failed: %s\n", strerror(errno)); _exit(EXIT_FAILURE); }

        close(pipe_stdin[0]);
        close(pipe_stdout[1]);

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
        add_env("SERVER_SOFTWARE", "SimpleCppServer/0.8-log"); // Version bump

        if (!request.body.empty() && (request.method == "POST" || request.method == "PUT")) {
             add_env("CONTENT_LENGTH", std::to_string(request.body.length()));
             // fprintf(stderr, "CHILD: Setting CONTENT_LENGTH=%zu\n", request.body.length()); // Keep if needed
             if (request.headers.count("Content-Type")) add_env("CONTENT_TYPE", request.headers.at("Content-Type"));
             else add_env("CONTENT_TYPE", "application/octet-stream");
        }
        // else { fprintf(stderr, "CHILD: Not setting CONTENT_LENGTH...\n"); } // Keep if needed

        for (const auto& pair : request.headers) {
            std::string http_header_key = "HTTP_"; std::string key = pair.first;
            std::replace(key.begin(), key.end(), '-', '_');
            std::transform(key.begin(), key.end(), key.begin(), ::toupper);
            http_header_key += key; add_env(http_header_key, pair.second);
        }

        cgi_env_ptr.reserve(env_vars_storage.size() + 1);
        for (const auto& s : env_vars_storage) cgi_env_ptr.push_back(const_cast<char*>(s.c_str()));
        cgi_env_ptr.push_back(nullptr);

        // fprintf(stderr, "CHILD: Attempting execve for script: %s\n", script_path_full.c_str()); // Keep if needed
        // fprintf(stderr, "CHILD: REQUEST_METHOD passed to execve: %s\n", request.method.c_str()); // Keep if needed
        fflush(stderr);

        char* argv[] = {const_cast<char*>(script_path_full.c_str()), nullptr};
        execve(script_path_full.c_str(), argv, cgi_env_ptr.data());

        fprintf(stderr, "CHILD FATAL: execve failed for '%s': %s\n", script_path_full.c_str(), strerror(errno));
        perror("CHILD: execve failed (reported by perror)");
        printf("Status: 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nServer Error: CGI script execution failed ('%s').\n", strerror(errno));
        fflush(stdout);
        _exit(EXIT_FAILURE);

    } else { // ==================== PARENT PROCESS ====================
        // fprintf(stderr, "PARENT: Child PID: %d\n", pid); // Use server_log instead if desired
        close(pipe_stdin[0]);
        close(pipe_stdout[1]);
        // fprintf(stderr, "PARENT: Closed unused pipe ends (stdin[0], stdout[1])\n"); // Debug only

        if (!request.body.empty()) {
            // fprintf(stderr, "PARENT: Writing %zu bytes to child stdin...\n", request.body.length()); // Debug only
            ssize_t bytes_written_total = 0;
            const char* body_ptr = request.body.c_str(); size_t body_len = request.body.length();
            while (bytes_written_total < body_len) {
                 ssize_t bytes_written = write(pipe_stdin[1], body_ptr + bytes_written_total, body_len - bytes_written_total);
                 if (bytes_written == -1) { if (errno == EINTR) continue; perror("PARENT: write to cgi stdin failed"); server_log("Error writing CGI stdin: " + std::string(strerror(errno))); break; }
                 bytes_written_total += bytes_written;
            }
             // if (bytes_written_total == body_len) fprintf(stderr, "PARENT: Successfully wrote %zd bytes to child stdin.\n", bytes_written_total); // Debug
             // else fprintf(stderr, "PARENT: Warning - Incomplete write to child stdin (%zd / %zu bytes)\n", bytes_written_total, body_len); // Debug
        }
        // else { fprintf(stderr, "PARENT: No request body to write.\n"); } // Debug only

        // fprintf(stderr, "PARENT: Closing write end of stdin pipe (stdin[1]).\n"); // Debug only
        close(pipe_stdin[1]);

        std::string cgi_output_str;
        char read_buf[READ_BUFFER_SIZE];
        ssize_t bytes_read;
        // fprintf(stderr, "PARENT: Starting read loop from child stdout (stdout[0])...\n"); // Debug only
        while ((bytes_read = read(pipe_stdout[0], read_buf, sizeof(read_buf))) > 0) {
            cgi_output_str.append(read_buf, bytes_read);
        }
        // fprintf(stderr, "PARENT: Finished read loop. Final bytes_read = %zd.\n", bytes_read); // Debug only
        if (bytes_read == -1 && errno != EPIPE) { // Ignore broken pipe if child exited cleanly
             perror("PARENT: read from cgi stdout failed");
             server_log("Error reading CGI stdout: " + std::string(strerror(errno)));
        }
        // fprintf(stderr, "PARENT: Closing read end of stdout pipe (stdout[0]).\n"); // Debug only
        close(pipe_stdout[0]);
        // fprintf(stderr, "PARENT: Total CGI output size: %zu bytes.\n", cgi_output_str.length()); // Debug only

        std::string cgi_headers_str;
        std::string cgi_body_str;
        int http_status_code = 200;
        std::string http_status_text = "OK";
        std::unordered_map<std::string, std::string> cgi_headers;

        size_t header_end_pos = cgi_output_str.find("\r\n\r\n");
        size_t body_start_offset = 4;
        if (header_end_pos == std::string::npos) {
            // fprintf(stderr, "PARENT: Did not find \\r\\n\\r\\n, trying \\n\\n...\n"); // Debug only
            header_end_pos = cgi_output_str.find("\n\n");
            body_start_offset = 2;
        }

        if (header_end_pos != std::string::npos) {
            cgi_headers_str = cgi_output_str.substr(0, header_end_pos);
            size_t body_start_pos = header_end_pos + body_start_offset;
            if (body_start_pos <= cgi_output_str.length()) cgi_body_str = cgi_output_str.substr(body_start_pos);
            else { /* Handle out of bounds - log warning if needed */ cgi_body_str = "";}
        } else {
            server_log("ERROR: Could not find ANY header separator in CGI output for " + request.path);
            cgi_body_str = cgi_output_str;
            cgi_headers["Content-Type"] = "text/plain";
            http_status_code = 500; http_status_text = "Internal Server Error";
        }

        std::istringstream header_stream(cgi_headers_str);
        std::string header_line;
        while (std::getline(header_stream, header_line)) {
             if (!header_line.empty() && header_line.back() == '\r') header_line.pop_back();
             if (header_line.empty()) continue;
             size_t colon_pos = header_line.find(':');
             if (colon_pos != std::string::npos) {
                 std::string key = header_line.substr(0, colon_pos); std::string value = header_line.substr(colon_pos + 1);
                 value.erase(0, value.find_first_not_of(" \t")); value.erase(value.find_last_not_of(" \t") + 1);
                 if (key == "Status") { /* Parse status */
                     size_t space_pos = value.find(' ');
                     if (space_pos != std::string::npos) { try { http_status_code = std::stoi(value.substr(0, space_pos)); http_status_text = value.substr(space_pos + 1); } catch (...) { server_log("Warn: Bad CGI Status hdr: "+value);} }
                     else { try { http_status_code = std::stoi(value); http_status_text = "Status " + std::to_string(http_status_code); } catch (...) { server_log("Warn: Bad CGI Status hdr: "+value);} }
                 } else { cgi_headers[key] = value; }
             } // else { server_log("Warn: Malformed CGI hdr: " + header_line); } // Optional logging
        }
        // fprintf(stderr, "PARENT: Parsing complete. Status=%d, Body Size=%zu\n", http_status_code, cgi_body_str.length()); // Debug


        std::ostringstream response_stream;
        response_stream << "HTTP/1.1 " << http_status_code << " " << http_status_text << "\r\n";
        response_stream << "Server: SimpleCppServer/0.8-log\r\n";
        response_stream << "Connection: close\r\n";
        bool content_type_sent = false;
        for(const auto& pair : cgi_headers) {
            response_stream << pair.first << ": " << pair.second << "\r\n";
            if (pair.first == "Content-Type") content_type_sent = true;
        }
        if (!content_type_sent) {
             response_stream << "Content-Type: text/html\r\n"; // Default
             server_log("Warn: CGI script " + request.path + " did not provide Content-Type.");
        }
        response_stream << "Content-Length: " << cgi_body_str.length() << "\r\n";
        response_stream << "\r\n";
        response_stream << cgi_body_str;
        std::string final_response = response_stream.str();
        // fprintf(stderr, "PARENT: Sending final response (%zu bytes)...\n", final_response.length()); // Debug

        ssize_t bytes_sent_total = 0;
        const char* response_ptr = final_response.c_str(); size_t response_len = final_response.length();
        while(bytes_sent_total < response_len) {
             ssize_t bytes_sent = send(client_socket, response_ptr + bytes_sent_total, response_len - bytes_sent_total, 0);
             if (bytes_sent == -1) { if (errno == EINTR) continue; perror("PARENT: send final response failed"); server_log("Error sending final CGI response: "+std::string(strerror(errno))); break; }
             bytes_sent_total += bytes_sent;
        }
        if (bytes_sent_total == response_len) {
             server_log("Sent Response: " + std::to_string(http_status_code) + " " + http_status_text + " (via CGI: " + request.path + ")");
             // fprintf(stderr, "PARENT: Final response sent successfully.\n"); // Debug
        } else { /* Log incomplete send warning */ }


        // fprintf(stderr, "PARENT: Waiting for child PID %d...\n", pid); // Debug
        int status;
        waitpid(pid, &status, 0);
        // fprintf(stderr, "PARENT: Child PID %d finished.\n", pid); // Debug
        if (WIFEXITED(status)) { int exit_code = WEXITSTATUS(status); if (exit_code != 0) server_log("CGI script " + request.path + " exited with status: " + std::to_string(exit_code)); }
        else if (WIFSIGNALED(status)) { server_log("CGI script " + request.path + " terminated by signal: " + std::to_string(WTERMSIG(status))); }
        else { server_log("CGI script " + request.path + " terminated abnormally."); }
        // fprintf(stderr, "PARENT: Exiting execute_cgi for child PID %d.\n", pid); // Debug

    } // End parent process block
}

// Helper function needed by handle_connection's catch block (basic implementation)
// WARNING: This is not fully reliable, especially after errors.
// A better approach might involve setsockopt SO_ERROR or non-blocking checks.
bool socket_is_valid(int sockfd) {
    if (sockfd < 0) return false;
    // Basic check using fcntl to see if descriptor is open
    #ifndef _WIN32 // fcntl is POSIX specific
        //#include <fcntl.h>
        return fcntl(sockfd, F_GETFL) != -1 || errno != EBADF;
    #else
        // No easy equivalent on Windows without more complex checks
        return true; // Assume valid on Windows for simplicity here
    #endif
}


// --- Request Handling Logic ---
// (handle_connection calls handle_connection_wrapper which handles thread lifecycle)
void handle_connection(int client_socket, struct sockaddr_in client_addr) {
    // This function now primarily parses request and calls appropriate handler
    total_requests_served++;
    std::string client_ip = inet_ntoa(client_addr.sin_addr);
    // Log connection start AFTER incrementing thread count (in wrapper)
    // server_log("Handling connection from: " + client_ip + " (Thread " + std::to_string(current_active_threads) + ")");

    char buffer[READ_BUFFER_SIZE] = {0};
    std::string raw_request;

    // Basic read - production server might need more robust reading loop
    ssize_t bytes_received = read(client_socket, buffer, sizeof(buffer) - 1);

    if (bytes_received <= 0) {
        if (bytes_received == 0) server_log("Client " + client_ip + " disconnected before sending data.");
        else { perror("read failed"); server_log("Read error from " + client_ip + ": " + strerror(errno));}
        // close(client_socket); // Socket will be closed in wrapper's finally block
        return; // Exit this specific handler function
    }
    raw_request.assign(buffer, bytes_received);
    // Simple way to handle potential embedded nulls if read didn't fill buffer
    raw_request.resize(strnlen(buffer, bytes_received));


    HttpRequest request;
    if (!parse_request(raw_request, request)) {
        server_log("Received Invalid Request from " + client_ip + ". Raw:\n" + raw_request.substr(0, 200)); // Log part of bad request
        send_error_response(client_socket, 400, "Bad Request");
        // close(client_socket); // Closed in wrapper
        return;
    }

    // Log parsed request AFTER successful parsing
    server_log("Received Request from " + client_ip + ": " + request.method + " " + request.path + (request.query_string.empty() ? "" : "?" + request.query_string));


    // --- Routing ---
    std::string requested_path = request.path;

    try { // Add try-catch around routing/handling for unexpected errors
        // Handle Log Data Request
        if (requested_path == "/logdata") {
            server_log("Serving log data request from " + client_ip);
            std::string log_content = get_log_tail(LOG_FILE, LOG_TAIL_LINES);
            std::string http_response = "HTTP/1.1 200 OK\r\n"
                                        "Content-Type: text/plain; charset=utf-8\r\n"
                                        "Content-Length: " + std::to_string(log_content.length()) + "\r\n"
                                        "Connection: close\r\n"
                                        "Cache-Control: no-cache\r\n"
                                        "\r\n" + log_content;
            ssize_t sent = send(client_socket, http_response.c_str(), http_response.length(), 0);
            if (sent == -1) server_log("Error sending log data to " + client_ip + ": " + strerror(errno));
        }
        // Handle Log Viewer HTML
        else if (requested_path == "/logviewer") {
            static_files_served++;
            serve_static_file(client_socket, std::string(WWW_ROOT) + "/logviewer.html");
        }
        // Handle other requests (static / CGI)
        else {
            if (requested_path == "/") requested_path = "/index.html";

            std::string full_path = WWW_ROOT + requested_path;

            // Basic security check: Prevent directory traversal
            // Real check should resolve path then verify it's still within WWW_ROOT
            if (full_path.find("..") != std::string::npos) {
                server_log("Security Alert: Path traversal attempt detected from " + client_ip + ": " + requested_path);
                send_error_response(client_socket, 403, "Forbidden");
            } else {
                // Check if it's a CGI request
                bool is_cgi = requested_path.rfind(CGI_BIN_PATH, 0) == 0;

                if (is_cgi) {
                    cgi_scripts_executed++;
                    std::string script_path_relative = requested_path.substr(strlen(CGI_BIN_PATH));
                    std::string script_full_path = std::string(WWW_ROOT) + CGI_BIN_PATH + script_path_relative;

                    if (access(script_full_path.c_str(), X_OK) == 0) {
                         execute_cgi(client_socket, request, script_full_path, client_addr);
                         // Note: execute_cgi now handles sending response and logging success/failure
                    } else {
                         server_log("Error: CGI script not found or not executable: " + script_full_path + " (" + strerror(errno) + ")");
                         send_error_response(client_socket, 404, "Not Found", "CGI script not found or not executable.");
                    }
                } else {
                    // Serve static file
                    static_files_served++;
                    serve_static_file(client_socket, full_path);
                    // Note: serve_static_file handles sending response and logging
                }
            }
        } // End standard routing else
    } catch (const std::exception& e) {
         server_log("!!! Exception during request handling for " + client_ip + " (" + request.path + "): " + e.what());
         // Try to send a 500 error if possible (socket might already be bad)
         if (socket_is_valid(client_socket)) { // Need a helper function `socket_is_valid`
             send_error_response(client_socket, 500, "Internal Server Error", "An internal error occurred.");
         }
    } catch (...) {
        server_log("!!! Unknown exception during request handling for " + client_ip + " (" + request.path + ")");
         if (socket_is_valid(client_socket)) {
             send_error_response(client_socket, 500, "Internal Server Error", "An unknown internal error occurred.");
         }
    }
    // Socket is closed by the wrapper function handle_connection_wrapper
}


// --- Thread Wrapper Function ---
// Manages thread lifecycle logging and socket closing
void handle_connection_wrapper(int client_socket, struct sockaddr_in client_addr) {
    current_active_threads++;
    std::string client_ip = inet_ntoa(client_addr.sin_addr); // Can call inet_ntoa again
    server_log("Connection accepted from: " + client_ip + " (Socket: " + std::to_string(client_socket) + ", Active Threads: " + std::to_string(current_active_threads.load()) + ")");

    try {
        handle_connection(client_socket, client_addr);
    } catch (const std::exception& e) {
         server_log("!!! UNHANDLED EXCEPTION in handle_connection thread for " + client_ip + ": " + e.what());
         // Socket might already be closed, error response unlikely here
    } catch (...) {
         server_log("!!! UNHANDLED UNKNOWN EXCEPTION in handle_connection thread for " + client_ip);
    }

    // Ensure socket is closed and thread count decremented
    server_log("Closing socket " + std::to_string(client_socket) + " for " + client_ip);
    close(client_socket);
    current_active_threads--;
    server_log("Connection finished for: " + client_ip + " (Active Threads: " + std::to_string(current_active_threads.load()) + ")");
}

// --- Main Server Loop ---
int main() {
    log_file_stream.open(LOG_FILE, std::ios::out | std::ios::app);
    if (!log_file_stream.is_open()) {
        std::cerr << "FATAL ERROR: Could not open log file '" << LOG_FILE << "' for writing." << std::endl;
        // Decide whether to continue logging only to stderr
    }

    server_log("--- Server Starting ---");

    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address); // Use socklen_t

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed"); server_log("FATAL: Socket creation failed: " + std::string(strerror(errno))); exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt failed"); server_log("WARN: setsockopt(SO_REUSEADDR) failed: " + std::string(strerror(errno)));
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed"); server_log("FATAL: Bind failed for port " + std::to_string(PORT) + ": " + std::string(strerror(errno))); close(server_fd); exit(EXIT_FAILURE);
    }

    if (listen(server_fd, SOMAXCONN) < 0) { // Use SOMAXCONN for backlog
        perror("Listen failed"); server_log("FATAL: Listen failed: " + std::string(strerror(errno))); close(server_fd); exit(EXIT_FAILURE);
    }

    server_log("Server listening on http://localhost:" + std::to_string(PORT) + "/");
    server_log("Serving files from directory: " + std::string(WWW_ROOT));
    server_log("CGI scripts expected in: " + std::string(WWW_ROOT) + CGI_BIN_PATH);
    server_log("Log file: " + std::string(LOG_FILE));

    while (true) {
        struct sockaddr_in client_addr; // Moved inside loop
        socklen_t client_addrlen = sizeof(client_addr); // Moved inside loop
        new_socket = accept(server_fd, (struct sockaddr*)&client_addr, &client_addrlen);

        if (new_socket < 0) {
            perror("Accept failed");
            server_log("WARN: Accept failed: " + std::string(strerror(errno)));
            // Consider adding a small sleep here if accept fails continuously
            continue;
        }

        // Use the wrapper function for the thread
        std::thread client_thread(handle_connection_wrapper, new_socket, client_addr);
        client_thread.detach();
    }

    server_log("--- Server Shutting Down ---"); // Normally unreachable
    if (log_file_stream.is_open()) log_file_stream.close();
    close(server_fd);
    return 0;
}

