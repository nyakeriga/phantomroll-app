#include "core/socket_server.hpp"
#include <iostream>
#include <cstring>
#include <thread>
#include <iomanip> // Required for std::hex and std::setw
#include <sstream>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #pragma comment(lib, "ws2_32.lib")
  #define close closesocket
#else
  #include <sys/socket.h>
  #include <unistd.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
#endif

SocketServer::SocketServer(int port)
    : port_(port), running_(false), server_fd_(-1) {}

SocketServer::~SocketServer() {
    stop();
}

void SocketServer::start(std::function<void(const std::string&)> handler) {
    command_handler_ = handler;
    running_ = true;
    server_thread_ = std::thread(&SocketServer::run, this);
}

void SocketServer::stop() {
    running_ = false;

    if (server_fd_ != -1) {
        close(server_fd_);
        server_fd_ = -1;
    }

    if (server_thread_.joinable()) {
        server_thread_.join();
    }

#ifdef _WIN32
    WSACleanup();
#endif
}

void SocketServer::run() {
#ifdef _WIN32
    WSADATA wsaData;
    int wsaInit = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaInit != 0) {
        std::cerr << "[SocketServer] WSAStartup failed: " << wsaInit << std::endl;
        return;
    }
#endif

    server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ == -1 || server_fd_ == INVALID_SOCKET) {
        std::cerr << "[SocketServer] Failed to create socket\n";
        return;
    }

    sockaddr_in address{};
    std::memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port_);

    if (bind(server_fd_, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "[SocketServer] Bind failed: " << strerror(errno) << std::endl;
        close(server_fd_);
        server_fd_ = -1;
        return;
    }

    if (listen(server_fd_, 3) < 0) {
        std::cerr << "[SocketServer] Listen failed: " << strerror(errno) << std::endl;
        close(server_fd_);
        server_fd_ = -1;
        return;
    }

    std::cout << "[SocketServer] Listening on port " << port_ << std::endl;

    while (running_) {
        socklen_t addrlen = sizeof(address);
        int client_socket = accept(server_fd_, (struct sockaddr*)&address, &addrlen);
        if (client_socket >= 0) {
            std::thread(&SocketServer::handle_client, this, client_socket).detach();
        }
    }
}

void SocketServer::handle_client(int client_socket) {
    char buffer[1024] = {0};
    ssize_t bytes_read =
#ifdef _WIN32
        recv(client_socket, buffer, sizeof(buffer), 0);
#else
        read(client_socket, buffer, sizeof(buffer));
#endif

    if (bytes_read > 0) {
        std::string command(buffer, bytes_read);

        // 🪛 Debug: Show raw bytes
        std::ostringstream hex_out;
        for (char c : command) {
            hex_out << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)c << " ";
        }
        std::cout << "[DEBUG] Received raw bytes: " << hex_out.str() << std::endl;

        std::cout << "[SocketServer] Command received: " << command << std::endl;

        if (command_handler_) {
            command_handler_(command);  // trigger callback
        }

        std::string response = "ack: " + command;
        send(client_socket, response.c_str(), response.size(), 0);
    }

    close(client_socket);
}
