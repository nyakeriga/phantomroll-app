// socket_server.cpp
#include "core/socket_server.hpp"
#include "core/message_handler.hpp"
#include "core/telegram_session.hpp"
#include "core/logger.hpp"
#include <iostream>
#include <thread>
#include <cstring>
#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <netinet/in.h>
#include <unistd.h>
#endif
#include <sstream>
#include <nlohmann/json.hpp>
// This is just a declaration; the definition is in main.cpp
extern MessageHandler* g_handler;
SocketServer::SocketServer(int port, std::shared_ptr<Logger> logger)
    : port_(port), logger_(logger), running_(false), server_fd_(-1) {}
SocketServer::~SocketServer() { stop(); }
void SocketServer::start() {
    running_ = true;
    server_thread_ = std::thread(&SocketServer::run, this);
}
void SocketServer::stop() {
    running_ = false;
    if (server_fd_ != -1) {
#ifdef _WIN32
    closesocket(server_fd_);
#else
    ::close(server_fd_);
#endif
    server_fd_ = -1;
    }
    if (server_thread_.joinable()) {
        server_thread_.join();
    }
    if (logger_) {
        logger_->info("SocketServer stopped");
    }
}
void SocketServer::run() {
    struct sockaddr_in address;
    int opt = 1;
    #ifdef _WIN32
    int addrlen = sizeof(address);
    #else
    socklen_t addrlen = static_cast<socklen_t>(sizeof(address));
    #endif

    if ((server_fd_ = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        if (logger_) {
            logger_->error("Socket creation failed");
        }
        return;
    }

#ifdef SO_REUSEPORT
    int reuse_flags = SO_REUSEADDR | SO_REUSEPORT;
#else
    int reuse_flags = SO_REUSEADDR;
#endif
    #ifdef _WIN32
    if (setsockopt(server_fd_, SOL_SOCKET, reuse_flags, (const char*)&opt, sizeof(opt))) {
    #else
    if (setsockopt(server_fd_, SOL_SOCKET, reuse_flags, &opt, sizeof(opt))) {
    #endif
        if (logger_) {
            logger_->error("setsockopt failed");
        }
        return;
    }

address.sin_family = AF_INET;
address.sin_addr.s_addr = INADDR_ANY;
address.sin_port = htons(port_);

if (bind(server_fd_, (struct sockaddr *)&address, sizeof(address)) < 0) {
    if (logger_) {
        logger_->error("Bind failed");
    }
    return;
}

if (listen(server_fd_, 10) < 0) {
    if (logger_) {
        logger_->error("Listen failed");
    }
    return;
}

if (logger_) {
    logger_->info("SocketServer (TCP) starting on port " + std::to_string(port_));
}

while (running_) {
    #ifdef _WIN32
    int new_socket = static_cast<int>(accept(server_fd_, (struct sockaddr *)&address, &addrlen));
    #else
    int new_socket = static_cast<int>(accept(server_fd_, (struct sockaddr *)&address, &addrlen));
    #endif
    if (new_socket < 0) {
        if (running_ && logger_) {
            logger_->error("Accept failed");
        }
        continue;
    }
    std::thread(&SocketServer::handle_client, this, new_socket).detach();
}
}
void SocketServer::handle_client(int client_socket) {
    try {
        char buffer[4096] = {0};
#ifdef _WIN32
        int valread = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
#else
        ssize_t valread = read(client_socket, buffer, sizeof(buffer) - 1);
#endif
        if (valread <= 0) {
#ifdef _WIN32
            closesocket(client_socket);
#else
            close(client_socket);
#endif
            return;
        }
        buffer[valread] = '\0';
        std::string command(buffer);
        // trim trailing newline/carriage returns
        while (!command.empty() && (command.back() == '\n' || command.back() == '\r')) command.pop_back();
        std::string response = process_command(command);
        response += "\n";
    send(client_socket, response.c_str(), static_cast<int>(response.size()), 0);

    } catch (const std::exception& e) {
        if (logger_) logger_->error("handle_client exception: " + std::string(e.what()));
    } catch (...) {
        if (logger_) logger_->error("handle_client unknown exception");
    }
#ifdef _WIN32
    closesocket(client_socket);
#else
    close(client_socket);
#endif
}
std::string SocketServer::process_command(const std::string& cmd) {
    try {
        // Forward all JSON commands to MessageHandler::sendCommand for unified handling
        if (g_handler) {
            g_handler->sendCommand(cmd);
            nlohmann::json resp;
            resp["ok"] = true;
            resp["event"] = "command_forwarded";
            return resp.dump();
        } else {
            return std::string("Handler not available");
        }
    } catch (const std::exception& e) {
        return std::string("Error processing command: ") + e.what();
    }
}
