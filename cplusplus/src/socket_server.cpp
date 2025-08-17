#include "core/socket_server.hpp"
#include "core/message_handler.hpp"
#include "core/telegram_session.hpp"
#include "core/logger.hpp"
#include <iostream>
#include <thread>
#include <cstring>
#include <netinet/in.h>
#include <unistd.h>
#include <sstream>

SocketServer::SocketServer(int port, std::shared_ptr<Logger> logger)
    : port_(port), logger_(logger), running_(false), server_fd_(-1) {}

SocketServer::~SocketServer() {
    stop();
}

void SocketServer::start() {
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
    if (logger_) logger_->info("SocketServer stopped");
}

void SocketServer::run() {
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((server_fd_ = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        if (logger_) logger_->error("Socket creation failed");
        return;
    }

    if (setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        if (logger_) logger_->error("setsockopt failed");
        return;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port_);

    if (bind(server_fd_, (struct sockaddr *)&address, sizeof(address)) < 0) {
        if (logger_) logger_->error("Bind failed");
        return;
    }

    if (listen(server_fd_, 10) < 0) {
        if (logger_) logger_->error("Listen failed");
        return;
    }

    if (logger_) logger_->info("SocketServer (TCP) starting on port " + std::to_string(port_));

    while (running_) {
        int new_socket = accept(server_fd_, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (new_socket < 0) {
            if (running_ && logger_) logger_->error("Accept failed");
            continue;
        }
        std::thread(&SocketServer::handle_client, this, new_socket).detach();
    }
}

void SocketServer::handle_client(int client_socket) {
    try {
        char buffer[1024] = {0};
        ssize_t valread = read(client_socket, buffer, sizeof(buffer) - 1);
        if (valread <= 0) {
            close(client_socket);
            return;
        }
        buffer[valread] = '\0';
        std::string command(buffer);
        command.erase(command.find_last_not_of("\r\n") + 1); // trim newline

        std::string response = process_command(command);

        // Always send a response (even if empty)
        response += "\n";
        send(client_socket, response.c_str(), response.size(), 0);
    } catch (...) {
        // Never throw from thread
    }
    close(client_socket);
}

std::string SocketServer::process_command(const std::string& cmd) {
    // Example: You can expand this to call your backend logic
    if (logger_) logger_->info("Received command: " + cmd);

    // Example commands (expand as needed)
    if (cmd == "ping") {
        return "pong";
    } else if (cmd == "pause") {
        // Pause dice rolling (if implemented)
        TelegramSession::get_instance().pause_dice();
        return "Paused";
    } else if (cmd == "resume") {
        TelegramSession::get_instance().resume_dice();
        return "Resumed";
    } else if (cmd.rfind("login:", 0) == 0) {
        std::string phone = cmd.substr(6);
        TelegramSession::get_instance().submit_phone_async(phone);
        return "Login started for " + phone;
    } else if (cmd.rfind("submit_2fa:", 0) == 0) {
        std::string pwd = cmd.substr(11);
        TelegramSession::get_instance().submit_2fa_async(pwd);
        return "2FA submitted";
    } else if (cmd.rfind("dice", 0) == 0) {
        // Example: trigger dice roll
        MessageHandler* handler = MessageHandler::get_instance();
        if (handler) {
            handler->process_dice_roll_and_publish();
            return "Dice roll triggered";
        }
        return "Handler not available";
    } else if (cmd == "save_config") {
        TelegramSession::get_instance().save_config();
        return "Config saved";
    }
    // Unknown command
    return "Unknown command: " + cmd;
}
