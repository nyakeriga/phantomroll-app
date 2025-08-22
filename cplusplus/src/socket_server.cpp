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
        close(server_fd_);
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
    int addrlen = sizeof(address);

    if ((server_fd_ = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        if (logger_) {
            logger_->error("Socket creation failed");
        }
        return;
    }

    if (setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
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
        int new_socket = accept(server_fd_, (struct sockaddr *)&address, (socklen_t*)&addrlen);
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
        ssize_t valread = read(client_socket, buffer, sizeof(buffer) - 1);
        if (valread <= 0) {
            close(client_socket);
            return;
        }
        buffer[valread] = '\0';
        std::string command(buffer);
        // trim trailing newline/carriage returns
        while (!command.empty() && (command.back() == '\n' || command.back() == '\r')) command.pop_back();

        std::string response = process_command(command);
        response += "\n";
        send(client_socket, response.c_str(), response.size(), 0);

    } catch (...) {}
    close(client_socket);
}

std::string SocketServer::process_command(const std::string& cmd) {
    if (logger_) {
        logger_->info("Received command: " + cmd);
    }

    // Try to accept JSON objects (single-line) as well as plain text commands.
    // UI sends JSON like: {"command":"dice","emoji":"🎲","allowed":"3,5,7"}
    try {
        nlohmann::json j = nlohmann::json::parse(cmd);
        std::string command = j.value("command", std::string{});
        if (command.empty()) {
            return std::string("Invalid JSON: missing 'command' field");
        }

        if (command == "ping") {
            return std::string("pong");
        }

        if (command == "dice") {
            if (!g_handler) return std::string("Handler not available");

            // optional params from UI (currently not forwarded to handler)
            std::string emoji = j.value("emoji", std::string{});
            std::string allowed = j.value("allowed", std::string{});
            int total_rolls = j.value("total_rolls", 10);
            int per_dice_timeout_ms = j.value("per_dice_timeout_ms", 2000);
            int send_pacing_ms = j.value("send_pacing_ms", 1000);
            bool auto_delete = j.value("auto_delete_private", false);

            std::set<int> allowed_set;
            if (!allowed.empty()) {
                std::stringstream ss(allowed);
                std::string token;
                while (std::getline(ss, token, ',')) {
                    try {
                        allowed_set.insert(std::stoi(token));
                    } catch (...) {}
                }
            }
            g_handler->set_allowed_sums(allowed_set);

            // If MessageHandler supports parameterized call, forward values there.
            // Fallback to existing no-arg trigger.
            try {
                // example: g_handler->process_dice_roll_and_publish( ... );
                g_handler->process_dice_roll_and_publish();
                nlohmann::json resp;
                resp["ok"] = true;
                resp["event"] = "dice_triggered";
                resp["command"] = "dice";
                return resp.dump();
            } catch (const std::exception& e) {
                nlohmann::json resp;
                resp["ok"] = false;
                resp["error"] = std::string("handler_exception: ") + e.what();
                return resp.dump();
            } catch (...) {
                return std::string("Handler invocation failed");
            }
        }

        // handle other JSON commands minimally
        if (command == "login") {
            // UI may send {"command":"login","phone":"+123..."}
            std::string phone = j.value("phone", std::string{});
            if (g_handler) {
                try { g_handler->start_login(phone); } catch(...) {}
                nlohmann::json resp; resp["ok"] = true; resp["event"] = "login_started"; return resp.dump();
            }
            return std::string("Handler not available");
        }

        if (command == "logout") {
            if (g_handler) { try { g_handler->logout(); } catch(...) {} nlohmann::json r; r["ok"]=true; r["event"]="logout"; return r.dump(); }
            return std::string("Handler not available");
        }

        if (command == "add_group") {
            std::string group = j.value("group", std::string{});
            if (g_handler) { try { g_handler->add_group_by_name(group); } catch(...) {} nlohmann::json r; r["ok"]=true; return r.dump(); }
            return std::string("Handler not available");
        }

        return std::string("Unknown JSON command: ") + command;
    } catch (const nlohmann::json::parse_error&) {
        // Not JSON — fall back to legacy plain-text handling
        if (cmd == "ping") return "pong";
        if (cmd == "dice") {
            if (g_handler) {
                try { g_handler->process_dice_roll_and_publish(); } catch(...) { return "Handler invocation failed"; }
                return "Dice roll triggered";
            }
            return "Handler not available";
        }
        if (cmd.rfind("login:", 0) == 0) {
            std::string phone = cmd.substr(6);
            if (g_handler) { try { g_handler->start_login(phone); } catch(...) {} return "login started"; }
            return "Handler not available";
        }
        return "Unknown command: " + cmd;
    } catch (...) {
        return "Error processing command";
    }
}

