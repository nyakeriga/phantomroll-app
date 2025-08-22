#ifndef SOCKET_SERVER_HPP
#define SOCKET_SERVER_HPP

#include <thread>
#include <functional>
#include <memory>
#include <string>
#include <atomic>

class Logger;

class SocketServer {
public:
    explicit SocketServer(int port, std::shared_ptr<Logger> logger);
    ~SocketServer();

    // non-copyable
    SocketServer(const SocketServer&) = delete;
    SocketServer& operator=(const SocketServer&) = delete;

    // Start server with default handler
    void start();
    // Start server with custom handler
    void start(std::function<void(const std::string&)> handler);

    void stop();

private:
    void run(); // Main server loop
    void handle_client(int client_socket); // Handle a client connection
    std::string process_command(const std::string& cmd); // Process a command

    int port_{};
    std::shared_ptr<Logger> logger_;
    std::atomic<bool> running_{false};
    int server_fd_{-1}; // Server socket file descriptor
    std::thread server_thread_;

    // Missing declaration added: store optional external handler provided via start(handler)
    std::function<void(const std::string&)> external_handler_;
};

#endif // SOCKET_SERVER_HPP

