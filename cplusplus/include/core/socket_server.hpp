#ifndef PHANTOMROLL_SOCKET_SERVER_HPP
#define PHANTOMROLL_SOCKET_SERVER_HPP

#include <string>
#include <thread>
#include <functional>
#include <atomic>

class SocketServer {
public:
    explicit SocketServer(int port);
    ~SocketServer();

    void start(std::function<void(const std::string&)> handler);
    void stop();

private:
    void run();
    void handle_client(int client_socket);

private:
    int port_;
    int server_fd_;
    std::atomic<bool> running_;
    std::thread server_thread_;
    std::function<void(const std::string&)> command_handler_;
};

#endif // PHANTOMROLL_SOCKET_SERVER_HPP

