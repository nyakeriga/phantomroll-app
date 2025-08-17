#ifndef SOCKET_SERVER_HPP
#define SOCKET_SERVER_HPP

#include <thread>
#include <functional>
#include <memory>
#include <string>

class Logger;

class SocketServer {
public:
    SocketServer(int port, std::shared_ptr<Logger> logger);
    ~SocketServer();

    void start();
    void start(std::function<void(const std::string&)> handler);
    void stop();

private:
    void run_socket();
    void run_internal();
    void run_external(std::function<void(const std::string&)> handler);
    std::string handle_command(const std::string& cmdline);

    int port_;
    std::shared_ptr<Logger> logger_;
    bool running_;
    std::thread server_thread_;
};

#endif // SOCKET_SERVER_HPP

