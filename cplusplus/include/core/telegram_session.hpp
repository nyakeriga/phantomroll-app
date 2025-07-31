#pragma once

#include <string>
#include <mutex>
#include <td/telegram/td_json_client.h>
#include "nlohmann/json.hpp"

class TelegramSession {
public:
    static TelegramSession& get_instance();

    void initialize(const nlohmann::json& config);
    void authenticate();
    void send(const std::string& request);
    std::string receive(double timeout = 1.0);
    void close();
    bool is_authorized() const;
    void set_session_suffix(const std::string& suffix);
    void reset_session_files();  // ✅ ADDED

    int64_t get_own_user_id();   // ✅ NEW: Needed for aggressive delete fallback

private:
    TelegramSession();
    ~TelegramSession();

    void *client_;
    std::mutex client_mutex_;
    nlohmann::json config_;
    bool authorized_;
    std::string session_suffix_;
};
