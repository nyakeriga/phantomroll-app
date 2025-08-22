#ifndef CORE_TELEGRAM_SESSION_HPP
#define CORE_TELEGRAM_SESSION_HPP

// telegram_session.hpp
// Complete header for TelegramSession with control-server and auth helpers.
// Add or adjust includes below to match your project layout.

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <set>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <functional>
#include <cstdint>
#include <unordered_map>
#include <optional>
#include <array>
#include <thread>
#include <chrono>
#include <atomic>

// Include shared types used by the session (GroupInfo, DiceSetting, etc.)
#include "core/bot_types.hpp"

class Logger;

/**
 * TelegramSession
 *
 * High-level session wrapper that talks to TDLib (or your internal native client).
 * This header contains declarations that match the definitions implemented in
 * telegram_session.cpp (control server, auth flow, dice operations, etc).
 */
class TelegramSession {
public:
    enum class AuthStage { None, WaitPhoneNumber, WaitCode, WaitPassword, Ready, Closed };

    TelegramSession();
    ~TelegramSession();

    // Core TDLib communication helpers (thin wrappers)
    void send(const std::string& payload);
    std::string receive(double timeout_seconds = 1.0);

    // Initialization and configuration
    void initialize(const nlohmann::json& config);
    bool load_config(const std::string& path);
    void save_config();

    // Authentication API (async-friendly naming)
    bool authenticate();
    void forceLogin();
    void submit_phone_async(const std::string& phone);
    void submit_code_async(const std::string& code);
    void submit_2fa_async(const std::string& password);

    // Convenience / synchronous wrappers (if you need them)
    void submit_code(const std::string& code);
    void submit2FA(const std::string& password);
    void add_phone_number(const std::string& phone);

    // Callback for authentication stage change
    void set_auth_callback(std::function<void(AuthStage)> cb);
    AuthStage get_auth_stage() const;

    // Dice / game configuration
    void set_allowed_sums(const std::set<int>& allowed);
    const std::set<int>& get_allowed_sums() const;
    void set_dice_emoji(const std::string& emoji);
    void set_group_target(const std::string& group_name_or_id);
    void add_group_name(const std::string& group);

    // Dice operations
    void send_best3_dice_to_public();
    int sendDice(int64_t chat_id, int dice_value = 0);
    int waitForDiceValue(int64_t chat_id, int msg_id, int timeout_ms);
    std::vector<int64_t> sendDiceBatch(int64_t chat_id, int count, int pacing_ms, const std::string& emoji = "");
    std::vector<int> waitForDiceResults(int64_t chat_id, const std::vector<int64_t>& message_ids, int per_dice_timeout_ms);

    // Best-triple selection helpers
    std::optional<std::tuple<int,int,int>> pick_best_triple(const std::array<int,10>& dice_values) const;
    std::vector<int> pick_best_triple(const std::vector<int>& V) const;

    // Publish API for UI
    bool publish_best3_now(const std::set<int>& allowed_override,
                           const std::vector<int64_t>& target_group_ids,
                           const std::string& emoji,
                           int total_rolls,
                           int per_dice_timeout_ms,
                           int send_pacing_ms,
                           bool auto_delete_private);

    // Message management
    bool delete_private_messages(int64_t chat_id, const std::vector<int64_t>& message_ids);
    void delete_message(long chat_id, long message_id);
    nlohmann::json copy_messages_to_public(int64_t from_chat_id, int64_t to_chat_id, const std::vector<int64_t>& message_ids);

    // Update listener / event handling
    void start_update_listener();
    void stop_update_listener();
    void on_update(const nlohmann::json& update);
    void handle_update(const nlohmann::json& update);

    // Session lifecycle and utility
    void close();
    void switch_account(const std::string& new_phone);
    void set_session_suffix(const std::string& suffix);
    void reset_session_files();
    void remove_session();

    // State introspection
    bool is_authorized() const;
    int64_t get_own_user_id() const;
    bool is_paused() const;
    void pause_dice();
    void resume_dice();
    void parse_dice_command(const std::string& command);
    void set_language(const std::string& lang_code);

    int64_t get_private_group_id() const;
    std::vector<int64_t> get_last_private_msgs(int count);
    bool has_access_to_group(int64_t chat_id);
    int64_t resolve_group_name(const std::string& name);

    // Logging and audit (wrappers to a Logger instance)
    void log_info(const std::string& s);
    void log_warn(const std::string& s);
    void log_error(const std::string& s);
    void append_audit(const std::string& s);

    // Auth state queries
    bool is_waiting_for_code() const;
    bool is_waiting_for_password() const;

    // Control server lifecycle (local management socket for commands)
    void start_control_server();
    void stop_control_server();

    // Handle a single textual control command and return response
    std::string handle_control_command(const std::string& line);

private:
    // Internal helpers
    void sendTdlibParameters();
    void handle_auth_update(const nlohmann::json& st);
    void update_auth_stage(AuthStage s);

    // Internal read/write helpers (thread-safe wrappers around TDLib client)
    std::string receive_internal(double timeout_seconds);

    // Private members: core client and synchronization
    void* client_; // opaque pointer to TDLib client/context (implementation-defined)
    std::unique_ptr<Logger> logger_;

    bool authorized_ = false;
    bool listening_ = false;
    bool stop_update_listener_flag_ = false;
    AuthStage current_auth_stage_ = AuthStage::None;

    std::mutex client_mutex_;
    std::mutex auth_mutex_;
    std::condition_variable auth_cv_;

    nlohmann::json config_;
    std::string dice_emoji_;
    std::string target_group_;
    std::string phone_number_;
    std::string current_phone_;
    std::string api_hash_;
    std::string system_language_code_;
    std::string device_model_;
    std::string system_version_;
    std::string application_version_;
    std::string session_suffix_;
    int api_id_ = 0;

    int64_t private_group_id_ = 0;
    int64_t private_dice_group_id_ = 0;
    std::vector<int64_t> last_private_msgs_;
    std::unordered_map<int64_t, std::vector<int64_t>> group_message_cache_;

    std::vector<GroupInfo> public_groups_;

    std::set<int> allowed_sums_;
    std::set<int> valid_sums_;
    std::unordered_map<std::string, DiceSetting> dice_settings_;

    bool is_paused_ = false;
    std::function<void(AuthStage)> auth_callback_;
    std::thread update_listener_thread_;

    // control server state (non-static member-based)
    bool control_server_running_ = false;
    std::thread control_thread_;
    int control_server_fd_ = -1;   // socket file descriptor (platform dependent)

    // TDLib parameter placeholders
    std::string database_directory_;
    std::string files_directory_;
    bool use_message_database_ = false;
    bool use_file_database_ = false;
    bool use_secret_chats_ = false;
    bool use_test_dc_ = false;

    // Other housekeeping
    int64_t own_user_id_ = 0;

    // === NEW: duplicate protection flags ===
    std::atomic<bool> sending_dice_{false};
    std::atomic<bool> dice_handler_started_{false};
};

#endif // CORE_TELEGRAM_SESSION_HPP
