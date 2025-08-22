#include "core/telegram_session.hpp"
#include <td/telegram/td_api.h>
#include <td/telegram/td_json_client.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <chrono>
#include <thread>
#include <cmath>
#include <climits>
#include <algorithm>
#include <cctype>
#include <exception>
#include <optional>
#include <tuple>
#include <array>
#include <nlohmann/json.hpp>
#include <vector>
#include <set>
#include <numeric>
#include <random>
#include <unordered_map>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <stdexcept>
#include <cstdio>
#include <atomic>

#include "core/logger.hpp"

using json = nlohmann::json;
using namespace std::literals::chrono_literals;

// alias for monotonic time
using Clock = std::chrono::steady_clock;

// ----------------- internal helpers & anonymous namespace -----------------
namespace {

std::string now_ts() {
    using namespace std::chrono;
    auto n = system_clock::now();
    auto t = system_clock::to_time_t(n);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    auto ms = duration_cast<milliseconds>(n.time_since_epoch()) % 1000;
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")
        << "." << std::setw(3) << std::setfill('0') << ms.count();
    return oss.str();
}

void sleep_ms(int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

std::string rand_token() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<uint64_t> d;
    std::ostringstream o; o << std::hex << d(rng);
    return o.str();
}

inline int roll_die(std::mt19937_64& rng) {
    static thread_local std::uniform_int_distribution<int> d(1,6);
    return d(rng);
}

inline double variance3(int a, int b, int c) {
    double m = (a + b + c) / 3.0;
    double v1 = a - m, v2 = b - m, v3 = c - m;
    return (v1*v1 + v2*v2 + v3*v3) / 3.0;
}

struct BestTriple { int i=-1,j=-1,k=-1; int sum=-1; double var=0.0; bool found=false; };

BestTriple best_triple_from_vector(const std::vector<int>& V, const std::set<int>& allowed) {
    BestTriple bt;
    if (V.size() < 3) return bt;
    const bool unconstrained = allowed.empty();
    int n = (int)V.size();
    for (int i=0;i<n;++i) for (int j=i+1;j<n;++j) for (int k=j+1;k<n;++k) {
        int s = V[i] + V[j] + V[k];
        if (!unconstrained && !allowed.count(s)) continue;
        double v = variance3(V[i], V[j], V[k]);
        if (!bt.found ||
            (s > bt.sum) ||
            (s == bt.sum && v < bt.var) ||
            (s == bt.sum && std::abs(v - bt.var) < 1e-12 && std::tie(i,j,k) < std::tie(bt.i, bt.j, bt.k))) {
            bt = {i,j,k,s,v,true};
        }
    }
    return bt;
}

bool json_has_extra(const json& j, const std::string& extra) {
    return j.contains("@extra") && j["@extra"].is_string() && j["@extra"].get<std::string>() == extra;
}

// file-local guard to protect send_best3_dice_to_public from re-entry without modifying header
static std::atomic<bool> sending_dice_flag{false};
struct LocalSendingGuard {
    std::atomic<bool>& flag;
    bool owned;
    LocalSendingGuard(std::atomic<bool>& f) : flag(f), owned(false) {
        bool expected = false;
        owned = flag.compare_exchange_strong(expected, true);
    }
    ~LocalSendingGuard() {
        if (owned) flag.store(false);
    }
    bool ok() const { return owned; }
};

} // namespace

// ----------------- dice result tracking globals -----------------
struct DiceKey {
    int64_t chat_id;
    int64_t msg_id;
    bool operator==(DiceKey const& o) const { return chat_id==o.chat_id && msg_id==o.msg_id; }
};
struct DiceKeyHash {
    std::size_t operator()(DiceKey const& k) const noexcept {
        return std::hash<int64_t>()(k.chat_id ^ (k.msg_id<<1));
    }
};
static std::unordered_map<DiceKey,int,DiceKeyHash> g_dice_values;
static std::mutex g_dice_mtx;
static std::condition_variable g_dice_cv;

// ----------------- @extra response mailbox -----------------
static std::mutex g_extra_mtx;
static std::condition_variable g_extra_cv;
static std::unordered_map<std::string, json> g_extra_responses;

// ----------------- helpers that call TelegramSession methods -----------------
static nlohmann::json request_with_extra_blocking(TelegramSession* self,
                                                  nlohmann::json req,
                                                  const std::string& extra,
                                                  double total_timeout_sec) {
    // attach extra and send
    req["@extra"] = extra;
    self->send(req.dump());

    // wait (listener will deliver the response into g_extra_responses)
    auto deadline = Clock::now() + std::chrono::milliseconds(static_cast<int>(total_timeout_sec * 1000.0));
    std::unique_lock<std::mutex> lk(g_extra_mtx);
    while (Clock::now() < deadline) {
        auto it = g_extra_responses.find(extra);
        if (it != g_extra_responses.end()) {
            json out = std::move(it->second);
            g_extra_responses.erase(it);
            return out;
        }
        g_extra_cv.wait_until(lk, deadline);
    }
    return json(); // timeout
}

// ----------------- TelegramSession implementation -----------------
TelegramSession::TelegramSession()
: client_(nullptr)
, logger_(std::make_unique<Logger>(Logger::Level::INFO))
, authorized_(false)
, listening_(false)
, stop_update_listener_flag_(false)
, current_auth_stage_(AuthStage::None)
, api_id_(0)
, private_group_id_(0)
, private_dice_group_id_(0)
, is_paused_(false)
{
}

TelegramSession::~TelegramSession() {
    // First, stop the update listener safely
    stop_update_listener();

    // Lock before accessing the client
    {
        std::lock_guard<std::mutex> lk(client_mutex_);
        if (client_) {
            // Destroy TDLib client safely
            td_json_client_destroy(client_);
            client_ = nullptr;
        }
    }
}

// ...existing includes and using statements...
void TelegramSession::initialize(const nlohmann::json& config_override) {
    if (!config_override.is_null() && !config_override.empty()) {
        config_ = config_override;
    } else {
        const std::string fallback_path = std::filesystem::absolute("resources/config/config.json").string();
        std::ifstream file(fallback_path);
        if (!file) {
            throw std::runtime_error(" Failed to open fallback config: " + fallback_path);
        }
        file >> config_;
        std::cout << "[DEBUG] Loaded fallback config from: " << fallback_path << std::endl;
    }

    if (!config_.contains("api_id") || !config_.contains("api_hash")) {
        throw std::runtime_error(" Missing required api_id or api_hash in config.");
    }

    client_ = td_json_client_create();

    nlohmann::json tdlib_params = {
        {"@type", "setTdlibParameters"},
        {"use_test_dc", config_.value("use_test_dc", false)},
        {"database_directory", "tdlib-data/" + session_suffix_},
        {"files_directory", config_.value("files_directory", "td_files")},
        {"use_file_database", config_.value("use_file_database", false)},
        {"use_chat_info_database", true},
        {"use_message_database", config_.value("use_message_database", false)},
        {"use_secret_chats", config_.value("use_secret_chats", false)},
        {"api_id", config_["api_id"].get<int>()},
        {"api_hash", config_["api_hash"].get<std::string>()},
        {"system_language_code", config_.value("system_language_code", "en")},
        {"device_model", config_.value("device_model", "PhantomRoll")},
        {"system_version", config_.value("system_version", "1.0")},
        {"application_version", config_.value("application_version", "1.0")},
        {"enable_storage_optimizer", config_.value("enable_storage_optimizer", true)}
    };

    send(tdlib_params.dump());

    std::cout << "[DEBUG] Using api_id = " << config_["api_id"]
              << ", api_hash = " << config_["api_hash"] << std::endl;
}

// --- Implementation for the linker ---
void TelegramSession::sendTdlibParameters() {
    if (!client_) {
        client_ = td_json_client_create();
    }

    nlohmann::json tdlib_params = {
        {"@type", "setTdlibParameters"},
        {"use_test_dc", config_.value("use_test_dc", false)},
        {"database_directory", "tdlib-data/" + session_suffix_},
        {"files_directory", config_.value("files_directory", "td_files")},
        {"use_file_database", config_.value("use_file_database", false)},
        {"use_chat_info_database", true},
        {"use_message_database", config_.value("use_message_database", false)},
        {"use_secret_chats", config_.value("use_secret_chats", false)},
        {"api_id", config_["api_id"].get<int>()},
        {"api_hash", config_["api_hash"].get<std::string>()},
        {"system_language_code", config_.value("system_language_code", "en")},
        {"device_model", config_.value("device_model", "PhantomRoll")},
        {"system_version", config_.value("system_version", "1.0")},
        {"application_version", config_.value("application_version", "1.0")},
        {"enable_storage_optimizer", config_.value("enable_storage_optimizer", true)}
    };

    try {
        send(tdlib_params.dump());
        if (logger_) logger_->info("sendTdlibParameters(): sent setTdlibParameters");
    } catch (const std::exception& ex) {
        if (logger_) logger_->error(std::string("sendTdlibParameters(): exception: ") + ex.what());
        else std::cerr << "sendTdlibParameters(): exception: " << ex.what() << std::endl;
    }

    // Optional: set TDLib log verbosity if configured
    int loglvl = config_.value("tdlib_log_level", 1);
    nlohmann::json log_msg = {
        {"@type", "setLogVerbosityLevel"},
        {"new_verbosity_level", loglvl}
    };
    try {
        send(log_msg.dump());
        if (logger_) logger_->info("sendTdlibParameters(): sent setLogVerbosityLevel=" + std::to_string(loglvl));
    } catch (const std::exception&) {
        // non-fatal: continue
    }
}

bool TelegramSession::authenticate() {
    bool use_external_auth = safe_get(config_, "external_auth", false);
    if (use_external_auth) {
        logger_->info("authenticate(): expecting external TDLib auth flow");
        start_update_listener(); // still listen so external flow can work
        return true;
    }

    logger_->info("authenticate(): starting automated TDLib auth");

    // 1) Ensure the update listener is running
    start_update_listener();

    // 2) Wait for TDLib to ask for parameters
    {
        std::unique_lock<std::mutex> lk(auth_mutex_);
        bool ok = auth_cv_.wait_for(lk, std::chrono::seconds(8), [this]() {
            return current_auth_stage_ == AuthStage::WaitPhoneNumber
                || current_auth_stage_ == AuthStage::WaitCode
                || current_auth_stage_ == AuthStage::WaitPassword
                || current_auth_stage_ == AuthStage::Ready
                || current_auth_stage_ == AuthStage::Closed
                || current_auth_stage_ == AuthStage::None;
        });
        if (!ok) {
            logger_->warn("authenticate(): no auth state observed within 8s; proceeding to send parameters anyway");
        }
    }

    // 3) Send TDLib parameters
    sendTdlibParameters();

    // 4) React to TDLib auth stages
    for (;;) {
        AuthStage stage;
        {
            std::unique_lock<std::mutex> lk(auth_mutex_);
            if (!auth_cv_.wait_for(lk, std::chrono::seconds(60), [this](){ return current_auth_stage_ != AuthStage::None; })) {
                logger_->warn("authenticate(): timeout waiting for auth update (60s)");
            }
            stage = current_auth_stage_;
        }

        if (stage == AuthStage::WaitPhoneNumber) {
            std::string phone = safe_get(config_, "phone_number", std::string{});
            if (phone.empty()) {
                std::cout << "Enter your phone number (e.g., +13522070047): ";
                std::getline(std::cin, phone);
                phone = trim(phone);
            }
            if (phone.empty()) phone = phone_number_;
            if (phone.empty()) {
                logger_->error("authenticate(): phone number empty, aborting");
                return false;
            }
            submit_phone_async(phone);
            continue;
        }

        if (stage == AuthStage::WaitCode) {
            std::string code = safe_get(config_, "login_code", std::string{});
            if (code.empty()) {
                std::cout << "Enter login code / 2FA (or 'exit'): ";
                std::getline(std::cin, code);
                code = trim(code);
                if (code == "exit") {
                    logger_->info("Authentication cancelled by user");
                    return false;
                }
            }
            submit_code_async(code);
            continue;
        }

        if (stage == AuthStage::WaitPassword) {
            std::string pwd;
            std::cout << "Enter 2FA password (or 'exit'): ";
            std::getline(std::cin, pwd);
            pwd = trim(pwd);
            if (pwd == "exit" || pwd.empty()) {
                logger_->info("Authentication cancelled by user (password)");
                return false;
            }
            submit_2fa_async(pwd);
            continue;
        }

        if (stage == AuthStage::Ready) {
            authorized_ = true;
            logger_->info("Authentication completed successfully (authorizationStateReady)");
            return true;
        }

        if (stage == AuthStage::Closed) {
            logger_->error("TDLib authorization closed unexpectedly");
            return false;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    return false; // not reached
}

void TelegramSession::forceLogin() {
    logger_->info("forceLogin() called");
}

void TelegramSession::submit_phone_async(const std::string& phone) {
    std::string clean_phone = trim(phone);
    if (clean_phone.empty()) {
        logger_->error("submit_phone_async: phone number is empty after trimming");
        return;
    }
    current_phone_ = clean_phone;
    json req = { {"@type","setAuthenticationPhoneNumber"}, {"phone_number", clean_phone} };
    request_with_extra_blocking(this, req, "auth_phone:" + rand_token(), 10.0);
}

void TelegramSession::submit_code_async(const std::string& code) {
    // Trim and validate the code
    std::string clean_code = trim(code);
    if (clean_code.empty()) {
        if (logger_) logger_->error("submit_code_async: Code is empty after trimming");
        else std::cerr << "[ERROR] submit_code_async: Code is empty after trimming" << std::endl;
        return;
    }

    // Build the request
    json req = {
        {"@type", "checkAuthenticationCode"},
        {"code", clean_code}
    };

    try {
        // Send the request to TDLib and use mailbox wait
        request_with_extra_blocking(this, req, "auth_code:" + rand_token(), 10.0);
        if (logger_) logger_->info("submit_code_async: Submitted login code asynchronously: " + clean_code);
        std::cout << "[AUTH] Submitted login code asynchronously: " << clean_code << std::endl;
    } catch (const std::exception& ex) {
        if (logger_) logger_->error(std::string("submit_code_async: Exception occurred: ") + ex.what());
        else std::cerr << "[ERROR] submit_code_async: Exception occurred: " << ex.what() << std::endl;
    }
}

void TelegramSession::submit_2fa_async(const std::string& password) {
    std::string clean_pwd = trim(password);
    if (clean_pwd.empty()) {
        if (logger_) logger_->error("submit_2fa_async: Password is empty after trimming");
        else std::cerr << "[ERROR] submit_2fa_async: Password is empty after trimming" << std::endl;
        return;
    }

    json req = {
        {"@type", "checkAuthenticationPassword"},
        {"password", clean_pwd}
    };

    try {
        request_with_extra_blocking(this, req, "auth_pwd:" + rand_token(), 10.0);
        if (logger_) logger_->info("submit_2fa_async: Submitted 2FA password asynchronously");
        std::cout << "[AUTH] Submitted 2FA password asynchronously: " << clean_pwd << std::endl;
    } catch (const std::exception& ex) {
        if (logger_) logger_->error(std::string("submit_2fa_async: Exception occurred: ") + ex.what());
        else std::cerr << "[ERROR] submit_2fa_async: Exception occurred: " << ex.what() << std::endl;
    }
}

// (these stray declarations were likely accidental in your file; keeping them no-op to preserve build)
void submit_2fa_async(const std::string& password);
void submit_code(const std::string& code);
void submit2FA(const std::string& password);
void add_phone_number(const std::string& phone);

void TelegramSession::set_auth_callback(std::function<void(AuthStage)> cb) {
    auth_callback_ = std::move(cb);
}
TelegramSession::AuthStage TelegramSession::get_auth_stage() const {
    return current_auth_stage_;
}

void TelegramSession::set_allowed_sums(const std::set<int>& allowed) {
    allowed_sums_ = allowed;
}
const std::set<int>& TelegramSession::get_allowed_sums() const {
    return allowed_sums_;
}
void TelegramSession::set_dice_emoji(const std::string& emoji) {
    dice_emoji_ = emoji;
}
void TelegramSession::set_group_target(const std::string& group_name_or_id) {
    target_group_ = group_name_or_id;
}
void TelegramSession::add_group_name(const std::string& group) {
    GroupInfo gi; gi.name = group; gi.id = 0; gi.interval_ms = 1000;
    public_groups_.push_back(gi);
}

void TelegramSession::send(const std::string& payload) {
    std::lock_guard<std::mutex> lk(client_mutex_);
    if (!client_) {
        Logger::log("send(): TDLib client not initialized", Logger::ERROR);
        return;
    }

    // Normalize dice emoji only if missing/empty → default to 🎲
    std::string out_payload = payload;
    try {
        json jp = json::parse(payload);
        if (jp.is_object() && jp.contains("@type") && jp["@type"].is_string() && jp["@type"] == "sendMessage") {
            if (jp.contains("input_message_content") && jp["input_message_content"].is_object()) {
                auto &imc = jp["input_message_content"];
                if (imc.contains("@type") && imc["@type"].is_string() && imc["@type"] == "inputMessageDice") {
                    if (!imc.contains("emoji") || !imc["emoji"].is_string() || imc["emoji"].get<std::string>().empty()) {
                        imc["emoji"] = u8"🎲";
                    }
                }
            }
        }
        out_payload = jp.dump();
    } catch (...) {
        // fallback: use original payload
    }

    try {
        td_json_client_send(client_, out_payload.c_str());
        Logger::log("TDLib send: " + (out_payload.size() > 200 ? out_payload.substr(0,200) + "..." : out_payload), Logger::INFO);
    } catch (const std::exception& e) {
        Logger::log(std::string("send exception: ") + e.what(), Logger::ERROR);
    }
}

std::string TelegramSession::receive(double timeout_seconds) {
    std::lock_guard<std::mutex> lk(client_mutex_);
    if (!client_) {
        Logger::log("receive(): TDLib client not initialized", Logger::ERROR);
        return {};
    }
    const char* resp = td_json_client_receive(client_, timeout_seconds);
    if (!resp) return {};
    return std::string(resp);
}

void TelegramSession::handle_update(const json& update) {
    if (!update.is_object() || !update.contains("@type")) return;
    std::string t = update["@type"].get<std::string>();

    if (t == "updateAuthorizationState") {
        handle_auth_update(update.value("authorization_state", json{}));
        return;
    }

    if (t == "updateNewMessage" && update.contains("message")) {
        const auto& m = update["message"];
        if (m.contains("chat_id") && m.contains("id") && m.contains("content")) {
            int64_t chat_id = m["chat_id"].get<int64_t>();
            int64_t msg_id  = m["id"].get<int64_t>();
            const auto& content = m["content"];
            if (content.contains("@type") && content["@type"] == "messageDice" && content.contains("value")) {
                int value = content["value"].get<int>();
                {
                    std::lock_guard<std::mutex> lk(g_dice_mtx);
                    g_dice_values[{chat_id,msg_id}] = value;
                }
                g_dice_cv.notify_all();
                append_audit("Received dice result chat=" + std::to_string(chat_id) + " msg=" + std::to_string(msg_id) + " value=" + std::to_string(value));
            }
        }
        return;
    }

    if (t == "updateMessageContent") {
        if (update.contains("chat_id") && update.contains("message_id")) {
            int64_t chat_id = update["chat_id"].get<int64_t>();
            int64_t msg_id  = update["message_id"].get<int64_t>();
            const auto& content = update["new_content"];
            if (content.contains("@type") && content["@type"] == "messageDice" && content.contains("value")) {
                int value = content["value"].get<int>();
                {
                    std::lock_guard<std::mutex> lk(g_dice_mtx);
                    g_dice_values[{chat_id,msg_id}] = value;
                }
                g_dice_cv.notify_all();
                append_audit("Received edited dice content chat=" + std::to_string(chat_id) + " msg=" + std::to_string(msg_id) + " value=" + std::to_string(value));
            }
        }
        return;
    }

    (void) t;
}

void TelegramSession::handle_auth_update(const json& st) {
    if (!st.is_object() || !st.contains("@type")) return;
    std::string tp = st["@type"].get<std::string>();
    if (tp == "authorizationStateReady") {
        authorized_ = true;
        update_auth_stage(AuthStage::Ready);
        logger_->info("Authorization ready");
    } else if (tp == "authorizationStateClosed") {
        authorized_ = false;
        update_auth_stage(AuthStage::Closed);
        logger_->warn("Authorization closed");
    } else if (tp == "authorizationStateWaitPhoneNumber") update_auth_stage(AuthStage::WaitPhoneNumber);
    else if (tp == "authorizationStateWaitCode") update_auth_stage(AuthStage::WaitCode);
    else if (tp == "authorizationStateWaitPassword") update_auth_stage(AuthStage::WaitPassword);
}

void TelegramSession::update_auth_stage(AuthStage s) {
    {
        std::lock_guard<std::mutex> lk(auth_mutex_);
        current_auth_stage_ = s;
    }
    auth_cv_.notify_all();
    if (auth_callback_) auth_callback_(s);
}

void TelegramSession::start_update_listener() {
    if (listening_) return;
    stop_update_listener_flag_ = false;
    listening_ = true;
    update_listener_thread_ = std::thread([this]() {
        logger_->info("update listener started");
        while (!stop_update_listener_flag_) {
            try {
                std::string s = receive(1.0);
                if (s.empty()) continue;
                try {
                    json j = json::parse(s);

                    // Deliver function results carrying @extra to the mailbox.
                    if (j.contains("@extra") && j["@extra"].is_string()) {
                        std::string extra = j["@extra"].get<std::string>();
                        {
                            std::lock_guard<std::mutex> lk(g_extra_mtx);
                            g_extra_responses[extra] = j;
                        }
                        g_extra_cv.notify_all();
                        continue; // don't pass to handle_update
                    }

                    // Only pass TDLib updates to update handler
                    handle_update(j);
                } catch(...) {
                    // swallow parse/dispatch errors
                }
            } catch(...) {
                // swallow receive errors
            }
        }
        logger_->info("update listener stopped");
    });
}

void TelegramSession::stop_update_listener() {
    if (!listening_) return;
    stop_update_listener_flag_ = true; // signal the listener to stop

    if (update_listener_thread_.joinable()) {
        update_listener_thread_.join();
    }

    {
        std::lock_guard<std::mutex> lk(client_mutex_);
        // Optional: ensure client isn't used after stopping
    }

    listening_ = false;
}

int TelegramSession::sendDice(int64_t chat_id, int /*dice_value*/) {
    std::lock_guard<std::mutex> lk(client_mutex_);
    if (!client_) {
        logger_->error("sendDice(): TDLib client not initialized");
        append_audit("sendDice failed: client not initialized");
        return 0;
    }

    // Build request
    json req = {
        {"@type", "sendMessage"},
        {"chat_id", chat_id},
        {"input_message_content", {
            {"@type", "inputMessageDice"},
            {"emoji", dice_emoji_}
        }}
    };

    try {
        std::string extra = "senddice:" + std::to_string(chat_id) + ":" + rand_token();
        json resp = request_with_extra_blocking(this, req, extra, 10.0);

        if (!resp.is_object()) {
            logger_->error("sendDice: timeout");
            append_audit("sendDice timeout chat=" + std::to_string(chat_id));
            return 0;
        }

        if (resp.contains("@type") && resp["@type"] == "error") {
            logger_->error("sendDice error: " + resp.dump());
            append_audit("sendDice error: " + resp.dump());
            return 0;
        }

        if (resp.contains("@type") && resp["@type"] == "message" && resp.contains("id")) {
            int64_t mid = resp["id"].get<int64_t>();
            append_audit("Sent dice chat=" + std::to_string(chat_id) + " msg=" + std::to_string(mid));
            return static_cast<int>(mid);
        }

        logger_->warn("sendDice: unknown response: " + resp.dump());
        append_audit("sendDice unknown response chat=" + std::to_string(chat_id));
        return 0;

    } catch (const std::exception& e) {
        logger_->error(std::string("sendDice exception: ") + e.what());
        append_audit(std::string("sendDice exception: ") + e.what());
        return 0;
    }
}

int TelegramSession::waitForDiceValue(int64_t chat_id, int msg_id, int timeout_ms) {
    std::unique_lock<std::mutex> lk(g_dice_mtx);
    DiceKey key{chat_id, static_cast<int64_t>(msg_id)};
    auto pred = [&]() { return g_dice_values.find(key) != g_dice_values.end(); };

    if (!g_dice_cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), pred)) {
        return -1; // timeout
    }

    return g_dice_values[key];
}

std::vector<int64_t> TelegramSession::sendDiceBatch(int64_t chat_id, int count, int pacing_ms, const std::string& emoji) {
    if (logger_) logger_->info("[TRACE] sendDiceBatch called on thread " +
              std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id())));
    std::string saved = dice_emoji_;
    if (!emoji.empty()) dice_emoji_ = emoji;
    std::vector<int64_t> ids; ids.reserve(count);
    for (int i=0;i<count;++i) {
        int id = sendDice(chat_id);
        ids.push_back((int64_t)id);
        if (pacing_ms > 0) sleep_ms(pacing_ms);
    }
    if (!emoji.empty()) dice_emoji_ = saved;
    return ids;
}

std::vector<int> TelegramSession::waitForDiceResults(int64_t chat_id, const std::vector<int64_t>& message_ids, int per_dice_timeout_ms) {
    std::vector<int> vals; vals.reserve(message_ids.size());
    for (auto m : message_ids) vals.push_back(waitForDiceValue(chat_id, (int)m, per_dice_timeout_ms));
    return vals;
}

std::optional<std::tuple<int,int,int>> TelegramSession::pick_best_triple(const std::array<int,10>& dice_values) const {
    std::vector<int> vec(dice_values.begin(), dice_values.end());
    const auto& allowed = valid_sums_.empty() ? allowed_sums_ : valid_sums_;
    BestTriple bt = best_triple_from_vector(vec, allowed);
    if (!bt.found) return std::nullopt;
    return std::make_tuple(bt.i, bt.j, bt.k);
}

// Implementation for the vector overload declared in the header
std::vector<int> TelegramSession::pick_best_triple(const std::vector<int>& V) const {
    const auto& allowed = valid_sums_.empty() ? allowed_sums_ : valid_sums_;
    BestTriple bt = best_triple_from_vector(V, allowed);
    if (!bt.found) return {};
    return {bt.i, bt.j, bt.k};
}

void TelegramSession::on_update(const json& update) {
    try {
        if (!update.contains("@type")) return;
        const std::string& type = update["@type"].get<std::string>();

        if (type == "updateNewMessage") {
            const auto& msg = update.value("message", json{});
            std::cout << "[UPDATE] New message from chat "
                      << msg.value("chat_id", 0)
                      << ": " << msg.dump() << std::endl;

            {
                std::lock_guard<std::mutex> lock(client_mutex_);
                last_private_msgs_.push_back(msg.value("id", 0));
                if (last_private_msgs_.size() > 100) last_private_msgs_.erase(last_private_msgs_.begin());
            }

        } else if (type == "updateMessageSendSucceeded") {
        } else if (type == "updateMessageSendFailed") {
            std::cerr << "[WARN] Message send failed: " << update.dump() << std::endl;
        } else if (type == "updateDeleteMessages") {
            const auto& ids = update.value("message_ids", json::array());
            std::cout << "[UPDATE] Messages deleted: ";
            for (auto& id : ids) std::cout << id << " ";
            std::cout << std::endl;

            {
                std::lock_guard<std::mutex> lock(client_mutex_);
                for (auto& id : ids) {
                    auto it = std::find(last_private_msgs_.begin(), last_private_msgs_.end(), id.get<int64_t>());
                    if (it != last_private_msgs_.end()) last_private_msgs_.erase(it);
                }
            }
        } else {
            std::cout << "[UPDATE] " << type << ": " << update.dump() << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Exception in on_update: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "[ERROR] Unknown exception in on_update" << std::endl;
    }
}

// --- MODIFIED LOGIC: send dice directly to public group, not as copy/forward ---
void TelegramSession::send_best3_dice_to_public() {
    LocalSendingGuard guard(sending_dice_flag);
    if (!guard.ok()) {
        if (logger_) logger_->warn("send_best3_dice_to_public: already running, skipping duplicate");
        return;
    }
    if (logger_) logger_->info("[TRACE] send_best3_dice_to_public entered");

    try {
        if (is_paused_) { logger_->warn("send_best3_dice_to_public: paused"); return; }
        if (!authorized_) { logger_->warn("send_best3_dice_to_public: not authorized"); return; }
        if (private_dice_group_id_ == 0) { logger_->error("private group not configured"); return; }
        if (public_groups_.empty()) { logger_->error("no public groups configured"); return; }

        const int MAX_ATTEMPTS = config_.value("max_attempts", 3);
        const int TOTAL = config_.value("dice_count", 10);
        const int PER_DICE_TIMEOUT_MS = config_.value("dice_result_timeout_ms", 2000);
        const int SEND_PACING_MS = std::max(1, dice_settings_[dice_emoji_].interval_ms);
        bool auto_delete = config_.value("auto_delete_private_rolls", false);

        for (int attempt=1; attempt<=MAX_ATTEMPTS; ++attempt) {
            logger_->info("Attempt " + std::to_string(attempt) + " rolling " + std::to_string(TOTAL) + " dice privately");
            append_audit("Attempt " + std::to_string(attempt) + " rolling private dice");

            auto msg_ids = sendDiceBatch(private_dice_group_id_, TOTAL, SEND_PACING_MS);
            append_audit("Sent private dice count=" + std::to_string(msg_ids.size()));

            auto vals = waitForDiceResults(private_dice_group_id_, msg_ids, PER_DICE_TIMEOUT_MS);
            if ((int)vals.size() != TOTAL) { logger_->warn("unexpected results count"); append_audit("unexpected results count"); continue; }
            bool any_bad=false; for (int v: vals) if (v<1 || v>6) { any_bad=true; break; }
            if (any_bad) { logger_->warn("some dice invalid"); append_audit("some dice invalid"); continue; }

            std::array<int,10> arr{};
            for (int i=0;i<TOTAL && i<10;++i) arr[i]=vals[i];

            auto triple = pick_best_triple(arr);
            if (!triple.has_value()) { logger_->info("no valid triple found"); append_audit("no valid triple"); continue; }

            auto [i,j,k] = triple.value();
            int v1 = arr[i], v2 = arr[j], v3 = arr[k];
            int sum = v1 + v2 + v3;
            append_audit("Picked triple indices (" + std::to_string(i) + "," + std::to_string(j) + "," + std::to_string(k) + ") values (" + std::to_string(v1)+","+std::to_string(v2)+","+std::to_string(v3)+") sum=" + std::to_string(sum));
            logger_->info("Picked triple sum=" + std::to_string(sum));

            // Send new dice messages to each public group, so they look native (not forwarded)
            for (const auto& g : public_groups_) {
                if (g.id == 0) continue;

                // Send three dice messages
                for (int n = 0; n < 3; ++n) {
                    json req = {
                        {"@type","sendMessage"},
                        {"chat_id", g.id},
                        {"input_message_content", { {"@type","inputMessageDice"}, {"emoji", dice_emoji_} }}
                    };
                    send(req.dump());
                    sleep_ms(SEND_PACING_MS);
                }

                // Send a summary message with the actual best triple values
                std::ostringstream disc;
                disc << "Best triple from developer roll: " << v1 << ", " << v2 << ", " << v3 << " (sum = " << sum << ")";
                json req = {
                    {"@type","sendMessage"},
                    {"chat_id", g.id},
                    {"input_message_content", {
                        {"@type","inputMessageText"},
                        {"text", { {"@type","formattedText"}, {"text", disc.str()} }}
                    }}
                };
                send(req.dump());
            }

            if (auto_delete) {
                bool ok = delete_private_messages(private_dice_group_id_, msg_ids);
                if (ok) append_audit("Auto-deleted private rolls");
                else append_audit("Auto-delete failed");
            }

            logger_->info("Completed send_best3_dice_to_public successfully");
            return;
        }

        logger_->warn("All attempts exhausted; failed to publish best triple");
        append_audit("Failed to publish best triple after attempts");
    } catch (const std::exception& ex) {
        logger_->error(std::string("send_best3_dice_to_public exception: ") + ex.what());
    }

    if (logger_) logger_->info("[TRACE] send_best3_dice_to_public exited");
}

bool TelegramSession::delete_private_messages(int64_t chat_id, const std::vector<int64_t>& message_ids) {
    if (message_ids.empty()) return true;
    json req = { {"@type","deleteMessages"}, {"chat_id", chat_id}, {"message_ids", message_ids}, {"revoke", true} };
    std::string extra = "del:" + std::to_string(chat_id) + ":" + rand_token();
    json resp = request_with_extra_blocking(this, req, extra, 10.0);
    if (!resp.is_object() || (resp.contains("@type") && resp["@type"]=="error")) {
        logger_->warn("deleteMessages failed: " + resp.dump());
        append_audit("deleteMessages failed: " + resp.dump());
        return false;
    }
    append_audit("Deleted private messages chat=" + std::to_string(chat_id) + " count=" + std::to_string(message_ids.size()));
    return true;
}

void TelegramSession::delete_message(long chat_id, long message_id) {
    json req;
    req["@type"] = "deleteMessages";
    req["chat_id"] = chat_id;
    req["message_ids"] = { message_id };
    req["revoke"] = true;
    send(req.dump());
}

json TelegramSession::copy_messages_to_public(int64_t from_chat_id, int64_t to_chat_id, const std::vector<int64_t>& message_ids) {
    if (message_ids.empty()) return json();
    json req = {
        {"@type","copyMessages"},
        {"chat_id", to_chat_id},
        {"from_chat_id", from_chat_id},
        {"message_ids", message_ids},
        {"options", { {"@type","messageSendOptions"} }},
        {"send_copy", true},
        {"remove_caption", false}
    };
    std::string extra = "copy:" + std::to_string(from_chat_id) + ":" + rand_token();
    json resp = request_with_extra_blocking(this, req, extra, 10.0);
    if (!resp.is_object() || (resp.contains("@type") && resp["@type"]=="error")) {
        logger_->warn("copyMessages failed: " + resp.dump());
        append_audit("copyMessages failed: " + resp.dump());
        return json();
    }
    append_audit("Copied " + std::to_string(message_ids.size()) + " messages from " + std::to_string(from_chat_id) + " to " + std::to_string(to_chat_id));
    return resp;
}

void TelegramSession::close() { stop_update_listener(); }
void TelegramSession::switch_account(const std::string& new_phone) { (void)new_phone; }
void TelegramSession::set_session_suffix(const std::string& suffix) { session_suffix_ = suffix; }
void TelegramSession::reset_session_files() { }
void TelegramSession::remove_session() { }
void TelegramSession::save_config() { }

bool TelegramSession::is_authorized() const { return authorized_; }
int64_t TelegramSession::get_own_user_id() { return 0; }
bool TelegramSession::is_paused() const { return is_paused_; }
void TelegramSession::pause_dice() { is_paused_ = true; }
void TelegramSession::resume_dice() { is_paused_ = false; }
void TelegramSession::parse_dice_command(const std::string& command) { (void)command; }
void TelegramSession::set_language(const std::string& lang_code) { system_language_code_ = lang_code; }

int64_t TelegramSession::get_private_group_id() const { return private_dice_group_id_; }

std::vector<int64_t> TelegramSession::get_last_private_msgs(int count) {
    auto it = group_message_cache_.find(private_dice_group_id_);
    if (it == group_message_cache_.end()) return {};
    std::vector<int64_t> out;
    auto &v = it->second;
    for (int i = std::max(0, (int)v.size() - count); i < (int)v.size(); ++i) out.push_back(v[i]);
    return out;
}

bool TelegramSession::has_access_to_group(int64_t chat_id) {
    for (auto &g : public_groups_) if (g.id == chat_id) return true;
    if (chat_id == private_dice_group_id_) return true;
    return false;
}

int64_t TelegramSession::resolve_group_name(const std::string& name) {
    try { return std::stoll(name); } catch(...) {}
    for (auto &g : public_groups_) if (g.name == name) return g.id;
    return 0;
}

void TelegramSession::log_info(const std::string& s) { if (logger_) logger_->info(s); }
void TelegramSession::log_warn(const std::string& s) { if (logger_) logger_->warn(s); }
void TelegramSession::log_error(const std::string& s) { if (logger_) logger_->error(s); }

bool TelegramSession::is_waiting_for_code() const { return current_auth_stage_ == AuthStage::WaitCode; }
bool TelegramSession::is_waiting_for_password() const { return current_auth_stage_ == AuthStage::WaitPassword; }

void TelegramSession::append_audit(const std::string& s) {
    static std::ofstream f("dice_rolls.log", std::ios::app);
    if (!f) return;
    f << "[" << now_ts() << "] " << s << std::endl;
    f.flush();
}
