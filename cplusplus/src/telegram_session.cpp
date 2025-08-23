// telegram_session.cpp
// ----------------------------------------------------------------------------
// PhantomRoll – Telegram Session implementation
// ----------------------------------------------------------------------------

#include "core/telegram_session.hpp"
#include "core/message_handler.hpp"
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
#include <map>
#include <regex> // IMPROVEMENT: Added for regex functionality

#include "core/logger.hpp"
using json = nlohmann::json;

using namespace std::literals::chrono_literals;

// alias for monotonic time
using Clock = std::chrono::steady_clock;

#ifdef __unix__
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#endif

// forward-declare MessageHandler so extern can compile without including header
class MessageHandler;
extern MessageHandler* g_handler;

// static control-server globals (keeps header changes optional)
static std::atomic<bool> s_control_server_running{false};
static std::thread s_control_thread;
static int s_control_server_fd = -1;

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

    std::size_t hash_allowed(const std::set<int>& S) {
        std::size_t h = 1469598103934665603ull;
        for (int x : S) { h ^= static_cast<std::size_t>(x); h *= 1099511628211ull; }
        return h;
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

    int simulate_best_sum_once(int N, const std::set<int>& allowed, std::mt19937_64& rng) {
        std::vector<int> V; V.reserve(N);
        for (int t=0;t<N;++t) V.push_back(roll_die(rng));
        auto bt = best_triple_from_vector(V, allowed);
        return bt.found ? bt.sum : -1;
    }

    bool json_has_extra(const json& j, const std::string& extra) {
        return j.contains("@extra") && j["@extra"].is_string() && j["@extra"].get<std::string>() == extra;
    }
}

// ----------------- dice result tracking globals -----------------
struct DiceKey { int64_t chat_id; int64_t msg_id; bool operator==(DiceKey const& o) const { return chat_id==o.chat_id && msg_id==o.msg_id; } };
struct DiceKeyHash { std::size_t operator()(DiceKey const& k) const noexcept { return std::hash<int64_t>()(k.chat_id ^ (k.msg_id<<1)); } };
static std::unordered_map<DiceKey,int,DiceKeyHash> g_dice_values;
static std::mutex g_dice_mtx;
static std::condition_variable g_dice_cv;

// ----------------- helpers that call TelegramSession methods -----------------
static nlohmann::json request_with_extra_blocking(TelegramSession* self, nlohmann::json req, const std::string& extra, double total_timeout_sec) {
    using Clock = std::chrono::steady_clock;

    req["@extra"] = extra;
    self->send(req.dump());

    auto deadline = Clock::now() + std::chrono::milliseconds(static_cast<int>(total_timeout_sec * 1000.0));
    while (Clock::now() < deadline) {
        std::string resp = self->receive(0.5);
        if (resp.empty()) continue;
        try {
            nlohmann::json jr = nlohmann::json::parse(resp);
            if (json_has_extra(jr, extra)) return jr;
            self->on_update(jr);
        } catch (const std::exception& e) {
            Logger::errorGlobal("request_with_extra_blocking: JSON parse error: " + std::string(e.what()));
        }
    }
    return nlohmann::json();
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
    stop_update_listener();
    stop_control_server();
    std::lock_guard<std::mutex> lk(client_mutex_);
    if (client_) {
        try { td_json_client_destroy(client_); } catch(...) {}
        client_ = nullptr;
    }
}

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

    // Validate config
    if (!config_.contains("api_id") || !config_["api_id"].is_number_integer()) {
        throw std::runtime_error("Missing or invalid 'api_id' in config.");
    }
    if (!config_.contains("api_hash") || !config_["api_hash"].is_string()) {
        throw std::runtime_error("Missing or invalid 'api_hash' in config.");
    }
    if (config_.contains("groups") && !config_["groups"].is_array()) {
        throw std::runtime_error("Invalid 'groups' field in config; must be an array.");
    }
    if (config_.contains("dice_settings") && !config_["dice_settings"].is_object()) {
        throw std::runtime_error("Invalid 'dice_settings' field in config; must be an object.");
    }

    private_dice_group_id_ = config_.value("private_dice_group_id", private_dice_group_id_);
    if (config_.contains("groups") && config_["groups"].is_array()) {
        public_groups_.clear();
        for (const auto &g : config_["groups"]) {
            GroupInfo gi;
            gi.id = g.value("id", 0LL);
            gi.name = g.value("name", std::string());
            gi.interval_ms = g.value("interval_ms", 1000);
            if (gi.id != 0 || !gi.name.empty()) public_groups_.push_back(gi);
        }
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
    bool use_external_auth = false;

    if (config_.contains("external_auth") && config_["external_auth"].is_boolean()) {
        use_external_auth = config_["external_auth"].get<bool>();
    }

    if (use_external_auth) {
        logger_->info("authenticate(): expecting external TDLib auth flow");
        return true;
    }

    logger_->info("authenticate(): starting automated TDLib auth");

    sendTdlibParameters();

    std::string phone = config_.value("phone_number", "");
    std::string code = config_.value("login_code", "");

    if (phone.empty()) {
        std::cout << "Enter your phone number (e.g., +13522070047): ";
        std::getline(std::cin, phone);
    }
    if (phone.empty()) phone = phone_number_;
    submit_phone_async(phone);

    if (code.empty()) {
        std::cout << "Enter login code / 2FA (or 'exit'): ";
        std::getline(std::cin, code);
        if (code == "exit") {
            logger_->info("Authentication cancelled");
            return false;
        }
    }
    submit_code_async(code);

    return true;
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
    std::string clean_code = trim(code);
    if (clean_code.empty()) {
        logger_->error("submit_code_async: code is empty after trimming");
        return;
    }
    json req = { {"@type","checkAuthenticationCode"}, {"code", clean_code} };
    request_with_extra_blocking(this, req, "auth_code:" + rand_token(), 10.0);
}

void TelegramSession::submit_2fa_async(const std::string& password) {
    std::string clean_pwd = trim(password);
    if (clean_pwd.empty()) {
        logger_->error("submit_2fa_async: password is empty after trimming");
        return;
    }
    json req = { {"@type","checkAuthenticationPassword"}, {"password", clean_pwd} };
    request_with_extra_blocking(this, req, "auth_pwd:" + rand_token(), 10.0);
}

void TelegramSession::submit_code(const std::string& code) { submit_code_async(code); }
void TelegramSession::submit2FA(const std::string& password) { submit_2fa_async(password); }
void TelegramSession::add_phone_number(const std::string& phone) { submit_phone_async(phone); }

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
        Logger::errorGlobal("send(): TDLib client not initialized");
        return;
    }

    try {
        auto jp = json::parse(payload);
        if (jp.is_object() && jp.contains("@type") && jp["@type"].is_string() && jp["@type"] == "sendMessage") {
            if (jp.contains("input_message_content") && jp["input_message_content"].is_object()) {
                const auto &imc = jp["input_message_content"];
                if (imc.contains("@type") && imc["@type"].is_string() && imc["@type"] == "inputMessageDice") {
                    bool enabled = config_.value("enable_auto_publish", false);
                    if (!enabled) {
                        std::string reason = "Blocked inputMessageDice send (enable_auto_publish=false)";
                        if (logger_) logger_->warn(reason);
                        append_audit(reason + " payload=" + jp.dump());
                        return;
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        Logger::errorGlobal("send(): JSON parse error: " + std::string(e.what()));
    }

    try {
        td_json_client_send(client_, payload.c_str());
        if (logger_) logger_->info("TDLib send: " + (payload.size() > 200 ? payload.substr(0,200) + "..." : payload));
    } catch (const std::exception& e) {
        if (logger_) logger_->error(std::string("send exception: ") + e.what());
    }
}

std::string TelegramSession::receive(double timeout_seconds) {
    std::lock_guard<std::mutex> lk(client_mutex_);
    if (!client_) {
        Logger::errorGlobal("receive(): TDLib client not initialized");
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
                    handle_update(j);
                } catch (const std::exception& e) {
                    logger_->error("update listener: JSON parse error: " + std::string(e.what()));
                }
            } catch (const std::exception& e) {
                logger_->error("update listener: exception: " + std::string(e.what()));
            }
        }
        logger_->info("update listener stopped");
    });
}

void TelegramSession::stop_update_listener() {
    if (!listening_) return;
    stop_update_listener_flag_ = true;
    if (update_listener_thread_.joinable()) update_listener_thread_.join();
    listening_ = false;
}

int TelegramSession::sendDice(int64_t chat_id, int /*dice_value*/) {
    json req = {
        {"@type","sendMessage"},
        {"chat_id", chat_id},
        {"input_message_content", { {"@type","inputMessageDice"}, {"emoji", dice_emoji_} }}
    };
    std::string extra = "senddice:" + std::to_string(chat_id) + ":" + rand_token();
    json resp = request_with_extra_blocking(this, req, extra, 10.0);
    if (!resp.is_object()) { logger_->error("sendDice: timeout"); append_audit("sendDice timeout chat=" + std::to_string(chat_id)); return 0; }
    if (resp.contains("@type") && resp["@type"] == "error") { logger_->error("sendDice error: " + resp.dump()); append_audit("sendDice error: " + resp.dump()); return 0; }
    if (resp.contains("@type") && resp["@type"] == "message" && resp.contains("id")) {
        int64_t mid = resp["id"].get<int64_t>();
        append_audit("Sent dice chat=" + std::to_string(chat_id) + " msg=" + std::to_string(mid));
        return static_cast<int>(mid);
    }
    return 0;
}

int TelegramSession::waitForDiceValue(int64_t chat_id, int msg_id, int timeout_ms) {
    std::unique_lock<std::mutex> lk(g_dice_mtx);
    DiceKey key{chat_id, (int64_t)msg_id};
    auto pred = [&](){ return g_dice_values.find(key) != g_dice_values.end(); };
    if (!g_dice_cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), pred)) return -1;
    return g_dice_values[key];
}

std::vector<int64_t> TelegramSession::sendDiceBatch(int64_t chat_id, int count, int pacing_ms, const std::string& emoji) {
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

std::vector<int> TelegramSession::pick_best_triple(const std::vector<int>& dice_values) const {
    const auto& allowed = valid_sums_.empty() ? allowed_sums_ : valid_sums_;
    BestTriple bt = best_triple_from_vector(dice_values, allowed);
    if (!bt.found) {
        return {};
    }
    return {bt.i, bt.j, bt.k};
}

void TelegramSession::on_update(const nlohmann::json& update) {
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
        logger_->error("on_update: exception: " + std::string(e.what()));
    } catch (...) {
        std::cerr << "[ERROR] Unknown exception in on_update" << std::endl;
        logger_->error("on_update: unknown exception");
    }
}

void TelegramSession::send_best3_dice_to_public() {
    if (!config_.value("enable_auto_publish", false)) {
        logger_->info("send_best3_dice_to_public: auto publish disabled by config");
        append_audit("Auto-publish disabled; skipping send_best3_dice_to_public");
        return;
    }

    if (is_paused_) { logger_->warn("send_best3_dice_to_public: paused"); return; }
    if (!authorized_) { logger_->warn("send_best3_dice_to_public: not authorized"); return; }
    if (private_dice_group_id_ == 0) { logger_->error("private group not configured"); return; }
    if (public_groups_.empty()) { logger_->error("no public groups configured"); return; }

    const int MAX_ATTEMPTS = config_.value("max_attempts", 3);
    const int TOTAL = config_.value("dice_count", 10);
    const int PER_DICE_TIMEOUT_MS = config_.value("dice_result_timeout_ms", 2000);
    const int SEND_PACING_MS = std::max(1, dice_settings_[dice_emoji_].interval_ms);
    const auto& allowed = valid_sums_.empty() ? allowed_sums_ : valid_sums_; // Use allowed sums
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

        auto triple = pick_best_triple(arr); // Uses allowed sums internally
        if (!triple.has_value()) { logger_->info("no valid triple found"); append_audit("no valid triple"); continue; }

        auto [i,j,k] = triple.value();
        int v1 = arr[i], v2 = arr[j], v3 = arr[k];
        int sum = v1 + v2 + v3;
        if (!allowed.empty() && !allowed.count(sum)) { // Check allowed sums
            logger_->info("triple sum " + std::to_string(sum) + " not in allowed sums");
            append_audit("Triple sum " + std::to_string(sum) + " not in allowed sums");
            continue;
        }

        append_audit("Picked triple indices (" + std::to_string(i) + "," + std::to_string(j) + "," + std::to_string(k) + ") values (" + std::to_string(v1)+","+std::to_string(v2)+","+std::to_string(v3)+") sum=" + std::to_string(sum));
        logger_->info("Picked triple sum=" + std::to_string(sum));

        for (const auto& g : public_groups_) {
            if (g.id == 0) continue;

            for (int n = 0; n < 3; ++n) {
                json req = {
                    {"@type","sendMessage"},
                    {"chat_id", g.id},
                    {"input_message_content", { {"@type","inputMessageDice"}, {"emoji", dice_emoji_} }}
                };
                send(req.dump());
                sleep_ms(SEND_PACING_MS);
            }

            std::ostringstream disc;
            disc << "Best triple from developer roll: " << v1 << ", " << v2 << ", " << v3 << " (sum = " << sum << ")";
            json req = { {"@type","sendMessage"}, {"chat_id", g.id}, {"input_message_content", { {"@type","inputMessageText"}, {"text", { {"@type","formattedText"}, {"text", disc.str()} } } } } };
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

void TelegramSession::close() { 
    stop_update_listener(); 
#ifdef __unix__
    s_control_server_running = false;
    if (s_control_server_fd != -1) {
        shutdown(s_control_server_fd, SHUT_RDWR);
        ::close(s_control_server_fd);
        s_control_server_fd = -1;
    }
#endif
}

void TelegramSession::switch_account(const std::string& new_phone) {
    if (new_phone.empty()) {
        logger_->error("switch_account: empty phone number");
        return;
    }
    logger_->info("switch_account: switching to phone " + new_phone);
    close();
    submit_phone_async(new_phone);
}

void TelegramSession::set_session_suffix(const std::string& suffix) { session_suffix_ = suffix; }

void TelegramSession::reset_session_files() {
    try {
        std::filesystem::remove_all("tdlib-data/" + session_suffix_);
        logger_->info("reset_session_files: cleared session files for " + session_suffix_);
    } catch (const std::exception& e) {
        logger_->error("reset_session_files: failed to remove session files: " + std::string(e.what()));
    }
}

void TelegramSession::remove_session() {
    close();
    reset_session_files();
    authorized_ = false;
    update_auth_stage(AuthStage::Closed);
    logger_->info("remove_session: session removed");
}

void TelegramSession::save_config() {
    try {
        std::ofstream file("resources/config/config.json");
        if (!file) {
            logger_->error("save_config: failed to open config file");
            return;
        }
        file << config_.dump(2);
        logger_->info("save_config: configuration saved");
    } catch (const std::exception& e) {
        logger_->error("save_config: error: " + std::string(e.what()));
    }
}

bool TelegramSession::is_authorized() const { return authorized_; }
int64_t TelegramSession::get_own_user_id() { return 0; }
bool TelegramSession::is_paused() const { return is_paused_; }
void TelegramSession::pause_dice() { is_paused_ = true; }
void TelegramSession::resume_dice() { is_paused_ = false; }

void TelegramSession::parse_dice_command(const std::string& command) {
    std::regex cmd_regex(R"(^([\x{1F3B2}-\x{1F3FF}]):(\d+):(-?\d+))",
                         std::regex::ECMAScript | std::regex::icase | std::regex::optimize);
    std::smatch match;
    if (std::regex_match(command, match, cmd_regex)) {
        std::string emoji = match[1];
        int target = std::stoi(match[2]);
        int64_t chat_id = std::stoll(match[3]);
        set_dice_emoji(emoji);
        if (g_handler) {
            g_handler->process_dice_command(emoji, target, chat_id);
            append_audit("Parsed dice command: " + command);
        }
    } else {
        logger_->warn("parse_dice_command: invalid command format: " + command);
        append_audit("Invalid dice command: " + command);
    }
}

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

std::vector<std::string> TelegramSession::get_audit_logs(int max_lines) {
    std::vector<std::string> logs;
    std::ifstream f("dice_rolls.log");
    if (!f) {
        logger_->error("get_audit_logs: failed to open dice_rolls.log");
        return logs;
    }
    std::string line;
    while (std::getline(f, line) && (max_lines <= 0 || logs.size() < static_cast<size_t>(max_lines))) {
        logs.push_back(line);
    }
    return logs;
}

void TelegramSession::start_control_server() {
#ifdef __unix__
    if (s_control_server_running.load()) return;
    s_control_server_running = true;
    s_control_thread = std::thread([this]() {
        int port = config_.value("control_port", 8879);
        int srv = ::socket(AF_INET, SOCK_STREAM, 0);
        if (srv < 0) { if (logger_) logger_->error("control server: socket failed"); s_control_server_running = false; return; }
        int one = 1; setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);
        if (::bind(srv, (struct sockaddr*)&addr, sizeof(addr)) != 0) { 
            ::close(srv); 
            if (logger_) logger_->error("control server: bind failed on port " + std::to_string(port)); 
            s_control_server_running = false; 
            return; 
        }
        if (::listen(srv, 4) != 0) { ::close(srv); if (logger_) logger_->error("control server: listen failed"); s_control_server_running = false; return; }
        s_control_server_fd = srv;
        if (logger_) logger_->info("Control server running on port " + std::to_string(port));
        while (s_control_server_running) {
            struct sockaddr_in peer{}; socklen_t plen = sizeof(peer);
            int fd = accept(srv, (struct sockaddr*)&peer, &plen);
            if (fd < 0) { if (!s_control_server_running) break; sleep_ms(50); continue; }
            std::string line;
            char buf[1024];
            ssize_t n;
            struct timeval tv; tv.tv_sec = 5; tv.tv_usec = 0;
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            while ((n = recv(fd, buf, sizeof(buf), 0)) > 0) {
                line.append(buf, buf + n);
                if (!line.empty() && line.back() == '\n') break;
                if (line.size() > 65536) break;
            }
            if (!line.empty() && line.back() == '\n') line.pop_back();
            std::string reply;
            try { 
                reply = this->handle_control_command(line); 
            } catch (const std::exception& ex) { 
                json err; err["ok"]=false; err["error"]="handler_exception: " + std::string(ex.what()); reply = err.dump(); 
            } catch (...) { 
                json err; err["ok"]=false; err["error"]="unknown_exception"; reply = err.dump(); 
            }
            reply.push_back('\n');
            ::send(fd, reply.data(), reply.size(), 0);
            ::close(fd);
        }
        ::close(srv);
        s_control_server_fd = -1;
        if (logger_) logger_->info("Control server stopped");
    });
    s_control_thread.detach();
#endif
}

void TelegramSession::stop_control_server() {
#ifdef __unix__
    s_control_server_running = false;
    if (s_control_server_fd != -1) {
        shutdown(s_control_server_fd, SHUT_RDWR);
        ::close(s_control_server_fd);
        s_control_server_fd = -1;
    }
#endif
}

std::string TelegramSession::handle_control_command(const std::string& line) {
    try {
        json req;
        if (!line.empty() && (line.front() == '{' || line.front() == '[')) {
            req = json::parse(line);
            if (req.is_object() && req.contains("command") && req["command"].is_string()) {
                std::string cmd = req["command"].get<std::string>();
                if (cmd == "get_audit_logs") {
                    int max_lines = req.value("max_lines", 100);
                    auto logs = get_audit_logs(max_lines);
                    json resp;
                    resp["ok"] = true;
                    resp["logs"] = logs;
                    return resp.dump();
                }
                if (g_handler) g_handler->sendCommand(cmd);
                json ok; ok["ok"]=true; return ok.dump();
            }
        }
        if (!line.empty()) {
            if (g_handler) g_handler->sendCommand(line);
            json ok; ok["ok"]=true; return ok.dump();
        }
        json err; err["ok"]=false; err["error"]="empty_command";
        return err.dump();
    } catch (const std::exception& ex) {
        json err; err["ok"]=false; err["error"]=std::string("exception: ")+ex.what();
        return err.dump();
    } catch (...) {
        json err; err["ok"]=false; err["error"]="unknown_exception";
        return err.dump();
    }
}

