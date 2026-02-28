// smb.cpp - single-file SMB2/SMB3 baseline server and CLI.
//
// This file intentionally uses an amalgamated layout:
//   1) core/platform
//   2) SMB protocol parsing/serialization
//   3) server runtime
//   4) CLI + self-tests
//
// Goal: standalone, portable, single translation unit without external deps.

#include <array>
#include <atomic>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <csignal>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <iostream>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifndef SMB_ENABLE_CONTRACTS
#define SMB_ENABLE_CONTRACTS 1
#endif

#ifdef _WIN32
#include <bcrypt.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#if defined(_MSC_VER)
#pragma comment(lib, "ws2_32.lib")
#endif
using socket_t = SOCKET;
using socket_len_t = int;
constexpr socket_t kInvalidSocket = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#if defined(__linux__)
#include <sys/random.h>
#endif
#include <unistd.h>
using socket_t = int;
using socket_len_t = socklen_t;
constexpr socket_t kInvalidSocket = -1;
#endif

namespace smb {

constexpr const char* kAppName = "smb-single";
constexpr const char* kAppVersion = "0.5.0";
constexpr std::uint16_t kDefaultPort = 445U;

constexpr std::uint32_t kProtocolSmb2 = 0x424D53FEU;
constexpr std::uint32_t kSmb2FlagResponse = 0x00000001U;
constexpr std::uint32_t kSmb2FlagSigned = 0x00000008U;

constexpr std::size_t kSmb2HeaderFlagsOffset = 16U;
constexpr std::size_t kSmb2HeaderSignatureOffset = 48U;
constexpr std::size_t kSmb2SignatureSize = 16U;

constexpr std::uint32_t kStatusSuccess = 0x00000000U;
constexpr std::uint32_t kStatusNotSupported = 0xC00000BBU;
constexpr std::uint32_t kStatusInvalidParameter = 0xC000000DU;
constexpr std::uint32_t kStatusRequestNotAccepted = 0xC00000D0U;
constexpr std::uint32_t kStatusLogonFailure = 0xC000006DU;
constexpr std::uint32_t kStatusMoreProcessingRequired = 0xC0000016U;
constexpr std::uint32_t kStatusAccessDenied = 0xC0000022U;
constexpr std::uint32_t kStatusObjectNameNotFound = 0xC0000034U;
constexpr std::uint32_t kStatusObjectPathNotFound = 0xC000003AU;
constexpr std::uint32_t kStatusObjectNameCollision = 0xC0000035U;
constexpr std::uint32_t kStatusBadNetworkName = 0xC00000CCU;
constexpr std::uint32_t kStatusInvalidHandle = 0xC0000008U;
constexpr std::uint32_t kStatusInternalError = 0xC00000E5U;
constexpr std::uint32_t kStatusInsufficientResources = 0xC000009AU;
constexpr std::uint32_t kStatusNoMoreFiles = 0x80000006U;

constexpr std::size_t kSmbMaxFrameBytes = 1024U * 1024U;
constexpr std::size_t kDefaultMaxConcurrentClients = 128U;
constexpr std::size_t kMaxRequestsPerConnection = 1024U;
constexpr std::size_t kDefaultMaxOpenFilesPerConnection = 64U;
constexpr std::size_t kDefaultMaxClientsPerIp = 8U;
constexpr std::size_t kDefaultProductionMaxClientsPerIp = 4U;
constexpr int kDefaultSocketTimeoutSeconds = 10;
constexpr std::uint32_t kDefaultAuthFailWindowSeconds = 600U;
constexpr std::size_t kDefaultAuthFailMax = 5U;
constexpr std::uint32_t kDefaultAuthBlockSeconds = 1800U;
constexpr std::uint64_t kDefaultMaxFileSizeBytes = 64ULL * 1024ULL * 1024ULL;
constexpr std::size_t kMinRecommendedPasswordLength = 8U;
constexpr std::size_t kMinProductionPasswordLength = 12U;
constexpr int kServerAcceptPollMillis = 250;

enum class ExitCode : int {
    Ok = 0,
    GenericError = 1,
    InvalidArguments = 2,
    EnvironmentRestricted = 3,
};

enum class Smb2Command : std::uint16_t {
    Negotiate = 0x0000U,
    SessionSetup = 0x0001U,
    Logoff = 0x0002U,
    TreeConnect = 0x0003U,
    TreeDisconnect = 0x0004U,
    Create = 0x0005U,
    Close = 0x0006U,
    Flush = 0x0007U,
    Read = 0x0008U,
    Write = 0x0009U,
    Lock = 0x000AU,
    Ioctl = 0x000BU,
    Cancel = 0x000CU,
    Echo = 0x000DU,
    QueryDirectory = 0x000EU,
    ChangeNotify = 0x000FU,
    QueryInfo = 0x0010U,
    SetInfo = 0x0011U,
    OplockBreak = 0x0012U,
};

#pragma pack(push, 1)
struct Smb2Header {
    std::uint32_t protocol_id;
    std::uint16_t structure_size;
    std::uint16_t credit_charge;
    std::uint32_t status;
    std::uint16_t command;
    std::uint16_t credit_request;
    std::uint32_t flags;
    std::uint32_t next_command;
    std::uint64_t message_id;
    std::uint32_t reserved;
    std::uint32_t tree_id;
    std::uint64_t session_id;
    std::uint8_t signature[16];
};

struct Smb2ErrorBody {
    std::uint16_t structure_size;
    std::uint16_t error_context_count;
    std::uint32_t byte_count;
};

struct NegotiateRequestBody {
    std::uint16_t structure_size;
    std::uint16_t dialect_count;
    std::uint16_t security_mode;
    std::uint16_t reserved;
    std::uint32_t capabilities;
    std::uint8_t client_guid[16];
    std::uint32_t negotiate_context_offset;
    std::uint16_t negotiate_context_count;
    std::uint16_t reserved2;
};

struct NegotiateResponseBody {
    std::uint16_t structure_size;
    std::uint16_t security_mode;
    std::uint16_t dialect_revision;
    std::uint16_t negotiate_context_count;
    std::uint8_t server_guid[16];
    std::uint32_t capabilities;
    std::uint32_t max_transact_size;
    std::uint32_t max_read_size;
    std::uint32_t max_write_size;
    std::uint64_t system_time;
    std::uint64_t server_start_time;
    std::uint16_t security_buffer_offset;
    std::uint16_t security_buffer_length;
    std::uint32_t negotiate_context_offset;
};

struct SessionSetupRequestBody {
    std::uint16_t structure_size;
    std::uint8_t flags;
    std::uint8_t security_mode;
    std::uint32_t capabilities;
    std::uint32_t channel;
    std::uint16_t security_buffer_offset;
    std::uint16_t security_buffer_length;
    std::uint64_t previous_session_id;
};

struct SessionSetupResponseBody {
    std::uint16_t structure_size;
    std::uint16_t session_flags;
    std::uint16_t security_buffer_offset;
    std::uint16_t security_buffer_length;
};
#pragma pack(pop)

static_assert(sizeof(Smb2Header) == 64U, "Smb2Header size must be 64");
static_assert(sizeof(Smb2ErrorBody) == 8U, "Smb2ErrorBody size mismatch");
static_assert(sizeof(NegotiateRequestBody) == 36U, "NegotiateRequestBody size mismatch");
static_assert(sizeof(NegotiateResponseBody) == 64U, "NegotiateResponseBody size mismatch");
static_assert(sizeof(SessionSetupRequestBody) == 24U, "SessionSetupRequestBody size mismatch");
static_assert(sizeof(SessionSetupResponseBody) == 8U, "SessionSetupResponseBody size mismatch");

struct AbuseProtectionConfig {
    std::size_t max_clients_per_ip{kDefaultMaxClientsPerIp};
    std::uint32_t auth_fail_window_sec{kDefaultAuthFailWindowSeconds};
    std::size_t auth_fail_max{kDefaultAuthFailMax};
    std::uint32_t auth_block_sec{kDefaultAuthBlockSeconds};
};

struct IpSecurityState {
    std::size_t active_connections{0U};
    std::deque<std::uint64_t> auth_fail_times{};
    std::uint64_t blocked_until_sec{0U};
};

enum class IpAcceptDecision : std::uint8_t {
    Allow = 0,
    Blocked,
    ConnectionLimit,
};

std::atomic<std::uint64_t> g_next_session_id{1U};
std::atomic<std::uint32_t> g_next_tree_id{1U};
std::atomic<std::uint64_t> g_next_file_id{1U};
std::atomic<std::size_t> g_active_clients{0U};
volatile std::sig_atomic_t g_shutdown_requested = 0;
std::mutex g_log_mutex;
std::mutex g_ip_security_mutex;
std::unordered_map<std::string, IpSecurityState> g_ip_security_states{};

[[noreturn]] void contract_fail(const char* kind, const char* expr, const char* file, int line) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    std::cerr << "[contract][" << kind << "] " << expr << " @ " << file << ":" << line << std::endl;
    std::abort();
}

#if SMB_ENABLE_CONTRACTS
#define SMB_EXPECT(expr) \
    do { \
        if (!(expr)) { \
            ::smb::contract_fail("expect", #expr, __FILE__, __LINE__); \
        } \
    } while (false)
#define SMB_ENSURE(expr) \
    do { \
        if (!(expr)) { \
            ::smb::contract_fail("ensure", #expr, __FILE__, __LINE__); \
        } \
    } while (false)
#define SMB_INVARIANT(expr) \
    do { \
        if (!(expr)) { \
            ::smb::contract_fail("invariant", #expr, __FILE__, __LINE__); \
        } \
    } while (false)
#else
#define SMB_EXPECT(expr) \
    do { \
        (void)(expr); \
    } while (false)
#define SMB_ENSURE(expr) \
    do { \
        (void)(expr); \
    } while (false)
#define SMB_INVARIANT(expr) \
    do { \
        (void)(expr); \
    } while (false)
#endif

void log_line(const std::string& message) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    std::cout << message << std::endl;
}

std::uint64_t monotonic_seconds() {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(now).count());
}

void prune_auth_failures_locked(IpSecurityState& st, std::uint64_t now_sec, std::uint32_t window_sec) {
    while (!st.auth_fail_times.empty()) {
        const std::uint64_t age = now_sec - st.auth_fail_times.front();
        if (age <= static_cast<std::uint64_t>(window_sec)) {
            break;
        }
        st.auth_fail_times.pop_front();
    }
}

void maybe_cleanup_ip_state_locked(std::unordered_map<std::string, IpSecurityState>::iterator it, std::uint64_t now_sec) {
    if (it->second.active_connections != 0U) {
        return;
    }
    if (!it->second.auth_fail_times.empty()) {
        return;
    }
    if (it->second.blocked_until_sec > now_sec) {
        return;
    }
    g_ip_security_states.erase(it);
}

IpAcceptDecision try_acquire_ip_slot(const std::string& ip, const AbuseProtectionConfig& cfg) {
    std::lock_guard<std::mutex> lock(g_ip_security_mutex);
    const std::uint64_t now_sec = monotonic_seconds();
    IpSecurityState& st = g_ip_security_states[ip];
    prune_auth_failures_locked(st, now_sec, cfg.auth_fail_window_sec);
    if (st.blocked_until_sec <= now_sec) {
        st.blocked_until_sec = 0U;
    }
    if (st.blocked_until_sec > now_sec) {
        return IpAcceptDecision::Blocked;
    }
    if (st.active_connections >= cfg.max_clients_per_ip) {
        return IpAcceptDecision::ConnectionLimit;
    }
    st.active_connections += 1U;
    return IpAcceptDecision::Allow;
}

void release_ip_slot(const std::string& ip) {
    std::lock_guard<std::mutex> lock(g_ip_security_mutex);
    const auto it = g_ip_security_states.find(ip);
    if (it == g_ip_security_states.end()) {
        return;
    }
    if (it->second.active_connections > 0U) {
        it->second.active_connections -= 1U;
    }
    maybe_cleanup_ip_state_locked(it, monotonic_seconds());
}

bool ip_is_currently_blocked(const std::string& ip, const AbuseProtectionConfig& cfg) {
    std::lock_guard<std::mutex> lock(g_ip_security_mutex);
    const auto it = g_ip_security_states.find(ip);
    if (it == g_ip_security_states.end()) {
        return false;
    }
    IpSecurityState& st = it->second;
    const std::uint64_t now_sec = monotonic_seconds();
    prune_auth_failures_locked(st, now_sec, cfg.auth_fail_window_sec);
    if (st.blocked_until_sec <= now_sec) {
        st.blocked_until_sec = 0U;
        maybe_cleanup_ip_state_locked(it, now_sec);
        return false;
    }
    return true;
}

void record_auth_failure_for_ip(const std::string& ip, const AbuseProtectionConfig& cfg) {
    if (ip.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_ip_security_mutex);
    const std::uint64_t now_sec = monotonic_seconds();
    IpSecurityState& st = g_ip_security_states[ip];
    prune_auth_failures_locked(st, now_sec, cfg.auth_fail_window_sec);
    st.auth_fail_times.push_back(now_sec);
    if (st.auth_fail_times.size() >= cfg.auth_fail_max) {
        st.blocked_until_sec = now_sec + static_cast<std::uint64_t>(cfg.auth_block_sec);
        st.auth_fail_times.clear();
    }
}

void record_auth_success_for_ip(const std::string& ip) {
    if (ip.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_ip_security_mutex);
    const auto it = g_ip_security_states.find(ip);
    if (it == g_ip_security_states.end()) {
        return;
    }
    it->second.auth_fail_times.clear();
    maybe_cleanup_ip_state_locked(it, monotonic_seconds());
}

bool fill_secure_random_bytes(std::uint8_t* out, std::size_t len) {
    SMB_EXPECT(out != nullptr || len == 0U);
    if (len == 0U) {
        return true;
    }
#ifdef _WIN32
    std::size_t offset = 0U;
    while (offset < len) {
        const std::size_t chunk = std::min<std::size_t>(len - offset, static_cast<std::size_t>(ULONG_MAX));
        const NTSTATUS rc = BCryptGenRandom(
            nullptr,
            reinterpret_cast<PUCHAR>(out + offset),
            static_cast<ULONG>(chunk),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (rc != 0) {
            return false;
        }
        offset += chunk;
    }
    return true;
#else
#if defined(__linux__)
    std::size_t offset = 0U;
    while (offset < len) {
        const ssize_t rc = getrandom(out + offset, len - offset, 0);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (rc == 0) {
            break;
        }
        offset += static_cast<std::size_t>(rc);
    }
    if (offset == len) {
        return true;
    }
#endif
    std::FILE* f = std::fopen("/dev/urandom", "rb");
    if (f == nullptr) {
        return false;
    }
    std::size_t read_total = 0U;
    while (read_total < len) {
        const std::size_t n = std::fread(out + read_total, 1U, len - read_total, f);
        if (n == 0U) {
            break;
        }
        read_total += n;
    }
    const bool ok = read_total == len;
    (void)std::fclose(f);
    return ok;
#endif
}

// -------------------------------
// Core byte order + parse helpers
// -------------------------------

std::uint16_t bswap16(std::uint16_t value) {
    return static_cast<std::uint16_t>((value << 8U) | (value >> 8U));
}

std::uint32_t bswap32(std::uint32_t value) {
    return ((value & 0x000000FFU) << 24U) |
           ((value & 0x0000FF00U) << 8U) |
           ((value & 0x00FF0000U) >> 8U) |
           ((value & 0xFF000000U) >> 24U);
}

std::uint64_t bswap64(std::uint64_t value) {
    return (static_cast<std::uint64_t>(bswap32(static_cast<std::uint32_t>(value & 0xFFFFFFFFULL))) << 32U) |
           static_cast<std::uint64_t>(bswap32(static_cast<std::uint32_t>(value >> 32U)));
}

constexpr bool host_is_little_endian() {
#if defined(_WIN32) || (defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
    return true;
#else
    return false;
#endif
}

std::uint16_t to_le16(std::uint16_t value) {
    return host_is_little_endian() ? value : bswap16(value);
}

std::uint32_t to_le32(std::uint32_t value) {
    return host_is_little_endian() ? value : bswap32(value);
}

std::uint64_t to_le64(std::uint64_t value) {
    return host_is_little_endian() ? value : bswap64(value);
}

std::uint16_t from_le16(std::uint16_t value) {
    return to_le16(value);
}

std::uint32_t from_le32(std::uint32_t value) {
    return to_le32(value);
}

std::uint64_t from_le64(std::uint64_t value) {
    return to_le64(value);
}

bool parse_u16(const char* text, std::uint16_t* out) {
    SMB_EXPECT(out != nullptr);
    if ((text == nullptr) || (text[0] == '\0')) {
        return false;
    }
    char* end = nullptr;
    const unsigned long value = std::strtoul(text, &end, 10);
    if ((end == nullptr) || (*end != '\0') || (value > 65535UL)) {
        return false;
    }
    *out = static_cast<std::uint16_t>(value);
    return true;
}

bool parse_u32(const char* text, std::uint32_t* out) {
    SMB_EXPECT(out != nullptr);
    if ((text == nullptr) || (text[0] == '\0')) {
        return false;
    }
    char* end = nullptr;
    const unsigned long value = std::strtoul(text, &end, 10);
    if ((end == nullptr) || (*end != '\0')) {
        return false;
    }
    if (value > static_cast<unsigned long>(std::numeric_limits<std::uint32_t>::max())) {
        return false;
    }
    *out = static_cast<std::uint32_t>(value);
    return true;
}

bool parse_u64(const char* text, std::uint64_t* out) {
    SMB_EXPECT(out != nullptr);
    if ((text == nullptr) || (text[0] == '\0')) {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    const unsigned long long value = std::strtoull(text, &end, 10);
    if ((end == nullptr) || (*end != '\0') || (errno != 0)) {
        return false;
    }
    *out = static_cast<std::uint64_t>(value);
    return true;
}

bool parse_int(const char* text, int* out) {
    SMB_EXPECT(out != nullptr);
    if ((text == nullptr) || (text[0] == '\0')) {
        return false;
    }
    char* end = nullptr;
    const long value = std::strtol(text, &end, 10);
    if ((end == nullptr) || (*end != '\0')) {
        return false;
    }
    if ((value < static_cast<long>(std::numeric_limits<int>::min())) ||
        (value > static_cast<long>(std::numeric_limits<int>::max()))) {
        return false;
    }
    *out = static_cast<int>(value);
    return true;
}

// -------------------------------
// Platform/socket helpers
// -------------------------------

int socket_last_error() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

bool socket_permission_error(int error_value) {
#ifdef _WIN32
    return (error_value == WSAEACCES);
#else
    return (error_value == EACCES) || (error_value == EPERM);
#endif
}

bool init_sockets() {
#ifdef _WIN32
    WSADATA wsa_data{};
    return WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0;
#else
    return true;
#endif
}

void cleanup_sockets() {
#ifdef _WIN32
    WSACleanup();
#endif
}

void close_socket(socket_t sock) {
    if (sock == kInvalidSocket) {
        return;
    }
#ifdef _WIN32
    (void)closesocket(sock);
#else
    (void)close(sock);
#endif
}

bool set_socket_timeouts(socket_t sock, int timeout_seconds) {
#ifdef _WIN32
    const DWORD timeout_ms = static_cast<DWORD>(timeout_seconds * 1000);
    const int rc1 =
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    const int rc2 =
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    return (rc1 == 0) && (rc2 == 0);
#else
    timeval tv{};
    tv.tv_sec = timeout_seconds;
    tv.tv_usec = 0;
    const int rc1 = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    const int rc2 = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return (rc1 == 0) && (rc2 == 0);
#endif
}

bool set_socket_keepalive(socket_t sock) {
    int enabled = 1;
#ifdef _WIN32
    return setsockopt(
               sock,
               SOL_SOCKET,
               SO_KEEPALIVE,
               reinterpret_cast<const char*>(&enabled),
               static_cast<int>(sizeof(enabled))) == 0;
#else
    return setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof(enabled)) == 0;
#endif
}

void on_shutdown_signal(int /*signum*/) {
    g_shutdown_requested = 1;
}

void install_shutdown_signal_handlers() {
#ifndef _WIN32
    (void)std::signal(SIGPIPE, SIG_IGN);
#endif
    (void)std::signal(SIGINT, on_shutdown_signal);
    (void)std::signal(SIGTERM, on_shutdown_signal);
}

bool shutdown_requested() {
    return g_shutdown_requested != 0;
}

bool wait_for_socket_readable(socket_t sock, int timeout_ms) {
    if (timeout_ms < 0) {
        return false;
    }
    fd_set readfds{};
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
#ifdef _WIN32
    const int rc = select(0, &readfds, nullptr, nullptr, &tv);
#else
    if (sock > static_cast<socket_t>(INT_MAX - 1)) {
        return false;
    }
    const int nfds = static_cast<int>(sock) + 1;
    const int rc = select(nfds, &readfds, nullptr, nullptr, &tv);
    if ((rc < 0) && (errno == EINTR)) {
        return false;
    }
#endif
    return (rc > 0) && (FD_ISSET(sock, &readfds) != 0);
}

#ifdef _WIN32
using io_result_t = int;
#else
using io_result_t = ssize_t;
#endif

io_result_t socket_send_bytes(socket_t sock, const std::uint8_t* data, std::size_t len) {
#ifdef _WIN32
    const int send_len = (len > static_cast<std::size_t>(INT_MAX)) ? INT_MAX : static_cast<int>(len);
    return send(sock, reinterpret_cast<const char*>(data), send_len, 0);
#else
    return send(sock, reinterpret_cast<const char*>(data), len, 0);
#endif
}

io_result_t socket_recv_bytes(socket_t sock, std::uint8_t* data, std::size_t len) {
#ifdef _WIN32
    const int recv_len = (len > static_cast<std::size_t>(INT_MAX)) ? INT_MAX : static_cast<int>(len);
    return recv(sock, reinterpret_cast<char*>(data), recv_len, 0);
#else
    return recv(sock, reinterpret_cast<char*>(data), len, 0);
#endif
}

bool send_all(socket_t sock, const std::uint8_t* data, std::size_t len) {
    SMB_EXPECT(data != nullptr);
    std::size_t sent = 0U;
    while (sent < len) {
        const io_result_t rc = socket_send_bytes(sock, data + sent, len - sent);
        if (rc <= 0) {
            return false;
        }
        sent += static_cast<std::size_t>(rc);
    }
    SMB_ENSURE(sent == len);
    return true;
}

bool recv_all(socket_t sock, std::uint8_t* data, std::size_t len) {
    SMB_EXPECT(data != nullptr);
    std::size_t read_total = 0U;
    while (read_total < len) {
        const io_result_t rc = socket_recv_bytes(sock, data + read_total, len - read_total);
        if (rc <= 0) {
            return false;
        }
        read_total += static_cast<std::size_t>(rc);
    }
    SMB_ENSURE(read_total == len);
    return true;
}

socket_t create_listener(std::uint16_t port) {
    const socket_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == kInvalidSocket) {
        return kInvalidSocket;
    }

    int reuse = 1;
    (void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close_socket(sock);
        return kInvalidSocket;
    }
    if (listen(sock, SOMAXCONN) != 0) {
        close_socket(sock);
        return kInvalidSocket;
    }
    return sock;
}

std::string client_address_string(const sockaddr_in& client_addr) {
    char ip_buf[INET_ADDRSTRLEN] = {};
    const char* text = inet_ntop(AF_INET, &client_addr.sin_addr, ip_buf, sizeof(ip_buf));
    if (text == nullptr) {
        return "unknown";
    }
    return std::string(text) + ":" + std::to_string(ntohs(client_addr.sin_port));
}

std::string client_ip_string(const sockaddr_in& client_addr) {
    char ip_buf[INET_ADDRSTRLEN] = {};
    const char* text = inet_ntop(AF_INET, &client_addr.sin_addr, ip_buf, sizeof(ip_buf));
    if (text == nullptr) {
        return "unknown";
    }
    return std::string(text);
}

// -----------------------------------
// SMB packet parsing + serialization
// -----------------------------------

std::optional<std::array<std::uint8_t, 16>> create_server_guid() {
    std::array<std::uint8_t, 16> guid{};
    if (!fill_secure_random_bytes(guid.data(), guid.size())) {
        return std::nullopt;
    }

    // UUIDv4 layout bits.
    guid[6] = static_cast<std::uint8_t>((guid[6] & 0x0FU) | 0x40U);
    guid[8] = static_cast<std::uint8_t>((guid[8] & 0x3FU) | 0x80U);
    return std::make_optional(guid);
}

std::uint64_t now_windows_filetime_utc() {
    const auto now = std::chrono::system_clock::now();
    const auto now_secs = std::chrono::time_point_cast<std::chrono::seconds>(now);
    const auto epoch_secs = static_cast<std::uint64_t>(now_secs.time_since_epoch().count());
    return (epoch_secs + 11644473600ULL) * 10000000ULL;
}

struct InputFrame {
    bool has_nbss_header{false};
    std::vector<std::uint8_t> payload{};
};

bool recv_smb_frame(socket_t client, InputFrame& frame) {
    std::array<std::uint8_t, 4> prefix{};
    if (!recv_all(client, prefix.data(), prefix.size())) {
        return false;
    }
    if (prefix[0] != 0x00U) {
        return false;
    }

    const std::uint32_t len = (static_cast<std::uint32_t>(prefix[1]) << 16U) |
                              (static_cast<std::uint32_t>(prefix[2]) << 8U) |
                              static_cast<std::uint32_t>(prefix[3]);
    if ((len == 0U) || (len > kSmbMaxFrameBytes)) {
        return false;
    }

    frame.has_nbss_header = true;
    frame.payload.resize(static_cast<std::size_t>(len));
    return recv_all(client, frame.payload.data(), frame.payload.size());
}

std::vector<std::uint8_t> add_nbss_header(const std::vector<std::uint8_t>& payload) {
    SMB_EXPECT(payload.size() <= 0x00FFFFFFU);
    std::vector<std::uint8_t> out;
    out.reserve(payload.size() + 4U);
    out.push_back(0x00U);
    out.push_back(static_cast<std::uint8_t>((payload.size() >> 16U) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((payload.size() >> 8U) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>(payload.size() & 0xFFU));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

struct ParsedRequestHeader {
    Smb2Header raw{};
    std::uint16_t command{0U};
    std::uint64_t message_id{0U};
    std::uint64_t session_id{0U};
    std::uint32_t tree_id{0U};
    std::uint32_t flags{0U};
    std::uint32_t next_command{0U};
};

std::optional<ParsedRequestHeader> parse_request_header(const std::vector<std::uint8_t>& frame) {
    if (frame.size() < sizeof(Smb2Header)) {
        return std::nullopt;
    }

    ParsedRequestHeader parsed{};
    std::memcpy(&parsed.raw, frame.data(), sizeof(Smb2Header));
    if (from_le32(parsed.raw.protocol_id) != kProtocolSmb2) {
        return std::nullopt;
    }
    if (from_le16(parsed.raw.structure_size) != 64U) {
        return std::nullopt;
    }

    parsed.command = from_le16(parsed.raw.command);
    parsed.message_id = from_le64(parsed.raw.message_id);
    parsed.session_id = from_le64(parsed.raw.session_id);
    parsed.tree_id = from_le32(parsed.raw.tree_id);
    parsed.flags = from_le32(parsed.raw.flags);
    parsed.next_command = from_le32(parsed.raw.next_command);
    return parsed;
}

std::string summarize_response_statuses(const std::vector<std::uint8_t>& payload) {
    if (payload.size() < sizeof(Smb2Header)) {
        return "invalid-response-short";
    }
    std::size_t offset = 0U;
    std::string out{};
    for (std::size_t i = 0U; offset < payload.size(); ++i) {
        if ((payload.size() - offset) < sizeof(Smb2Header)) {
            if (!out.empty()) {
                out += " ";
            }
            out += "truncated";
            break;
        }
        Smb2Header hdr{};
        std::memcpy(&hdr, payload.data() + offset, sizeof(Smb2Header));
        const std::uint16_t cmd = from_le16(hdr.command);
        const std::uint32_t status = from_le32(hdr.status);
        const std::uint32_t next = from_le32(hdr.next_command);
        if (!out.empty()) {
            out += " ";
        }
        out += "cmd=" + std::to_string(cmd) + " status=0x";
        {
            std::ostringstream ss{};
            ss << std::hex << status;
            out += ss.str();
        }
        if (next == 0U) {
            break;
        }
        if ((next < sizeof(Smb2Header)) || ((next % 8U) != 0U) || ((offset + static_cast<std::size_t>(next)) > payload.size())) {
            out += " next=invalid";
            break;
        }
        offset += static_cast<std::size_t>(next);
        if (i > 15U) {
            out += " ...";
            break;
        }
    }
    return out;
}

bool validate_negotiate_request(const std::vector<std::uint8_t>& frame) {
    if (frame.size() < (sizeof(Smb2Header) + sizeof(NegotiateRequestBody))) {
        return false;
    }

    NegotiateRequestBody req{};
    std::memcpy(&req, frame.data() + sizeof(Smb2Header), sizeof(NegotiateRequestBody));
    if (from_le16(req.structure_size) != 36U) {
        return false;
    }

    const std::uint16_t dialect_count = from_le16(req.dialect_count);
    if (dialect_count == 0U) {
        return false;
    }

    const std::size_t dialect_bytes = static_cast<std::size_t>(dialect_count) * sizeof(std::uint16_t);
    const std::size_t expected_min = sizeof(Smb2Header) + sizeof(NegotiateRequestBody) + dialect_bytes;
    if (frame.size() < expected_min) {
        return false;
    }

    bool has_supported_dialect = false;
    const std::uint8_t* dialect_ptr = frame.data() + sizeof(Smb2Header) + sizeof(NegotiateRequestBody);
    for (std::size_t i = 0U; i < static_cast<std::size_t>(dialect_count); ++i) {
        std::uint16_t dialect{};
        std::memcpy(&dialect, dialect_ptr + (i * sizeof(std::uint16_t)), sizeof(std::uint16_t));
        const std::uint16_t value = from_le16(dialect);
        if ((value == 0x0202U) || (value == 0x0210U) || (value == 0x0300U) || (value == 0x0302U) ||
            (value == 0x0311U)) {
            has_supported_dialect = true;
            break;
        }
    }
    return has_supported_dialect;
}

bool validate_session_setup_request(const std::vector<std::uint8_t>& frame) {
    if (frame.size() < (sizeof(Smb2Header) + sizeof(SessionSetupRequestBody))) {
        return false;
    }

    SessionSetupRequestBody req{};
    std::memcpy(&req, frame.data() + sizeof(Smb2Header), sizeof(SessionSetupRequestBody));
    if (from_le16(req.structure_size) != 25U) {
        return false;
    }

    const std::uint16_t offset = from_le16(req.security_buffer_offset);
    const std::uint16_t length = from_le16(req.security_buffer_length);
    if (length == 0U) {
        return true;
    }

    if (offset < static_cast<std::uint16_t>(sizeof(Smb2Header) + sizeof(SessionSetupRequestBody))) {
        return false;
    }
    const std::size_t end = static_cast<std::size_t>(offset) + static_cast<std::size_t>(length);
    return end <= frame.size();
}

Smb2Header make_response_header(std::uint16_t command,
                                std::uint64_t message_id,
                                std::uint32_t status,
                                std::uint64_t session_id,
                                std::uint32_t tree_id) {
    Smb2Header hdr{};
    hdr.protocol_id = to_le32(kProtocolSmb2);
    hdr.structure_size = to_le16(64U);
    hdr.credit_charge = to_le16(0U);
    hdr.status = to_le32(status);
    hdr.command = to_le16(command);
    hdr.credit_request = to_le16(1U);
    hdr.flags = to_le32(kSmb2FlagResponse);
    hdr.next_command = to_le32(0U);
    hdr.message_id = to_le64(message_id);
    hdr.reserved = to_le32(0U);
    hdr.tree_id = to_le32(tree_id);
    hdr.session_id = to_le64(session_id);
    std::memset(hdr.signature, 0, sizeof(hdr.signature));
    return hdr;
}

std::vector<std::uint8_t> build_error_response(std::uint64_t message_id,
                                               std::uint16_t command,
                                               std::uint32_t status,
                                               std::uint64_t session_id,
                                               std::uint32_t tree_id) {
    const Smb2Header hdr = make_response_header(command, message_id, status, session_id, tree_id);
    Smb2ErrorBody body{};
    body.structure_size = to_le16(9U);
    body.error_context_count = to_le16(0U);
    body.byte_count = to_le32(0U);

    std::vector<std::uint8_t> packet(sizeof(Smb2Header) + sizeof(Smb2ErrorBody));
    std::memcpy(packet.data(), &hdr, sizeof(Smb2Header));
    std::memcpy(packet.data() + sizeof(Smb2Header), &body, sizeof(Smb2ErrorBody));
    return packet;
}

std::vector<std::uint8_t> build_negotiate_response(std::uint64_t message_id,
                                                   const std::array<std::uint8_t, 16>& server_guid,
                                                   std::uint64_t start_time_filetime,
                                                   std::uint16_t security_mode) {
    const Smb2Header hdr =
        make_response_header(static_cast<std::uint16_t>(Smb2Command::Negotiate), message_id, kStatusSuccess, 0U, 0U);

    NegotiateResponseBody body{};
    body.structure_size = to_le16(65U);
    body.security_mode = to_le16(security_mode);
    body.dialect_revision = to_le16(0x0210U);
    body.negotiate_context_count = to_le16(0U);
    std::memcpy(body.server_guid, server_guid.data(), sizeof(body.server_guid));
    body.capabilities = to_le32(0U);
    body.max_transact_size = to_le32(1024U * 1024U);
    body.max_read_size = to_le32(1024U * 1024U);
    body.max_write_size = to_le32(1024U * 1024U);
    body.system_time = to_le64(now_windows_filetime_utc());
    body.server_start_time = to_le64(start_time_filetime);
    // SPNEGO NegTokenInit with NTLMSSP OID to satisfy SMB clients expecting a security blob.
    static const std::array<std::uint8_t, 30> kSpnegoNegTokenInitNtlm = {
        0x60U, 0x1CU, 0x06U, 0x06U, 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x02U,
        0xA0U, 0x12U, 0x30U, 0x10U, 0xA0U, 0x0EU, 0x30U, 0x0CU, 0x06U, 0x0AU,
        0x2BU, 0x06U, 0x01U, 0x04U, 0x01U, 0x82U, 0x37U, 0x02U, 0x02U, 0x0AU,
    };
    body.security_buffer_offset =
        to_le16(static_cast<std::uint16_t>(sizeof(Smb2Header) + sizeof(NegotiateResponseBody)));
    body.security_buffer_length = to_le16(static_cast<std::uint16_t>(kSpnegoNegTokenInitNtlm.size()));
    body.negotiate_context_offset = to_le32(0U);

    std::vector<std::uint8_t> packet(sizeof(Smb2Header) + sizeof(NegotiateResponseBody) + kSpnegoNegTokenInitNtlm.size());
    std::memcpy(packet.data(), &hdr, sizeof(Smb2Header));
    std::memcpy(packet.data() + sizeof(Smb2Header), &body, sizeof(NegotiateResponseBody));
    std::memcpy(packet.data() + sizeof(Smb2Header) + sizeof(NegotiateResponseBody),
                kSpnegoNegTokenInitNtlm.data(),
                kSpnegoNegTokenInitNtlm.size());
    return packet;
}

std::vector<std::uint8_t> build_session_setup_response(std::uint64_t message_id,
                                                       std::uint64_t session_id,
                                                       std::uint32_t status,
                                                       std::uint16_t session_flags,
                                                       const std::vector<std::uint8_t>& security_blob) {
    const Smb2Header hdr = make_response_header(static_cast<std::uint16_t>(Smb2Command::SessionSetup),
                                                message_id,
                                                status,
                                                session_id,
                                                0U);
    SessionSetupResponseBody body{};
    body.structure_size = to_le16(9U);
    body.session_flags = to_le16(session_flags);
    body.security_buffer_offset = to_le16(static_cast<std::uint16_t>(sizeof(Smb2Header) + sizeof(SessionSetupResponseBody)));
    SMB_EXPECT(security_blob.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()));
    body.security_buffer_length = to_le16(static_cast<std::uint16_t>(security_blob.size()));

    std::vector<std::uint8_t> packet(sizeof(Smb2Header) + sizeof(SessionSetupResponseBody) + security_blob.size());
    std::memcpy(packet.data(), &hdr, sizeof(Smb2Header));
    std::memcpy(packet.data() + sizeof(Smb2Header), &body, sizeof(SessionSetupResponseBody));
    if (!security_blob.empty()) {
        std::memcpy(packet.data() + sizeof(Smb2Header) + sizeof(SessionSetupResponseBody),
                    security_blob.data(),
                    security_blob.size());
    }
    return packet;
}

struct ConnectionState {
    bool negotiated{false};
    bool session_established{false};
    bool session_setup_token_sent{false};
    bool ntlm_challenge_sent{false};
    bool signing_key_valid{false};
    std::array<std::uint8_t, 16> signing_key{};
    std::array<std::uint8_t, 8> ntlm_challenge{};
    bool ntlm_challenge_valid{false};
    std::uint64_t session_id{0U};
    bool tree_connected{false};
    std::uint32_t tree_id{0U};
    std::unordered_set<std::uint64_t> seen_signed_message_ids{};
    struct OpenFileHandle {
        std::uint64_t persistent_id{0U};
        std::uint64_t volatile_id{0U};
        std::FILE* stream{nullptr};
        bool is_directory{false};
        bool directory_listing_sent{false};
        bool writable{false};
        bool delete_allowed{false};
        bool delete_on_close{false};
        std::string full_path{};
    };
    std::map<std::uint64_t, OpenFileHandle> open_files{};
};

struct AuthConfig {
    bool require_auth{true};
    bool auth_session_guest_compat{false};
    bool allow_legacy_ntlm{false};
    bool signing_enabled{false};
    bool signing_required{false};
    std::string username{};
    std::string password{};
};

struct ShareSecurityConfig {
    bool read_only{false};
    bool allow_overwrite{false};
    bool deny_dot_files{true};
    std::size_t max_open_files{kDefaultMaxOpenFilesPerConnection};
    std::uint64_t max_file_size_bytes{kDefaultMaxFileSizeBytes};
};

struct RequestResult {
    std::vector<std::uint8_t> payload{};
    bool keep_connection{true};
};

struct FileIdPair {
    std::uint64_t persistent_id{0U};
    std::uint64_t volatile_id{0U};
};

struct TreeConnectRequestFields {
    std::string share_path{};
};

struct CreateRequestFields {
    std::uint32_t desired_access{0U};
    std::uint32_t create_disposition{0U};
    std::uint32_t create_options{0U};
    std::string relative_path{};
};

struct WriteRequestFields {
    FileIdPair file_id{};
    std::uint64_t offset{0U};
    std::uint32_t length{0U};
    std::size_t data_offset{0U};
};

struct ReadRequestFields {
    FileIdPair file_id{};
    std::uint64_t offset{0U};
    std::uint32_t length{0U};
};

struct QueryDirectoryRequestFields {
    std::uint8_t file_info_class{0U};
    std::uint8_t flags{0U};
    std::uint32_t output_buffer_length{0U};
    FileIdPair file_id{};
    std::string file_name_pattern{"*"};
};

struct LockRequestFields {
    FileIdPair file_id{};
    std::uint16_t lock_count{0U};
};

struct IoctlRequestFields {
    std::uint32_t ctl_code{0U};
    FileIdPair file_id{};
    std::uint32_t flags{0U};
    std::uint32_t max_output_response{0U};
    const std::uint8_t* input_data{nullptr};
    std::size_t input_len{0U};
};

struct SetInfoRequestFields {
    std::uint8_t info_type{0U};
    std::uint8_t file_info_class{0U};
    std::uint32_t additional_info{0U};
    FileIdPair file_id{};
    const std::uint8_t* buffer_data{nullptr};
    std::size_t buffer_len{0U};
};

struct ChangeNotifyRequestFields {
    std::uint16_t flags{0U};
    std::uint32_t output_buffer_length{0U};
    FileIdPair file_id{};
    std::uint32_t completion_filter{0U};
};

struct OplockBreakRequestFields {
    std::uint16_t structure_size{0U};
    std::uint8_t oplock_level{0U};
    FileIdPair file_id{};
};

constexpr std::uint32_t kFileSupersede = 0U;
constexpr std::uint32_t kFileOpen = 1U;
constexpr std::uint32_t kFileCreate = 2U;
constexpr std::uint32_t kFileOpenIf = 3U;
constexpr std::uint32_t kFileOverwrite = 4U;
constexpr std::uint32_t kFileOverwriteIf = 5U;

constexpr std::uint32_t kFileActionSuperseded = 0U;
constexpr std::uint32_t kFileActionOpened = 1U;
constexpr std::uint32_t kFileActionCreated = 2U;
constexpr std::uint32_t kFileActionOverwritten = 3U;

constexpr std::uint32_t kDesiredAccessDelete = 0x00010000U;
constexpr std::uint8_t kInfoTypeFile = 0x01U;
constexpr std::uint8_t kFileRenameInformationClass = 0x0AU;
constexpr std::uint8_t kFileDispositionInformationClass = 0x0DU;
constexpr std::uint8_t kFileDispositionInformationExClass = 0x40U;
constexpr std::uint32_t kDispositionDeleteFlag = 0x00000001U;
constexpr std::uint32_t kFsctlDfsGetReferrals = 0x00060194U;
constexpr std::uint32_t kFsctlLmrRequestResiliency = 0x001401D4U;
constexpr std::uint32_t kFsctlQueryNetworkInterfaceInfo = 0x001401FCU;
constexpr std::uint32_t kFsctlValidateNegotiateInfo = 0x00140204U;

bool read_wire_u16(const std::vector<std::uint8_t>& frame, std::size_t offset, std::uint16_t& out) {
    if ((offset + 2U) > frame.size()) {
        return false;
    }
    out = static_cast<std::uint16_t>(frame[offset]) |
          static_cast<std::uint16_t>(static_cast<std::uint16_t>(frame[offset + 1U]) << 8U);
    return true;
}

bool read_wire_u32(const std::vector<std::uint8_t>& frame, std::size_t offset, std::uint32_t& out) {
    if ((offset + 4U) > frame.size()) {
        return false;
    }
    out = static_cast<std::uint32_t>(frame[offset]) |
          (static_cast<std::uint32_t>(frame[offset + 1U]) << 8U) |
          (static_cast<std::uint32_t>(frame[offset + 2U]) << 16U) |
          (static_cast<std::uint32_t>(frame[offset + 3U]) << 24U);
    return true;
}

bool read_wire_u64(const std::vector<std::uint8_t>& frame, std::size_t offset, std::uint64_t& out) {
    std::uint32_t lo = 0U;
    std::uint32_t hi = 0U;
    if (!read_wire_u32(frame, offset, lo) || !read_wire_u32(frame, offset + 4U, hi)) {
        return false;
    }
    out = static_cast<std::uint64_t>(lo) | (static_cast<std::uint64_t>(hi) << 32U);
    return true;
}

bool decode_utf16le_ascii(const std::uint8_t* data, std::size_t size, std::string& out) {
    SMB_EXPECT(data != nullptr);
    if ((size == 0U) || ((size % 2U) != 0U)) {
        return false;
    }
    std::string decoded{};
    decoded.reserve(size / 2U);
    for (std::size_t i = 0U; i < size; i += 2U) {
        const std::uint16_t ch =
            static_cast<std::uint16_t>(data[i]) | static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[i + 1U]) << 8U);
        if (ch == 0U) {
            continue;
        }
        if ((ch < 0x20U) || (ch > 0x7EU)) {
            return false;
        }
        char c = static_cast<char>(ch & 0x7FU);
        if (c == '\\') {
            c = '/';
        }
        decoded.push_back(c);
    }
    if (decoded.empty()) {
        return false;
    }
    out = decoded;
    return true;
}

bool normalize_relative_path(const std::string& raw, std::string& normalized) {
    if (raw.empty()) {
        return false;
    }

    std::vector<std::string> parts{};
    std::size_t start = 0U;
    while (start < raw.size()) {
        while ((start < raw.size()) && (raw[start] == '/')) {
            ++start;
        }
        if (start >= raw.size()) {
            break;
        }
        std::size_t end = start;
        while ((end < raw.size()) && (raw[end] != '/')) {
            ++end;
        }
        const std::string part = raw.substr(start, end - start);
        if (part.empty() || (part == ".") || (part == "..")) {
            return false;
        }
        if (part.find(':') != std::string::npos) {
            return false;
        }
        parts.push_back(part);
        start = end;
    }

    if (parts.empty()) {
        return false;
    }

    std::string out{};
    for (std::size_t i = 0U; i < parts.size(); ++i) {
        if (i > 0U) {
            out.push_back('/');
        }
        out += parts[i];
    }
    if (out.empty()) {
        return false;
    }
    normalized = out;
    return true;
}

bool has_hidden_path_component(const std::string& normalized_rel_path) {
    std::size_t start = 0U;
    while (start < normalized_rel_path.size()) {
        std::size_t end = normalized_rel_path.find('/', start);
        if (end == std::string::npos) {
            end = normalized_rel_path.size();
        }
        if ((end > start) && (normalized_rel_path[start] == '.')) {
            return true;
        }
        start = end + 1U;
    }
    return false;
}

bool contains_wildcards(const std::string& path) {
    return (path.find('*') != std::string::npos) || (path.find('?') != std::string::npos);
}

bool path_has_prefix(const std::filesystem::path& base, const std::filesystem::path& target) {
    auto b_it = base.begin();
    auto t_it = target.begin();
    for (; b_it != base.end(); ++b_it, ++t_it) {
        if ((t_it == target.end()) || (*b_it != *t_it)) {
            return false;
        }
    }
    return true;
}

bool resolve_share_file_path(const std::string& share_dir,
                             const std::string& relative_path,
                             bool for_create,
                             bool deny_dot_files,
                             std::string& full_path) {
    if (relative_path.empty()) {
        std::error_code ec{};
        const std::filesystem::path base =
            std::filesystem::weakly_canonical(std::filesystem::path(share_dir).lexically_normal(), ec);
        if (ec) {
            return false;
        }
        full_path = base.string();
        return !full_path.empty();
    }
    std::string normalized_rel{};
    if (!normalize_relative_path(relative_path, normalized_rel)) {
        return false;
    }
    if (deny_dot_files && has_hidden_path_component(normalized_rel)) {
        return false;
    }

    std::error_code ec{};
    const std::filesystem::path base =
        std::filesystem::weakly_canonical(std::filesystem::path(share_dir).lexically_normal(), ec);
    if (ec) {
        return false;
    }
    const std::filesystem::path candidate_raw = (base / normalized_rel).lexically_normal();
    const std::filesystem::path parent_resolved = std::filesystem::weakly_canonical(candidate_raw.parent_path(), ec);
    if (ec || !path_has_prefix(base, parent_resolved)) {
        return false;
    }
    std::filesystem::path candidate = (parent_resolved / candidate_raw.filename()).lexically_normal();

    const bool exists = std::filesystem::exists(candidate, ec);
    if (ec) {
        return false;
    }
    if (exists) {
        const bool is_symlink = std::filesystem::is_symlink(candidate, ec);
        if (ec || is_symlink) {
            return false;
        }
        const std::filesystem::path resolved_existing = std::filesystem::weakly_canonical(candidate, ec);
        if (ec || !path_has_prefix(base, resolved_existing)) {
            return false;
        }
        candidate = resolved_existing;
    } else if (!for_create) {
        return false;
    }

    full_path = candidate.string();
    return !full_path.empty();
}

bool close_open_file_entry(ConnectionState::OpenFileHandle& entry) {
    bool ok = true;
    if (entry.stream != nullptr) {
        ok = (std::fclose(entry.stream) == 0);
        entry.stream = nullptr;
    }
    return ok;
}

void close_all_open_files(ConnectionState& state) {
    for (auto& kv : state.open_files) {
        (void)close_open_file_entry(kv.second);
    }
    state.open_files.clear();
}

void trim_open_directory_handles(ConnectionState& state, std::size_t target_max_open_files) {
    const auto trim_pass = [&](bool require_listing_sent) {
        for (auto it = state.open_files.begin();
             (it != state.open_files.end()) && (state.open_files.size() > target_max_open_files);) {
            ConnectionState::OpenFileHandle& handle = it->second;
            if (!handle.is_directory) {
                ++it;
                continue;
            }
            if (require_listing_sent && !handle.directory_listing_sent) {
                ++it;
                continue;
            }
            (void)close_open_file_entry(handle);
            it = state.open_files.erase(it);
        }
    };

    trim_pass(true);
    trim_pass(false);
}

ConnectionState::OpenFileHandle* find_open_file(ConnectionState& state, const FileIdPair& file_id) {
    const auto it = state.open_files.find(file_id.persistent_id);
    if (it == state.open_files.end()) {
        return nullptr;
    }
    if (it->second.volatile_id != file_id.volatile_id) {
        return nullptr;
    }
    return &it->second;
}

bool seek_file(std::FILE* stream, std::uint64_t offset) {
    SMB_EXPECT(stream != nullptr);
    if (offset > static_cast<std::uint64_t>(LONG_MAX)) {
        return false;
    }
    return std::fseek(stream, static_cast<long>(offset), SEEK_SET) == 0;
}

std::optional<std::uint64_t> query_file_size(std::FILE* stream) {
    SMB_EXPECT(stream != nullptr);
    const long original = std::ftell(stream);
    if (original < 0L) {
        return std::nullopt;
    }
    if (std::fseek(stream, 0L, SEEK_END) != 0) {
        return std::nullopt;
    }
    const long end = std::ftell(stream);
    if (end < 0L) {
        return std::nullopt;
    }
    if (std::fseek(stream, original, SEEK_SET) != 0) {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(end);
}

bool parse_tree_connect_request(const std::vector<std::uint8_t>& frame, TreeConnectRequestFields& out) {
    if (frame.size() < (sizeof(Smb2Header) + 8U)) {
        return false;
    }
    std::uint16_t structure_size = 0U;
    std::uint16_t path_offset = 0U;
    std::uint16_t path_length = 0U;
    if (!read_wire_u16(frame, sizeof(Smb2Header), structure_size) ||
        !read_wire_u16(frame, sizeof(Smb2Header) + 4U, path_offset) ||
        !read_wire_u16(frame, sizeof(Smb2Header) + 6U, path_length)) {
        return false;
    }
    if ((structure_size != 9U) || (path_length == 0U)) {
        return false;
    }
    const std::size_t end = static_cast<std::size_t>(path_offset) + static_cast<std::size_t>(path_length);
    if (end > frame.size()) {
        return false;
    }
    return decode_utf16le_ascii(frame.data() + static_cast<std::size_t>(path_offset),
                                static_cast<std::size_t>(path_length),
                                out.share_path);
}

bool validate_tree_disconnect_request(const std::vector<std::uint8_t>& frame) {
    if (frame.size() < (sizeof(Smb2Header) + 4U)) {
        return false;
    }
    std::uint16_t structure_size = 0U;
    if (!read_wire_u16(frame, sizeof(Smb2Header), structure_size)) {
        return false;
    }
    return (structure_size == 4U) || (structure_size == 0U);
}

bool validate_logoff_request(const std::vector<std::uint8_t>& frame) {
    if (frame.size() < (sizeof(Smb2Header) + 4U)) {
        return false;
    }
    std::uint16_t structure_size = 0U;
    if (!read_wire_u16(frame, sizeof(Smb2Header), structure_size)) {
        return false;
    }
    return (structure_size == 4U) || (structure_size == 0U);
}

bool parse_create_request(const std::vector<std::uint8_t>& frame, CreateRequestFields& out) {
    if (frame.size() < (sizeof(Smb2Header) + 56U)) {
        return false;
    }
    std::uint16_t structure_size = 0U;
    std::uint32_t desired_access = 0U;
    std::uint32_t create_disposition = 0U;
    std::uint32_t create_options = 0U;
    std::uint16_t name_offset = 0U;
    std::uint16_t name_length = 0U;
    if (!read_wire_u16(frame, sizeof(Smb2Header), structure_size) ||
        !read_wire_u32(frame, sizeof(Smb2Header) + 24U, desired_access) ||
        !read_wire_u32(frame, sizeof(Smb2Header) + 36U, create_disposition) ||
        !read_wire_u32(frame, sizeof(Smb2Header) + 40U, create_options) ||
        !read_wire_u16(frame, sizeof(Smb2Header) + 44U, name_offset) ||
        !read_wire_u16(frame, sizeof(Smb2Header) + 46U, name_length)) {
        return false;
    }
    if (structure_size != 57U) {
        return false;
    }
    if (create_disposition > kFileOverwriteIf) {
        return false;
    }
    std::string decoded_name{};
    if (name_length > 0U) {
        const std::size_t end = static_cast<std::size_t>(name_offset) + static_cast<std::size_t>(name_length);
        if (end > frame.size()) {
            return false;
        }
        if (!decode_utf16le_ascii(frame.data() + static_cast<std::size_t>(name_offset),
                                  static_cast<std::size_t>(name_length),
                                  decoded_name)) {
            return false;
        }
    }

    out.desired_access = desired_access;
    out.create_disposition = create_disposition;
    out.create_options = create_options;
    out.relative_path = decoded_name;
    return true;
}

bool parse_close_request(const std::vector<std::uint8_t>& frame, FileIdPair& out) {
    if (frame.size() < (sizeof(Smb2Header) + 24U)) {
        return false;
    }
    std::uint16_t structure_size = 0U;
    if (!read_wire_u16(frame, sizeof(Smb2Header), structure_size)) {
        return false;
    }
    if (structure_size != 24U) {
        return false;
    }
    if (!read_wire_u64(frame, sizeof(Smb2Header) + 8U, out.persistent_id) ||
        !read_wire_u64(frame, sizeof(Smb2Header) + 16U, out.volatile_id)) {
        return false;
    }
    return true;
}

bool parse_flush_request(const std::vector<std::uint8_t>& frame, FileIdPair& out) {
    if (frame.size() < (sizeof(Smb2Header) + 24U)) {
        return false;
    }
    std::uint16_t structure_size = 0U;
    if (!read_wire_u16(frame, sizeof(Smb2Header), structure_size)) {
        return false;
    }
    if (structure_size != 24U) {
        return false;
    }
    if (!read_wire_u64(frame, sizeof(Smb2Header) + 8U, out.persistent_id) ||
        !read_wire_u64(frame, sizeof(Smb2Header) + 16U, out.volatile_id)) {
        return false;
    }
    return true;
}

bool parse_echo_request(const std::vector<std::uint8_t>& frame) {
    if (frame.size() < (sizeof(Smb2Header) + 4U)) {
        return false;
    }
    std::uint16_t structure_size = 0U;
    if (!read_wire_u16(frame, sizeof(Smb2Header), structure_size)) {
        return false;
    }
    return structure_size == 4U;
}

bool parse_lock_request(const std::vector<std::uint8_t>& frame, LockRequestFields& out) {
    out = LockRequestFields{};
    if (frame.size() < (sizeof(Smb2Header) + 48U)) {
        return false;
    }
    std::uint16_t structure_size = 0U;
    std::uint16_t lock_count = 0U;
    if (!read_wire_u16(frame, sizeof(Smb2Header), structure_size) ||
        !read_wire_u16(frame, sizeof(Smb2Header) + 2U, lock_count) ||
        !read_wire_u64(frame, sizeof(Smb2Header) + 8U, out.file_id.persistent_id) ||
        !read_wire_u64(frame, sizeof(Smb2Header) + 16U, out.file_id.volatile_id)) {
        return false;
    }
    if ((structure_size != 48U) || (lock_count == 0U)) {
        return false;
    }
    const std::size_t lock_bytes = static_cast<std::size_t>(lock_count) * 24U;
    const std::size_t end = sizeof(Smb2Header) + 24U + lock_bytes;
    if (end > frame.size()) {
        return false;
    }
    out.lock_count = lock_count;
    return true;
}

bool parse_ioctl_request(const std::vector<std::uint8_t>& frame, IoctlRequestFields& out) {
    out = IoctlRequestFields{};
    if (frame.size() < (sizeof(Smb2Header) + 56U)) {
        return false;
    }
    std::uint16_t structure_size = 0U;
    std::uint32_t input_offset = 0U;
    std::uint32_t input_count = 0U;
    if (!read_wire_u16(frame, sizeof(Smb2Header), structure_size) ||
        !read_wire_u32(frame, sizeof(Smb2Header) + 4U, out.ctl_code) ||
        !read_wire_u64(frame, sizeof(Smb2Header) + 8U, out.file_id.persistent_id) ||
        !read_wire_u64(frame, sizeof(Smb2Header) + 16U, out.file_id.volatile_id) ||
        !read_wire_u32(frame, sizeof(Smb2Header) + 24U, input_offset) ||
        !read_wire_u32(frame, sizeof(Smb2Header) + 28U, input_count) ||
        !read_wire_u32(frame, sizeof(Smb2Header) + 40U, out.max_output_response) ||
        !read_wire_u32(frame, sizeof(Smb2Header) + 48U, out.flags)) {
        return false;
    }
    if (structure_size != 57U) {
        return false;
    }
    if (input_count == 0U) {
        out.input_data = nullptr;
        out.input_len = 0U;
        return true;
    }
    const std::size_t begin = static_cast<std::size_t>(input_offset);
    const std::size_t end = begin + static_cast<std::size_t>(input_count);
    if ((begin < (sizeof(Smb2Header) + 56U)) || (end > frame.size())) {
        return false;
    }
    out.input_data = frame.data() + begin;
    out.input_len = static_cast<std::size_t>(input_count);
    return true;
}

bool parse_cancel_request(const std::vector<std::uint8_t>& frame) {
    if (frame.size() < (sizeof(Smb2Header) + 4U)) {
        return false;
    }
    std::uint16_t structure_size = 0U;
    if (!read_wire_u16(frame, sizeof(Smb2Header), structure_size)) {
        return false;
    }
    return (structure_size == 4U) || (structure_size == 0U);
}

bool parse_change_notify_request(const std::vector<std::uint8_t>& frame, ChangeNotifyRequestFields& out) {
    out = ChangeNotifyRequestFields{};
    if (frame.size() < (sizeof(Smb2Header) + 32U)) {
        return false;
    }
    std::uint16_t structure_size = 0U;
    if (!read_wire_u16(frame, sizeof(Smb2Header), structure_size) ||
        !read_wire_u16(frame, sizeof(Smb2Header) + 2U, out.flags) ||
        !read_wire_u32(frame, sizeof(Smb2Header) + 4U, out.output_buffer_length) ||
        !read_wire_u64(frame, sizeof(Smb2Header) + 8U, out.file_id.persistent_id) ||
        !read_wire_u64(frame, sizeof(Smb2Header) + 16U, out.file_id.volatile_id) ||
        !read_wire_u32(frame, sizeof(Smb2Header) + 24U, out.completion_filter)) {
        return false;
    }
    if ((structure_size != 32U) || (out.output_buffer_length == 0U)) {
        return false;
    }
    return true;
}

bool parse_oplock_break_request(const std::vector<std::uint8_t>& frame, OplockBreakRequestFields& out) {
    out = OplockBreakRequestFields{};
    if (frame.size() < (sizeof(Smb2Header) + 24U)) {
        return false;
    }
    if (!read_wire_u16(frame, sizeof(Smb2Header), out.structure_size)) {
        return false;
    }
    if ((out.structure_size != 24U) && (out.structure_size != 36U) && (out.structure_size != 44U)) {
        return false;
    }
    if (frame.size() < (sizeof(Smb2Header) + static_cast<std::size_t>(out.structure_size))) {
        return false;
    }
    out.oplock_level = frame[sizeof(Smb2Header) + 2U];
    if (!read_wire_u64(frame, sizeof(Smb2Header) + 8U, out.file_id.persistent_id) ||
        !read_wire_u64(frame, sizeof(Smb2Header) + 16U, out.file_id.volatile_id)) {
        return false;
    }
    return true;
}

bool parse_write_request(const std::vector<std::uint8_t>& frame, WriteRequestFields& out) {
    if (frame.size() < (sizeof(Smb2Header) + 48U)) {
        return false;
    }
    std::uint16_t structure_size = 0U;
    std::uint16_t data_offset = 0U;
    if (!read_wire_u16(frame, sizeof(Smb2Header), structure_size) ||
        !read_wire_u16(frame, sizeof(Smb2Header) + 2U, data_offset) ||
        !read_wire_u32(frame, sizeof(Smb2Header) + 4U, out.length) ||
        !read_wire_u64(frame, sizeof(Smb2Header) + 8U, out.offset) ||
        !read_wire_u64(frame, sizeof(Smb2Header) + 16U, out.file_id.persistent_id) ||
        !read_wire_u64(frame, sizeof(Smb2Header) + 24U, out.file_id.volatile_id)) {
        return false;
    }
    if ((structure_size != 49U) || (out.length == 0U)) {
        return false;
    }
    out.data_offset = static_cast<std::size_t>(data_offset);
    const std::size_t end = out.data_offset + static_cast<std::size_t>(out.length);
    if ((out.data_offset < (sizeof(Smb2Header) + 48U)) || (end > frame.size())) {
        return false;
    }
    return true;
}

bool parse_read_request(const std::vector<std::uint8_t>& frame, ReadRequestFields& out) {
    if (frame.size() < (sizeof(Smb2Header) + 48U)) {
        return false;
    }
    std::uint16_t structure_size = 0U;
    if (!read_wire_u16(frame, sizeof(Smb2Header), structure_size) ||
        !read_wire_u32(frame, sizeof(Smb2Header) + 4U, out.length) ||
        !read_wire_u64(frame, sizeof(Smb2Header) + 8U, out.offset) ||
        !read_wire_u64(frame, sizeof(Smb2Header) + 16U, out.file_id.persistent_id) ||
        !read_wire_u64(frame, sizeof(Smb2Header) + 24U, out.file_id.volatile_id)) {
        return false;
    }
    if ((structure_size != 49U) || (out.length == 0U) || (out.length > static_cast<std::uint32_t>(kSmbMaxFrameBytes))) {
        return false;
    }
    return true;
}

bool parse_query_info_request(const std::vector<std::uint8_t>& frame,
                              std::uint8_t& info_type,
                              std::uint8_t& info_class,
                              FileIdPair& file_id) {
    if (frame.size() < (sizeof(Smb2Header) + 40U)) {
        return false;
    }
    std::uint16_t structure_size = 0U;
    if (!read_wire_u16(frame, sizeof(Smb2Header), structure_size)) {
        return false;
    }
    if (structure_size != 41U) {
        return false;
    }
    info_type = frame[sizeof(Smb2Header) + 2U];
    info_class = frame[sizeof(Smb2Header) + 3U];
    if (!read_wire_u64(frame, sizeof(Smb2Header) + 24U, file_id.persistent_id) ||
        !read_wire_u64(frame, sizeof(Smb2Header) + 32U, file_id.volatile_id)) {
        return false;
    }
    return true;
}

bool parse_set_info_request(const std::vector<std::uint8_t>& frame, SetInfoRequestFields& out) {
    out = SetInfoRequestFields{};
    if (frame.size() < (sizeof(Smb2Header) + 32U)) {
        return false;
    }
    std::uint16_t structure_size = 0U;
    std::uint32_t buffer_length = 0U;
    std::uint16_t buffer_offset = 0U;
    if (!read_wire_u16(frame, sizeof(Smb2Header), structure_size) ||
        !read_wire_u32(frame, sizeof(Smb2Header) + 4U, buffer_length) ||
        !read_wire_u16(frame, sizeof(Smb2Header) + 8U, buffer_offset) ||
        !read_wire_u32(frame, sizeof(Smb2Header) + 12U, out.additional_info) ||
        !read_wire_u64(frame, sizeof(Smb2Header) + 16U, out.file_id.persistent_id) ||
        !read_wire_u64(frame, sizeof(Smb2Header) + 24U, out.file_id.volatile_id)) {
        return false;
    }
    if (structure_size != 33U) {
        return false;
    }
    out.info_type = frame[sizeof(Smb2Header) + 2U];
    out.file_info_class = frame[sizeof(Smb2Header) + 3U];

    if (buffer_length == 0U) {
        out.buffer_data = nullptr;
        out.buffer_len = 0U;
        return true;
    }

    const std::size_t begin = static_cast<std::size_t>(buffer_offset);
    const std::size_t end = begin + static_cast<std::size_t>(buffer_length);
    if ((begin < (sizeof(Smb2Header) + 32U)) || (end > frame.size())) {
        return false;
    }
    out.buffer_data = frame.data() + begin;
    out.buffer_len = static_cast<std::size_t>(buffer_length);
    return true;
}

bool parse_set_info_rename_target(const SetInfoRequestFields& req,
                                  bool& replace_if_exists,
                                  std::string& target_relative_path) {
    if ((req.buffer_data == nullptr) || (req.buffer_len < 20U)) {
        return false;
    }
    replace_if_exists = req.buffer_data[0] != 0U;
    const std::uint32_t name_length = static_cast<std::uint32_t>(req.buffer_data[16U]) |
                                      (static_cast<std::uint32_t>(req.buffer_data[17U]) << 8U) |
                                      (static_cast<std::uint32_t>(req.buffer_data[18U]) << 16U) |
                                      (static_cast<std::uint32_t>(req.buffer_data[19U]) << 24U);
    if (name_length == 0U) {
        return false;
    }
    const std::size_t name_offset = 20U;
    const std::size_t name_end = name_offset + static_cast<std::size_t>(name_length);
    if (name_end > req.buffer_len) {
        return false;
    }
    return decode_utf16le_ascii(req.buffer_data + name_offset, static_cast<std::size_t>(name_length), target_relative_path);
}

bool parse_query_directory_request(const std::vector<std::uint8_t>& frame, QueryDirectoryRequestFields& out) {
    if (frame.size() < (sizeof(Smb2Header) + 32U)) {
        return false;
    }
    std::uint16_t structure_size = 0U;
    std::uint16_t file_name_offset = 0U;
    std::uint16_t file_name_length = 0U;
    if (!read_wire_u16(frame, sizeof(Smb2Header), structure_size)) {
        return false;
    }
    if (structure_size != 33U) {
        return false;
    }
    out.file_info_class = frame[sizeof(Smb2Header) + 2U];
    out.flags = frame[sizeof(Smb2Header) + 3U];
    if (!read_wire_u64(frame, sizeof(Smb2Header) + 8U, out.file_id.persistent_id) ||
        !read_wire_u64(frame, sizeof(Smb2Header) + 16U, out.file_id.volatile_id) ||
        !read_wire_u16(frame, sizeof(Smb2Header) + 24U, file_name_offset) ||
        !read_wire_u16(frame, sizeof(Smb2Header) + 26U, file_name_length) ||
        !read_wire_u32(frame, sizeof(Smb2Header) + 28U, out.output_buffer_length)) {
        return false;
    }
    if (out.output_buffer_length == 0U) {
        return false;
    }
    out.file_name_pattern = "*";
    if (file_name_length == 0U) {
        return true;
    }
    const std::size_t name_end =
        static_cast<std::size_t>(file_name_offset) + static_cast<std::size_t>(file_name_length);
    if ((file_name_offset < static_cast<std::uint16_t>(sizeof(Smb2Header) + 32U)) || (name_end > frame.size())) {
        return false;
    }
    std::string decoded_name{};
    if (!decode_utf16le_ascii(frame.data() + static_cast<std::size_t>(file_name_offset),
                              static_cast<std::size_t>(file_name_length),
                              decoded_name)) {
        return false;
    }
    out.file_name_pattern = decoded_name;
    return true;
}

std::vector<std::uint8_t> build_tree_connect_response(std::uint64_t message_id,
                                                      std::uint64_t session_id,
                                                      std::uint32_t tree_id) {
    const Smb2Header hdr = make_response_header(static_cast<std::uint16_t>(Smb2Command::TreeConnect),
                                                message_id,
                                                kStatusSuccess,
                                                session_id,
                                                tree_id);
    std::vector<std::uint8_t> packet(sizeof(Smb2Header) + 16U, 0U);
    std::memcpy(packet.data(), &hdr, sizeof(Smb2Header));
    const std::uint16_t structure_size = to_le16(16U);
    const std::uint32_t share_flags = to_le32(0U);
    const std::uint32_t capabilities = to_le32(0U);
    const std::uint32_t maximal_access = to_le32(0x001F01FFU);
    std::memcpy(packet.data() + sizeof(Smb2Header), &structure_size, sizeof(structure_size));
    packet[sizeof(Smb2Header) + 2U] = 0x01U;  // disk share
    packet[sizeof(Smb2Header) + 3U] = 0U;
    std::memcpy(packet.data() + sizeof(Smb2Header) + 4U, &share_flags, sizeof(share_flags));
    std::memcpy(packet.data() + sizeof(Smb2Header) + 8U, &capabilities, sizeof(capabilities));
    std::memcpy(packet.data() + sizeof(Smb2Header) + 12U, &maximal_access, sizeof(maximal_access));
    return packet;
}

std::vector<std::uint8_t> build_tree_disconnect_response(std::uint64_t message_id,
                                                         std::uint64_t session_id,
                                                         std::uint32_t tree_id) {
    const Smb2Header hdr = make_response_header(static_cast<std::uint16_t>(Smb2Command::TreeDisconnect),
                                                message_id,
                                                kStatusSuccess,
                                                session_id,
                                                tree_id);
    std::vector<std::uint8_t> packet(sizeof(Smb2Header) + 4U, 0U);
    std::memcpy(packet.data(), &hdr, sizeof(Smb2Header));
    const std::uint16_t structure_size = to_le16(4U);
    const std::uint16_t reserved = to_le16(0U);
    std::memcpy(packet.data() + sizeof(Smb2Header), &structure_size, sizeof(structure_size));
    std::memcpy(packet.data() + sizeof(Smb2Header) + 2U, &reserved, sizeof(reserved));
    return packet;
}

std::vector<std::uint8_t> build_logoff_response(std::uint64_t message_id, std::uint64_t session_id) {
    const Smb2Header hdr =
        make_response_header(static_cast<std::uint16_t>(Smb2Command::Logoff), message_id, kStatusSuccess, session_id, 0U);
    std::vector<std::uint8_t> packet(sizeof(Smb2Header) + 4U, 0U);
    std::memcpy(packet.data(), &hdr, sizeof(Smb2Header));
    const std::uint16_t structure_size = to_le16(4U);
    const std::uint16_t reserved = to_le16(0U);
    std::memcpy(packet.data() + sizeof(Smb2Header), &structure_size, sizeof(structure_size));
    std::memcpy(packet.data() + sizeof(Smb2Header) + 2U, &reserved, sizeof(reserved));
    return packet;
}

std::vector<std::uint8_t> build_create_response(std::uint64_t message_id,
                                                std::uint64_t session_id,
                                                std::uint32_t tree_id,
                                                const FileIdPair& file_id,
                                                std::uint32_t create_action,
                                                std::uint64_t file_size_bytes,
                                                bool is_directory = false) {
    const Smb2Header hdr = make_response_header(static_cast<std::uint16_t>(Smb2Command::Create),
                                                message_id,
                                                kStatusSuccess,
                                                session_id,
                                                tree_id);
    std::vector<std::uint8_t> packet(sizeof(Smb2Header) + 88U, 0U);
    std::memcpy(packet.data(), &hdr, sizeof(Smb2Header));

    const std::uint16_t structure_size = to_le16(89U);
    const std::uint32_t action_le = to_le32(create_action);
    const std::uint64_t now_ft = to_le64(now_windows_filetime_utc());
    const std::uint64_t alloc_size = to_le64(file_size_bytes);
    const std::uint64_t eof_size = to_le64(file_size_bytes);
    const std::uint32_t file_attributes = to_le32(is_directory ? 0x00000010U : 0x00000080U);
    const std::uint32_t reserved = to_le32(0U);
    const std::uint64_t persistent = to_le64(file_id.persistent_id);
    const std::uint64_t volatile_id = to_le64(file_id.volatile_id);
    const std::uint32_t contexts_offset = to_le32(0U);
    const std::uint32_t contexts_length = to_le32(0U);

    std::uint8_t* body = packet.data() + sizeof(Smb2Header);
    std::memcpy(body + 0U, &structure_size, sizeof(structure_size));
    body[2U] = 0U;
    body[3U] = 0U;
    std::memcpy(body + 4U, &action_le, sizeof(action_le));
    std::memcpy(body + 8U, &now_ft, sizeof(now_ft));
    std::memcpy(body + 16U, &now_ft, sizeof(now_ft));
    std::memcpy(body + 24U, &now_ft, sizeof(now_ft));
    std::memcpy(body + 32U, &now_ft, sizeof(now_ft));
    std::memcpy(body + 40U, &alloc_size, sizeof(alloc_size));
    std::memcpy(body + 48U, &eof_size, sizeof(eof_size));
    std::memcpy(body + 56U, &file_attributes, sizeof(file_attributes));
    std::memcpy(body + 60U, &reserved, sizeof(reserved));
    std::memcpy(body + 64U, &persistent, sizeof(persistent));
    std::memcpy(body + 72U, &volatile_id, sizeof(volatile_id));
    std::memcpy(body + 80U, &contexts_offset, sizeof(contexts_offset));
    std::memcpy(body + 84U, &contexts_length, sizeof(contexts_length));
    return packet;
}

std::vector<std::uint8_t> build_close_response(std::uint64_t message_id,
                                               std::uint64_t session_id,
                                               std::uint32_t tree_id,
                                               std::uint64_t file_size_bytes) {
    const Smb2Header hdr = make_response_header(static_cast<std::uint16_t>(Smb2Command::Close),
                                                message_id,
                                                kStatusSuccess,
                                                session_id,
                                                tree_id);
    std::vector<std::uint8_t> packet(sizeof(Smb2Header) + 60U, 0U);
    std::memcpy(packet.data(), &hdr, sizeof(Smb2Header));

    const std::uint16_t structure_size = to_le16(60U);
    const std::uint16_t flags = to_le16(0U);
    const std::uint32_t reserved = to_le32(0U);
    const std::uint64_t now_ft = to_le64(now_windows_filetime_utc());
    const std::uint64_t alloc_size = to_le64(file_size_bytes);
    const std::uint64_t eof_size = to_le64(file_size_bytes);
    const std::uint32_t file_attributes = to_le32(0x00000080U);

    std::uint8_t* body = packet.data() + sizeof(Smb2Header);
    std::memcpy(body + 0U, &structure_size, sizeof(structure_size));
    std::memcpy(body + 2U, &flags, sizeof(flags));
    std::memcpy(body + 4U, &reserved, sizeof(reserved));
    std::memcpy(body + 8U, &now_ft, sizeof(now_ft));
    std::memcpy(body + 16U, &now_ft, sizeof(now_ft));
    std::memcpy(body + 24U, &now_ft, sizeof(now_ft));
    std::memcpy(body + 32U, &now_ft, sizeof(now_ft));
    std::memcpy(body + 40U, &alloc_size, sizeof(alloc_size));
    std::memcpy(body + 48U, &eof_size, sizeof(eof_size));
    std::memcpy(body + 56U, &file_attributes, sizeof(file_attributes));
    return packet;
}

std::vector<std::uint8_t> build_flush_response(std::uint64_t message_id,
                                               std::uint64_t session_id,
                                               std::uint32_t tree_id) {
    const Smb2Header hdr = make_response_header(static_cast<std::uint16_t>(Smb2Command::Flush),
                                                message_id,
                                                kStatusSuccess,
                                                session_id,
                                                tree_id);
    std::vector<std::uint8_t> packet(sizeof(Smb2Header) + 4U, 0U);
    std::memcpy(packet.data(), &hdr, sizeof(Smb2Header));
    const std::uint16_t structure_size = to_le16(4U);
    const std::uint16_t reserved = to_le16(0U);
    std::memcpy(packet.data() + sizeof(Smb2Header), &structure_size, sizeof(structure_size));
    std::memcpy(packet.data() + sizeof(Smb2Header) + 2U, &reserved, sizeof(reserved));
    return packet;
}

std::vector<std::uint8_t> build_echo_response(std::uint64_t message_id,
                                              std::uint64_t session_id,
                                              std::uint32_t tree_id) {
    const Smb2Header hdr = make_response_header(static_cast<std::uint16_t>(Smb2Command::Echo),
                                                message_id,
                                                kStatusSuccess,
                                                session_id,
                                                tree_id);
    std::vector<std::uint8_t> packet(sizeof(Smb2Header) + 4U, 0U);
    std::memcpy(packet.data(), &hdr, sizeof(Smb2Header));
    const std::uint16_t structure_size = to_le16(4U);
    const std::uint16_t reserved = to_le16(0U);
    std::memcpy(packet.data() + sizeof(Smb2Header), &structure_size, sizeof(structure_size));
    std::memcpy(packet.data() + sizeof(Smb2Header) + 2U, &reserved, sizeof(reserved));
    return packet;
}

std::vector<std::uint8_t> build_lock_response(std::uint64_t message_id,
                                              std::uint64_t session_id,
                                              std::uint32_t tree_id) {
    const Smb2Header hdr = make_response_header(static_cast<std::uint16_t>(Smb2Command::Lock),
                                                message_id,
                                                kStatusSuccess,
                                                session_id,
                                                tree_id);
    std::vector<std::uint8_t> packet(sizeof(Smb2Header) + 4U, 0U);
    std::memcpy(packet.data(), &hdr, sizeof(Smb2Header));
    const std::uint16_t structure_size = to_le16(4U);
    const std::uint16_t reserved = to_le16(0U);
    std::memcpy(packet.data() + sizeof(Smb2Header), &structure_size, sizeof(structure_size));
    std::memcpy(packet.data() + sizeof(Smb2Header) + 2U, &reserved, sizeof(reserved));
    return packet;
}

std::vector<std::uint8_t> build_cancel_response(std::uint64_t message_id,
                                                std::uint64_t session_id,
                                                std::uint32_t tree_id) {
    const Smb2Header hdr = make_response_header(static_cast<std::uint16_t>(Smb2Command::Cancel),
                                                message_id,
                                                kStatusSuccess,
                                                session_id,
                                                tree_id);
    std::vector<std::uint8_t> packet(sizeof(Smb2Header) + 4U, 0U);
    std::memcpy(packet.data(), &hdr, sizeof(Smb2Header));
    const std::uint16_t structure_size = to_le16(4U);
    const std::uint16_t reserved = to_le16(0U);
    std::memcpy(packet.data() + sizeof(Smb2Header), &structure_size, sizeof(structure_size));
    std::memcpy(packet.data() + sizeof(Smb2Header) + 2U, &reserved, sizeof(reserved));
    return packet;
}

std::vector<std::uint8_t> build_write_response(std::uint64_t message_id,
                                               std::uint64_t session_id,
                                               std::uint32_t tree_id,
                                               std::uint32_t count) {
    const Smb2Header hdr = make_response_header(static_cast<std::uint16_t>(Smb2Command::Write),
                                                message_id,
                                                kStatusSuccess,
                                                session_id,
                                                tree_id);
    std::vector<std::uint8_t> packet(sizeof(Smb2Header) + 16U, 0U);
    std::memcpy(packet.data(), &hdr, sizeof(Smb2Header));
    const std::uint16_t structure_size = to_le16(17U);
    const std::uint16_t reserved = to_le16(0U);
    const std::uint32_t count_le = to_le32(count);
    const std::uint32_t remaining = to_le32(0U);
    const std::uint16_t info_offset = to_le16(0U);
    const std::uint16_t info_length = to_le16(0U);
    std::uint8_t* body = packet.data() + sizeof(Smb2Header);
    std::memcpy(body + 0U, &structure_size, sizeof(structure_size));
    std::memcpy(body + 2U, &reserved, sizeof(reserved));
    std::memcpy(body + 4U, &count_le, sizeof(count_le));
    std::memcpy(body + 8U, &remaining, sizeof(remaining));
    std::memcpy(body + 12U, &info_offset, sizeof(info_offset));
    std::memcpy(body + 14U, &info_length, sizeof(info_length));
    return packet;
}

std::vector<std::uint8_t> build_read_response(std::uint64_t message_id,
                                              std::uint64_t session_id,
                                              std::uint32_t tree_id,
                                              const std::vector<std::uint8_t>& data) {
    const Smb2Header hdr = make_response_header(static_cast<std::uint16_t>(Smb2Command::Read),
                                                message_id,
                                                kStatusSuccess,
                                                session_id,
                                                tree_id);
    std::vector<std::uint8_t> packet(sizeof(Smb2Header) + 16U + data.size(), 0U);
    std::memcpy(packet.data(), &hdr, sizeof(Smb2Header));

    const std::uint16_t structure_size = to_le16(17U);
    const std::uint8_t data_offset = static_cast<std::uint8_t>(sizeof(Smb2Header) + 16U);
    const std::uint8_t reserved = 0U;
    const std::uint32_t data_length = to_le32(static_cast<std::uint32_t>(data.size()));
    const std::uint32_t data_remaining = to_le32(0U);
    const std::uint32_t reserved2 = to_le32(0U);

    std::uint8_t* body = packet.data() + sizeof(Smb2Header);
    std::memcpy(body + 0U, &structure_size, sizeof(structure_size));
    std::memcpy(body + 2U, &data_offset, sizeof(data_offset));
    std::memcpy(body + 3U, &reserved, sizeof(reserved));
    std::memcpy(body + 4U, &data_length, sizeof(data_length));
    std::memcpy(body + 8U, &data_remaining, sizeof(data_remaining));
    std::memcpy(body + 12U, &reserved2, sizeof(reserved2));
    if (!data.empty()) {
        std::memcpy(packet.data() + sizeof(Smb2Header) + 16U, data.data(), data.size());
    }
    return packet;
}

std::vector<std::uint8_t> build_query_info_response(std::uint64_t message_id,
                                                    std::uint64_t session_id,
                                                    std::uint32_t tree_id,
                                                    const std::vector<std::uint8_t>& info_data) {
    const Smb2Header hdr = make_response_header(static_cast<std::uint16_t>(Smb2Command::QueryInfo),
                                                message_id,
                                                kStatusSuccess,
                                                session_id,
                                                tree_id);
    std::vector<std::uint8_t> packet(sizeof(Smb2Header) + 8U + info_data.size(), 0U);
    std::memcpy(packet.data(), &hdr, sizeof(Smb2Header));

    const std::uint16_t structure_size = to_le16(9U);
    const std::uint16_t output_offset = to_le16(static_cast<std::uint16_t>(sizeof(Smb2Header) + 8U));
    SMB_EXPECT(info_data.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()));
    const std::uint32_t output_length = to_le32(static_cast<std::uint32_t>(info_data.size()));
    std::uint8_t* body = packet.data() + sizeof(Smb2Header);
    std::memcpy(body + 0U, &structure_size, sizeof(structure_size));
    std::memcpy(body + 2U, &output_offset, sizeof(output_offset));
    std::memcpy(body + 4U, &output_length, sizeof(output_length));
    if (!info_data.empty()) {
        std::memcpy(packet.data() + sizeof(Smb2Header) + 8U, info_data.data(), info_data.size());
    }
    return packet;
}

std::vector<std::uint8_t> build_set_info_response(std::uint64_t message_id,
                                                  std::uint64_t session_id,
                                                  std::uint32_t tree_id) {
    const Smb2Header hdr = make_response_header(static_cast<std::uint16_t>(Smb2Command::SetInfo),
                                                message_id,
                                                kStatusSuccess,
                                                session_id,
                                                tree_id);
    std::vector<std::uint8_t> packet(sizeof(Smb2Header) + 2U, 0U);
    std::memcpy(packet.data(), &hdr, sizeof(Smb2Header));
    const std::uint16_t structure_size = to_le16(2U);
    std::memcpy(packet.data() + sizeof(Smb2Header), &structure_size, sizeof(structure_size));
    return packet;
}

std::vector<std::uint8_t> build_query_directory_response(std::uint64_t message_id,
                                                         std::uint64_t session_id,
                                                         std::uint32_t tree_id,
                                                         const std::vector<std::uint8_t>& data) {
    const Smb2Header hdr = make_response_header(static_cast<std::uint16_t>(Smb2Command::QueryDirectory),
                                                message_id,
                                                kStatusSuccess,
                                                session_id,
                                                tree_id);
    std::vector<std::uint8_t> packet(sizeof(Smb2Header) + 8U + data.size(), 0U);
    std::memcpy(packet.data(), &hdr, sizeof(Smb2Header));

    const std::uint16_t structure_size = to_le16(9U);
    const std::uint16_t output_offset = to_le16(static_cast<std::uint16_t>(sizeof(Smb2Header) + 8U));
    SMB_EXPECT(data.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()));
    const std::uint32_t output_length = to_le32(static_cast<std::uint32_t>(data.size()));
    std::uint8_t* body = packet.data() + sizeof(Smb2Header);
    std::memcpy(body + 0U, &structure_size, sizeof(structure_size));
    std::memcpy(body + 2U, &output_offset, sizeof(output_offset));
    std::memcpy(body + 4U, &output_length, sizeof(output_length));
    if (!data.empty()) {
        std::memcpy(packet.data() + sizeof(Smb2Header) + 8U, data.data(), data.size());
    }
    return packet;
}

std::vector<std::uint8_t> build_change_notify_response(std::uint64_t message_id,
                                                       std::uint64_t session_id,
                                                       std::uint32_t tree_id,
                                                       const std::vector<std::uint8_t>& notify_data) {
    const Smb2Header hdr = make_response_header(static_cast<std::uint16_t>(Smb2Command::ChangeNotify),
                                                message_id,
                                                kStatusSuccess,
                                                session_id,
                                                tree_id);
    std::vector<std::uint8_t> packet(sizeof(Smb2Header) + 8U + notify_data.size(), 0U);
    std::memcpy(packet.data(), &hdr, sizeof(Smb2Header));
    const std::uint16_t structure_size = to_le16(9U);
    const std::uint16_t output_offset = notify_data.empty()
                                            ? to_le16(0U)
                                            : to_le16(static_cast<std::uint16_t>(sizeof(Smb2Header) + 8U));
    SMB_EXPECT(notify_data.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()));
    const std::uint32_t output_length = to_le32(static_cast<std::uint32_t>(notify_data.size()));
    std::uint8_t* body = packet.data() + sizeof(Smb2Header);
    std::memcpy(body + 0U, &structure_size, sizeof(structure_size));
    std::memcpy(body + 2U, &output_offset, sizeof(output_offset));
    std::memcpy(body + 4U, &output_length, sizeof(output_length));
    if (!notify_data.empty()) {
        std::memcpy(packet.data() + sizeof(Smb2Header) + 8U, notify_data.data(), notify_data.size());
    }
    return packet;
}

std::vector<std::uint8_t> build_ioctl_response(std::uint64_t message_id,
                                               std::uint64_t session_id,
                                               std::uint32_t tree_id,
                                               std::uint32_t ctl_code,
                                               const FileIdPair& file_id,
                                               std::uint32_t flags,
                                               const std::vector<std::uint8_t>& output_data) {
    const Smb2Header hdr = make_response_header(static_cast<std::uint16_t>(Smb2Command::Ioctl),
                                                message_id,
                                                kStatusSuccess,
                                                session_id,
                                                tree_id);
    std::vector<std::uint8_t> packet(sizeof(Smb2Header) + 48U + output_data.size(), 0U);
    std::memcpy(packet.data(), &hdr, sizeof(Smb2Header));
    const std::uint16_t structure_size = to_le16(49U);
    const std::uint16_t reserved = to_le16(0U);
    const std::uint32_t ctl_code_le = to_le32(ctl_code);
    const std::uint64_t file_id_persistent = to_le64(file_id.persistent_id);
    const std::uint64_t file_id_volatile = to_le64(file_id.volatile_id);
    const std::uint32_t input_offset = to_le32(0U);
    const std::uint32_t input_count = to_le32(0U);
    const std::uint32_t output_offset =
        output_data.empty() ? to_le32(0U) : to_le32(static_cast<std::uint32_t>(sizeof(Smb2Header) + 48U));
    SMB_EXPECT(output_data.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()));
    const std::uint32_t output_count = to_le32(static_cast<std::uint32_t>(output_data.size()));
    const std::uint32_t flags_le = to_le32(flags);
    const std::uint32_t reserved2 = to_le32(0U);

    std::uint8_t* body = packet.data() + sizeof(Smb2Header);
    std::memcpy(body + 0U, &structure_size, sizeof(structure_size));
    std::memcpy(body + 2U, &reserved, sizeof(reserved));
    std::memcpy(body + 4U, &ctl_code_le, sizeof(ctl_code_le));
    std::memcpy(body + 8U, &file_id_persistent, sizeof(file_id_persistent));
    std::memcpy(body + 16U, &file_id_volatile, sizeof(file_id_volatile));
    std::memcpy(body + 24U, &input_offset, sizeof(input_offset));
    std::memcpy(body + 28U, &input_count, sizeof(input_count));
    std::memcpy(body + 32U, &output_offset, sizeof(output_offset));
    std::memcpy(body + 36U, &output_count, sizeof(output_count));
    std::memcpy(body + 40U, &flags_le, sizeof(flags_le));
    std::memcpy(body + 44U, &reserved2, sizeof(reserved2));
    if (!output_data.empty()) {
        std::memcpy(packet.data() + sizeof(Smb2Header) + 48U, output_data.data(), output_data.size());
    }
    return packet;
}

std::vector<std::uint8_t> build_oplock_break_response(std::uint64_t message_id,
                                                      std::uint64_t session_id,
                                                      std::uint32_t tree_id,
                                                      const OplockBreakRequestFields& req) {
    const Smb2Header hdr = make_response_header(static_cast<std::uint16_t>(Smb2Command::OplockBreak),
                                                message_id,
                                                kStatusSuccess,
                                                session_id,
                                                tree_id);
    const std::size_t body_len = static_cast<std::size_t>(req.structure_size);
    std::vector<std::uint8_t> packet(sizeof(Smb2Header) + body_len, 0U);
    std::memcpy(packet.data(), &hdr, sizeof(Smb2Header));
    const std::uint16_t structure_size = to_le16(req.structure_size);
    const std::uint32_t reserved = to_le32(0U);
    const std::uint64_t persistent = to_le64(req.file_id.persistent_id);
    const std::uint64_t volatile_id = to_le64(req.file_id.volatile_id);
    std::uint8_t* body = packet.data() + sizeof(Smb2Header);
    std::memcpy(body + 0U, &structure_size, sizeof(structure_size));
    if (body_len >= 4U) {
        body[2U] = req.oplock_level;
        body[3U] = 0U;
    }
    if (body_len >= 8U) {
        std::memcpy(body + 4U, &reserved, sizeof(reserved));
    }
    if (body_len >= 24U) {
        std::memcpy(body + 8U, &persistent, sizeof(persistent));
        std::memcpy(body + 16U, &volatile_id, sizeof(volatile_id));
    }
    return packet;
}

bool is_special_ioctl_file_id(const FileIdPair& file_id) {
    const bool all_zero = (file_id.persistent_id == 0U) && (file_id.volatile_id == 0U);
    const bool all_ones = (file_id.persistent_id == std::numeric_limits<std::uint64_t>::max()) &&
                          (file_id.volatile_id == std::numeric_limits<std::uint64_t>::max());
    return all_zero || all_ones;
}

std::vector<std::uint8_t> build_validate_negotiate_info_blob(const std::array<std::uint8_t, 16>& server_guid) {
    std::vector<std::uint8_t> blob(24U, 0U);
    const std::uint32_t capabilities = to_le32(0U);
    const std::uint16_t security_mode = to_le16(0U);
    const std::uint16_t dialect = to_le16(0x0210U);
    std::memcpy(blob.data() + 0U, &capabilities, sizeof(capabilities));
    std::memcpy(blob.data() + 4U, server_guid.data(), server_guid.size());
    std::memcpy(blob.data() + 20U, &security_mode, sizeof(security_mode));
    std::memcpy(blob.data() + 22U, &dialect, sizeof(dialect));
    return blob;
}

std::string ascii_lower_copy(const std::string& value) {
    std::string out{};
    out.reserve(value.size());
    for (char c : value) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

bool wildcard_match_ascii_case_insensitive(const std::string& pattern, const std::string& candidate) {
    const std::string pat = ascii_lower_copy(pattern);
    const std::string text = ascii_lower_copy(candidate);
    std::size_t p = 0U;
    std::size_t t = 0U;
    std::size_t star = std::string::npos;
    std::size_t match = 0U;

    while (t < text.size()) {
        if ((p < pat.size()) && ((pat[p] == '?') || (pat[p] == text[t]))) {
            ++p;
            ++t;
            continue;
        }
        if ((p < pat.size()) && (pat[p] == '*')) {
            star = p++;
            match = t;
            continue;
        }
        if (star != std::string::npos) {
            p = star + 1U;
            ++match;
            t = match;
            continue;
        }
        return false;
    }
    while ((p < pat.size()) && (pat[p] == '*')) {
        ++p;
    }
    return p == pat.size();
}

std::uint64_t align_up_u64(std::uint64_t value, std::uint64_t alignment) {
    SMB_EXPECT(alignment > 0U);
    const std::uint64_t rem = value % alignment;
    if (rem == 0U) {
        return value;
    }
    return value + (alignment - rem);
}

struct QueryDirectoryEntry {
    std::string name{};
    bool is_directory{false};
    std::uint64_t size{0U};
    std::uint32_t attributes{0U};
    std::uint64_t file_id{0U};
};

bool collect_query_directory_entries(const std::string& directory_path,
                                     bool deny_dot_files,
                                     std::vector<QueryDirectoryEntry>& out) {
    out.clear();
    out.push_back(QueryDirectoryEntry{".", true, 0U, 0x00000010U, 1U});
    out.push_back(QueryDirectoryEntry{"..", true, 0U, 0x00000010U, 2U});

    std::error_code ec{};
    std::filesystem::directory_iterator it(std::filesystem::path(directory_path), ec);
    if (ec) {
        return false;
    }

    std::uint64_t next_id = 16U;
    for (const auto& entry : it) {
        const std::string name = entry.path().filename().string();
        if (name.empty()) {
            continue;
        }
        if (deny_dot_files && (name[0] == '.')) {
            continue;
        }

        std::error_code attr_ec{};
        const bool is_dir = entry.is_directory(attr_ec);
        if (attr_ec) {
            continue;
        }
        std::uint64_t file_size = 0U;
        if (!is_dir) {
            std::error_code size_ec{};
            file_size = entry.file_size(size_ec);
            if (size_ec) {
                file_size = 0U;
            }
        }
        out.push_back(QueryDirectoryEntry{
            name, is_dir, file_size, is_dir ? 0x00000010U : 0x00000080U, next_id++,
        });
    }

    if (out.size() > 2U) {
        std::sort(out.begin() + 2,
                  out.end(),
                  [](const QueryDirectoryEntry& lhs, const QueryDirectoryEntry& rhs) {
                      const std::string l = ascii_lower_copy(lhs.name);
                      const std::string r = ascii_lower_copy(rhs.name);
                      if (l == r) {
                          return lhs.name < rhs.name;
                      }
                      return l < r;
                  });
    }
    return true;
}

std::vector<std::uint8_t> encode_query_directory_id_both_record(const QueryDirectoryEntry& entry) {
    std::vector<std::uint8_t> utf16_name{};
    utf16_name.reserve(entry.name.size() * 2U);
    for (char c : entry.name) {
        utf16_name.push_back(static_cast<std::uint8_t>(c));
        utf16_name.push_back(0U);
    }
    const std::size_t record_size = 104U + utf16_name.size();
    std::vector<std::uint8_t> out(record_size, 0U);

    const std::uint64_t now_ft = to_le64(now_windows_filetime_utc());
    const std::uint64_t eof_size = to_le64(entry.size);
    const std::uint64_t alloc_size = to_le64(align_up_u64(entry.size, 4096U));
    const std::uint32_t attrs = to_le32(entry.attributes);
    const std::uint32_t name_len = to_le32(static_cast<std::uint32_t>(utf16_name.size()));
    const std::uint32_t reparse_tag = to_le32(0U);
    const std::uint64_t file_id = to_le64(entry.file_id);

    std::memcpy(out.data() + 8U, &now_ft, sizeof(now_ft));
    std::memcpy(out.data() + 16U, &now_ft, sizeof(now_ft));
    std::memcpy(out.data() + 24U, &now_ft, sizeof(now_ft));
    std::memcpy(out.data() + 32U, &now_ft, sizeof(now_ft));
    std::memcpy(out.data() + 40U, &eof_size, sizeof(eof_size));
    std::memcpy(out.data() + 48U, &alloc_size, sizeof(alloc_size));
    std::memcpy(out.data() + 56U, &attrs, sizeof(attrs));
    std::memcpy(out.data() + 60U, &name_len, sizeof(name_len));
    std::memcpy(out.data() + 64U, &reparse_tag, sizeof(reparse_tag));
    out[68U] = 0U;  // short name length (none)
    out[69U] = 0U;  // reserved
    std::memcpy(out.data() + 96U, &file_id, sizeof(file_id));
    if (!utf16_name.empty()) {
        std::memcpy(out.data() + 104U, utf16_name.data(), utf16_name.size());
    }
    return out;
}

bool build_query_directory_id_both_blob(const std::string& directory_path,
                                        const std::string& pattern,
                                        bool return_single_entry,
                                        bool deny_dot_files,
                                        std::uint32_t output_buffer_length,
                                        std::vector<std::uint8_t>& out_data,
                                        bool& out_has_entries) {
    out_data.clear();
    out_has_entries = false;
    std::vector<QueryDirectoryEntry> entries{};
    if (!collect_query_directory_entries(directory_path, deny_dot_files, entries)) {
        return false;
    }

    const std::string effective_pattern = pattern.empty() ? "*" : pattern;
    const std::size_t max_out =
        std::min<std::size_t>(static_cast<std::size_t>(output_buffer_length), static_cast<std::size_t>(kSmbMaxFrameBytes));

    std::size_t prev_offset = 0U;
    std::size_t prev_wire_len = 0U;
    bool has_prev = false;

    for (const auto& entry : entries) {
        if (!wildcard_match_ascii_case_insensitive(effective_pattern, entry.name)) {
            continue;
        }

        std::vector<std::uint8_t> record = encode_query_directory_id_both_record(entry);
        const std::size_t wire_len =
            static_cast<std::size_t>(align_up_u64(static_cast<std::uint64_t>(record.size()), 8U));
        if ((wire_len > max_out) && out_data.empty()) {
            break;
        }
        if ((out_data.size() + wire_len) > max_out) {
            break;
        }

        const std::size_t offset = out_data.size();
        out_data.resize(offset + wire_len, 0U);
        std::memcpy(out_data.data() + offset, record.data(), record.size());

        if (has_prev) {
            const std::uint32_t next_le = to_le32(static_cast<std::uint32_t>(prev_wire_len));
            std::memcpy(out_data.data() + prev_offset, &next_le, sizeof(next_le));
        }
        has_prev = true;
        prev_offset = offset;
        prev_wire_len = wire_len;
        out_has_entries = true;
        if (return_single_entry) {
            break;
        }
    }

    if (has_prev) {
        const std::uint32_t final_next = to_le32(0U);
        std::memcpy(out_data.data() + prev_offset, &final_next, sizeof(final_next));
    }
    return true;
}

std::vector<std::uint8_t> build_file_all_information_blob(std::uint64_t file_size, bool is_directory) {
    std::vector<std::uint8_t> out(100U, 0U);
    const std::uint64_t now_ft = to_le64(now_windows_filetime_utc());
    const std::uint32_t attrs = to_le32(is_directory ? 0x00000010U : 0x00000080U);
    const std::uint64_t alloc = to_le64(file_size);
    const std::uint64_t eof = to_le64(file_size);
    const std::uint32_t links = to_le32(1U);
    const std::uint64_t index = to_le64(0U);
    const std::uint32_t ea_size = to_le32(0U);
    const std::uint32_t access_flags = to_le32(0U);
    const std::uint64_t current_offset = to_le64(0U);
    const std::uint32_t mode = to_le32(0U);
    const std::uint32_t alignment = to_le32(0U);
    const std::uint32_t name_len = to_le32(0U);

    std::memcpy(out.data() + 0U, &now_ft, sizeof(now_ft));
    std::memcpy(out.data() + 8U, &now_ft, sizeof(now_ft));
    std::memcpy(out.data() + 16U, &now_ft, sizeof(now_ft));
    std::memcpy(out.data() + 24U, &now_ft, sizeof(now_ft));
    std::memcpy(out.data() + 32U, &attrs, sizeof(attrs));
    std::memcpy(out.data() + 40U, &alloc, sizeof(alloc));
    std::memcpy(out.data() + 48U, &eof, sizeof(eof));
    std::memcpy(out.data() + 56U, &links, sizeof(links));
    out[60U] = 0U;  // delete pending
    out[61U] = is_directory ? 1U : 0U;
    std::memcpy(out.data() + 64U, &index, sizeof(index));
    std::memcpy(out.data() + 72U, &ea_size, sizeof(ea_size));
    std::memcpy(out.data() + 76U, &access_flags, sizeof(access_flags));
    std::memcpy(out.data() + 80U, &current_offset, sizeof(current_offset));
    std::memcpy(out.data() + 88U, &mode, sizeof(mode));
    std::memcpy(out.data() + 92U, &alignment, sizeof(alignment));
    std::memcpy(out.data() + 96U, &name_len, sizeof(name_len));
    return out;
}

std::vector<std::uint8_t> build_file_fs_size_information_blob(const std::filesystem::space_info& space_info) {
    std::vector<std::uint8_t> out(24U, 0U);
    constexpr std::uint64_t kBytesPerSector = 512U;
    constexpr std::uint64_t kSectorsPerAllocation = 8U;
    const std::uint64_t unit = kBytesPerSector * kSectorsPerAllocation;
    const std::uint64_t total_units = static_cast<std::uint64_t>(space_info.capacity / unit);
    const std::uint64_t avail_units = static_cast<std::uint64_t>(space_info.available / unit);
    const std::uint64_t total_units_le = to_le64(total_units);
    const std::uint64_t avail_units_le = to_le64(avail_units);
    const std::uint32_t sectors_le = to_le32(static_cast<std::uint32_t>(kSectorsPerAllocation));
    const std::uint32_t bytes_le = to_le32(static_cast<std::uint32_t>(kBytesPerSector));
    std::memcpy(out.data() + 0U, &total_units_le, sizeof(total_units_le));
    std::memcpy(out.data() + 8U, &avail_units_le, sizeof(avail_units_le));
    std::memcpy(out.data() + 16U, &sectors_le, sizeof(sectors_le));
    std::memcpy(out.data() + 20U, &bytes_le, sizeof(bytes_le));
    return out;
}

std::vector<std::uint8_t> build_file_fs_full_size_information_blob(const std::filesystem::space_info& space_info) {
    std::vector<std::uint8_t> out(32U, 0U);
    constexpr std::uint64_t kBytesPerSector = 512U;
    constexpr std::uint64_t kSectorsPerAllocation = 8U;
    const std::uint64_t unit = kBytesPerSector * kSectorsPerAllocation;
    const std::uint64_t total_units = static_cast<std::uint64_t>(space_info.capacity / unit);
    const std::uint64_t caller_avail_units = static_cast<std::uint64_t>(space_info.available / unit);
    const std::uint64_t actual_avail_units = static_cast<std::uint64_t>(space_info.available / unit);
    const std::uint64_t total_units_le = to_le64(total_units);
    const std::uint64_t caller_avail_le = to_le64(caller_avail_units);
    const std::uint64_t actual_avail_le = to_le64(actual_avail_units);
    const std::uint32_t sectors_le = to_le32(static_cast<std::uint32_t>(kSectorsPerAllocation));
    const std::uint32_t bytes_le = to_le32(static_cast<std::uint32_t>(kBytesPerSector));
    std::memcpy(out.data() + 0U, &total_units_le, sizeof(total_units_le));
    std::memcpy(out.data() + 8U, &caller_avail_le, sizeof(caller_avail_le));
    std::memcpy(out.data() + 16U, &actual_avail_le, sizeof(actual_avail_le));
    std::memcpy(out.data() + 24U, &sectors_le, sizeof(sectors_le));
    std::memcpy(out.data() + 28U, &bytes_le, sizeof(bytes_le));
    return out;
}

bool constant_time_equal(const std::string& lhs, const std::string& rhs) {
    std::uint8_t diff = 0U;
    const std::size_t lhs_size = lhs.size();
    const std::size_t rhs_size = rhs.size();
    const std::size_t max_size = (lhs_size > rhs_size) ? lhs_size : rhs_size;
    for (std::size_t i = 0U; i < max_size; ++i) {
        const std::uint8_t l =
            (i < lhs_size) ? static_cast<std::uint8_t>(lhs[i]) : static_cast<std::uint8_t>(0U);
        const std::uint8_t r =
            (i < rhs_size) ? static_cast<std::uint8_t>(rhs[i]) : static_cast<std::uint8_t>(0U);
        diff = static_cast<std::uint8_t>(diff | static_cast<std::uint8_t>(l ^ r));
    }
    return (diff == 0U) && (lhs_size == rhs_size);
}

bool validate_auth_blob(const std::uint8_t* data,
                        std::size_t size,
                        const AuthConfig& auth) {
    SMB_EXPECT(data != nullptr);
    if (size == 0U) {
        return false;
    }

    const std::string blob(reinterpret_cast<const char*>(data), size);
    constexpr const char* kUserPrefix = "USER=";
    constexpr const char* kPassKey = ";PASS=";
    if (blob.rfind(kUserPrefix, 0U) != 0U) {
        return false;
    }

    const std::size_t pass_pos = blob.find(kPassKey);
    if (pass_pos == std::string::npos) {
        return false;
    }
    const std::size_t user_start = std::strlen(kUserPrefix);
    if (pass_pos <= user_start) {
        return false;
    }

    const std::size_t pass_start = pass_pos + std::strlen(kPassKey);
    if (pass_start >= blob.size()) {
        return false;
    }

    const std::string user = blob.substr(user_start, pass_pos - user_start);
    const std::string pass = blob.substr(pass_start);
    if (user.empty() || pass.empty()) {
        return false;
    }

    return constant_time_equal(user, auth.username) && constant_time_equal(pass, auth.password);
}

bool authenticate_user_pass_session_blob(const std::uint8_t* blob_data, std::size_t blob_size, const AuthConfig& auth) {
    SMB_EXPECT(blob_data != nullptr);
    if (!auth.require_auth) {
        return true;
    }
    return validate_auth_blob(blob_data, blob_size, auth);
}

bool extract_session_setup_security_blob(const std::vector<std::uint8_t>& frame,
                                         const std::uint8_t*& blob_data,
                                         std::size_t& blob_size) {
    blob_data = nullptr;
    blob_size = 0U;
    if (frame.size() < (sizeof(Smb2Header) + sizeof(SessionSetupRequestBody))) {
        return false;
    }
    SessionSetupRequestBody req{};
    std::memcpy(&req, frame.data() + sizeof(Smb2Header), sizeof(SessionSetupRequestBody));
    const std::uint16_t offset = from_le16(req.security_buffer_offset);
    const std::uint16_t length = from_le16(req.security_buffer_length);
    if (length == 0U) {
        return true;
    }
    const std::size_t end = static_cast<std::size_t>(offset) + static_cast<std::size_t>(length);
    if ((offset < static_cast<std::uint16_t>(sizeof(Smb2Header) + sizeof(SessionSetupRequestBody))) ||
        (end > frame.size())) {
        return false;
    }
    blob_data = frame.data() + static_cast<std::size_t>(offset);
    blob_size = static_cast<std::size_t>(length);
    return true;
}

bool blob_starts_with_user_pass_auth(const std::uint8_t* blob_data, std::size_t blob_size) {
    SMB_EXPECT(blob_data != nullptr);
    constexpr const char* kPrefix = "USER=";
    const std::size_t prefix_len = std::strlen(kPrefix);
    if (blob_size < prefix_len) {
        return false;
    }
    return std::memcmp(blob_data, kPrefix, prefix_len) == 0;
}

std::optional<std::size_t> find_ntlmssp_signature(const std::uint8_t* blob_data, std::size_t blob_size) {
    SMB_EXPECT(blob_data != nullptr);
    static const std::array<std::uint8_t, 8> kSig = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00U};
    if (blob_size < (kSig.size() + 4U)) {
        return std::nullopt;
    }
    for (std::size_t i = 0U; (i + kSig.size() + 4U) <= blob_size; ++i) {
        if (std::memcmp(blob_data + i, kSig.data(), kSig.size()) == 0) {
            return i;
        }
    }
    return std::nullopt;
}

std::optional<std::uint32_t> extract_ntlm_message_type(const std::uint8_t* blob_data, std::size_t blob_size) {
    const auto sig_offset = find_ntlmssp_signature(blob_data, blob_size);
    if (!sig_offset.has_value()) {
        return std::nullopt;
    }
    const std::size_t type_off = sig_offset.value() + 8U;
    if ((type_off + 4U) > blob_size) {
        return std::nullopt;
    }
    const std::uint32_t type = static_cast<std::uint32_t>(blob_data[type_off]) |
                               (static_cast<std::uint32_t>(blob_data[type_off + 1U]) << 8U) |
                               (static_cast<std::uint32_t>(blob_data[type_off + 2U]) << 16U) |
                               (static_cast<std::uint32_t>(blob_data[type_off + 3U]) << 24U);
    return type;
}

std::optional<std::array<std::uint8_t, 8>> make_ntlm_server_challenge() {
    std::array<std::uint8_t, 8> challenge{};
    if (!fill_secure_random_bytes(challenge.data(), challenge.size())) {
        return std::nullopt;
    }
    return std::make_optional(challenge);
}

void append_asn1_length(std::vector<std::uint8_t>& out, std::size_t len) {
    if (len < 0x80U) {
        out.push_back(static_cast<std::uint8_t>(len));
        return;
    }
    if (len <= 0xFFU) {
        out.push_back(0x81U);
        out.push_back(static_cast<std::uint8_t>(len));
        return;
    }
    SMB_EXPECT(len <= 0xFFFFU);
    out.push_back(0x82U);
    out.push_back(static_cast<std::uint8_t>((len >> 8U) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>(len & 0xFFU));
}

std::vector<std::uint8_t> build_ntlm_type2_challenge_token(const std::array<std::uint8_t, 8>& challenge) {
    auto utf16le_ascii = [](const std::string& text) {
        std::vector<std::uint8_t> out{};
        out.reserve(text.size() * 2U);
        for (char c : text) {
            out.push_back(static_cast<std::uint8_t>(c));
            out.push_back(0U);
        }
        return out;
    };

    const std::string target_name_ascii = "SMBSERVER";
    const std::string target_domain_ascii = "WORKGROUP";
    const std::vector<std::uint8_t> target_name = utf16le_ascii(target_name_ascii);
    std::vector<std::uint8_t> target_info{};
    const auto append_av_pair = [&](std::uint16_t id, const std::vector<std::uint8_t>& value) {
        const std::uint16_t id_le = to_le16(id);
        const std::uint16_t len_le = to_le16(static_cast<std::uint16_t>(value.size()));
        target_info.insert(target_info.end(),
                           reinterpret_cast<const std::uint8_t*>(&id_le),
                           reinterpret_cast<const std::uint8_t*>(&id_le) + sizeof(id_le));
        target_info.insert(target_info.end(),
                           reinterpret_cast<const std::uint8_t*>(&len_le),
                           reinterpret_cast<const std::uint8_t*>(&len_le) + sizeof(len_le));
        target_info.insert(target_info.end(), value.begin(), value.end());
    };
    append_av_pair(0x0001U, utf16le_ascii(target_name_ascii));   // MsvAvNbComputerName
    append_av_pair(0x0002U, utf16le_ascii(target_domain_ascii)); // MsvAvNbDomainName
    append_av_pair(0x0003U, utf16le_ascii(target_name_ascii));   // MsvAvDnsComputerName
    append_av_pair(0x0004U, utf16le_ascii(target_domain_ascii)); // MsvAvDnsDomainName
    {
        std::vector<std::uint8_t> timestamp(8U, 0U);
        const std::uint64_t ts_le = to_le64(now_windows_filetime_utc());
        std::memcpy(timestamp.data(), &ts_le, sizeof(ts_le));
        append_av_pair(0x0007U, timestamp);  // MsvAvTimestamp
    }
    append_av_pair(0x0000U, std::vector<std::uint8_t>{});  // MsvAvEOL

    const std::size_t payload_offset = 56U;
    const std::size_t target_name_offset = payload_offset;
    const std::size_t target_info_offset = target_name_offset + target_name.size();
    std::vector<std::uint8_t> ntlm(payload_offset + target_name.size() + target_info.size(), 0U);
    SMB_EXPECT(ntlm.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()));

    std::memcpy(ntlm.data(), "NTLMSSP\0", 8U);
    const std::uint32_t msg_type_le = to_le32(2U);
    std::memcpy(ntlm.data() + 8U, &msg_type_le, sizeof(msg_type_le));

    const auto write_secbuf = [&](std::size_t off, std::uint16_t len, std::uint32_t ptr_off) {
        const std::uint16_t len_le = to_le16(len);
        const std::uint16_t max_le = to_le16(len);
        const std::uint32_t off_le = to_le32(ptr_off);
        std::memcpy(ntlm.data() + off + 0U, &len_le, sizeof(len_le));
        std::memcpy(ntlm.data() + off + 2U, &max_le, sizeof(max_le));
        std::memcpy(ntlm.data() + off + 4U, &off_le, sizeof(off_le));
    };
    write_secbuf(12U,
                 static_cast<std::uint16_t>(target_name.size()),
                 static_cast<std::uint32_t>(target_name_offset));

    const std::uint32_t flags_le = to_le32(0xA28A8205U);
    std::memcpy(ntlm.data() + 20U, &flags_le, sizeof(flags_le));
    std::memcpy(ntlm.data() + 24U, challenge.data(), challenge.size());
    write_secbuf(40U,
                 static_cast<std::uint16_t>(target_info.size()),
                 static_cast<std::uint32_t>(target_info_offset));

    // VERSION structure: major=10, minor=0, build=0, revision=0x0F.
    ntlm[48U] = 10U;
    ntlm[49U] = 0U;
    ntlm[50U] = 0U;
    ntlm[51U] = 0U;
    ntlm[52U] = 0U;
    ntlm[53U] = 0U;
    ntlm[54U] = 0U;
    ntlm[55U] = 0x0FU;

    std::memcpy(ntlm.data() + target_name_offset, target_name.data(), target_name.size());
    std::memcpy(ntlm.data() + target_info_offset, target_info.data(), target_info.size());

    const std::array<std::uint8_t, 10> ntlm_oid = {
        0x2BU, 0x06U, 0x01U, 0x04U, 0x01U, 0x82U, 0x37U, 0x02U, 0x02U, 0x0AU,
    };

    auto make_tlv = [](std::uint8_t tag, const std::vector<std::uint8_t>& value) {
        std::vector<std::uint8_t> out{};
        out.reserve(2U + value.size());
        out.push_back(tag);
        append_asn1_length(out, value.size());
        out.insert(out.end(), value.begin(), value.end());
        return out;
    };

    const std::vector<std::uint8_t> neg_state = {0x0AU, 0x01U, 0x01U};  // accept-incomplete
    const std::vector<std::uint8_t> mech_type = [&]() {
        std::vector<std::uint8_t> v{};
        v.push_back(0x06U);
        append_asn1_length(v, ntlm_oid.size());
        v.insert(v.end(), ntlm_oid.begin(), ntlm_oid.end());
        return v;
    }();
    const std::vector<std::uint8_t> response_token = [&]() {
        std::vector<std::uint8_t> v{};
        v.push_back(0x04U);
        append_asn1_length(v, ntlm.size());
        v.insert(v.end(), ntlm.begin(), ntlm.end());
        return v;
    }();

    const std::vector<std::uint8_t> field_a0 = make_tlv(0xA0U, neg_state);
    const std::vector<std::uint8_t> field_a1 = make_tlv(0xA1U, mech_type);
    const std::vector<std::uint8_t> field_a2 = make_tlv(0xA2U, response_token);
    std::vector<std::uint8_t> seq_content{};
    seq_content.reserve(field_a0.size() + field_a1.size() + field_a2.size());
    seq_content.insert(seq_content.end(), field_a0.begin(), field_a0.end());
    seq_content.insert(seq_content.end(), field_a1.begin(), field_a1.end());
    seq_content.insert(seq_content.end(), field_a2.begin(), field_a2.end());
    const std::vector<std::uint8_t> seq = make_tlv(0x30U, seq_content);
    return make_tlv(0xA1U, seq);
}

bool extract_ntlm_auth_username_ascii(const std::uint8_t* blob_data, std::size_t blob_size, std::string& username) {
    const auto sig_offset = find_ntlmssp_signature(blob_data, blob_size);
    if (!sig_offset.has_value()) {
        return false;
    }
    const std::size_t base = sig_offset.value();
    if ((base + 64U) > blob_size) {
        return false;
    }
    const std::size_t user_secbuf = base + 36U;
    const std::uint16_t user_len = static_cast<std::uint16_t>(blob_data[user_secbuf]) |
                                   static_cast<std::uint16_t>(static_cast<std::uint16_t>(blob_data[user_secbuf + 1U]) << 8U);
    const std::uint32_t user_off = static_cast<std::uint32_t>(blob_data[user_secbuf + 4U]) |
                                   (static_cast<std::uint32_t>(blob_data[user_secbuf + 5U]) << 8U) |
                                   (static_cast<std::uint32_t>(blob_data[user_secbuf + 6U]) << 16U) |
                                   (static_cast<std::uint32_t>(blob_data[user_secbuf + 7U]) << 24U);
    const std::size_t user_begin = base + static_cast<std::size_t>(user_off);
    const std::size_t user_end = user_begin + static_cast<std::size_t>(user_len);
    if ((user_len == 0U) || (user_end > blob_size)) {
        return false;
    }
    return decode_utf16le_ascii(blob_data + user_begin, static_cast<std::size_t>(user_len), username);
}

bool ascii_case_equal(const std::string& lhs, const std::string& rhs) {
    if (lhs.size() != rhs.size()) {
        return false;
    }
    for (std::size_t i = 0U; i < lhs.size(); ++i) {
        const unsigned char lc = static_cast<unsigned char>(lhs[i]);
        const unsigned char rc = static_cast<unsigned char>(rhs[i]);
        if (std::tolower(lc) != std::tolower(rc)) {
            return false;
        }
    }
    return true;
}

bool constant_time_equal_bytes(const std::uint8_t* lhs, const std::uint8_t* rhs, std::size_t len) {
    SMB_EXPECT(lhs != nullptr);
    SMB_EXPECT(rhs != nullptr);
    std::uint8_t diff = 0U;
    for (std::size_t i = 0U; i < len; ++i) {
        diff = static_cast<std::uint8_t>(diff | static_cast<std::uint8_t>(lhs[i] ^ rhs[i]));
    }
    return diff == 0U;
}

std::uint16_t read_blob_le16(const std::uint8_t* data) {
    SMB_EXPECT(data != nullptr);
    return static_cast<std::uint16_t>(data[0]) |
           static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[1]) << 8U);
}

std::uint32_t read_blob_le32(const std::uint8_t* data) {
    SMB_EXPECT(data != nullptr);
    return static_cast<std::uint32_t>(data[0]) |
           (static_cast<std::uint32_t>(data[1]) << 8U) |
           (static_cast<std::uint32_t>(data[2]) << 16U) |
           (static_cast<std::uint32_t>(data[3]) << 24U);
}

bool decode_utf16le_ascii_allow_empty(const std::uint8_t* data, std::size_t size, std::string& out) {
    if (size == 0U) {
        out.clear();
        return true;
    }
    SMB_EXPECT(data != nullptr);
    if ((size % 2U) != 0U) {
        return false;
    }
    std::string decoded{};
    decoded.reserve(size / 2U);
    for (std::size_t i = 0U; i < size; i += 2U) {
        const std::uint16_t ch =
            static_cast<std::uint16_t>(data[i]) | static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[i + 1U]) << 8U);
        if (ch == 0U) {
            continue;
        }
        if ((ch < 0x20U) || (ch > 0x7EU)) {
            return false;
        }
        decoded.push_back(static_cast<char>(ch & 0x7FU));
    }
    out = decoded;
    return true;
}

std::string ascii_upper_copy(const std::string& value) {
    std::string out{};
    out.reserve(value.size());
    for (char c : value) {
        out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }
    return out;
}

std::string strip_qualified_username(const std::string& user) {
    if (user.empty()) {
        return user;
    }
    const std::size_t slash_back = user.rfind('\\');
    const std::size_t slash_forward = user.rfind('/');
    const std::size_t slash = (slash_back == std::string::npos)
                                  ? slash_forward
                                  : ((slash_forward == std::string::npos) ? slash_back : std::max(slash_back, slash_forward));
    if ((slash != std::string::npos) && ((slash + 1U) < user.size())) {
        return user.substr(slash + 1U);
    }
    const std::size_t at = user.find('@');
    if (at != std::string::npos) {
        return user.substr(0U, at);
    }
    return user;
}

std::string domain_from_qualified_username(const std::string& user) {
    if (user.empty()) {
        return {};
    }
    const std::size_t slash_back = user.rfind('\\');
    const std::size_t slash_forward = user.rfind('/');
    const std::size_t slash = (slash_back == std::string::npos)
                                  ? slash_forward
                                  : ((slash_forward == std::string::npos) ? slash_back : std::max(slash_back, slash_forward));
    if (slash != std::string::npos) {
        return user.substr(0U, slash);
    }
    const std::size_t at = user.find('@');
    if ((at != std::string::npos) && ((at + 1U) < user.size())) {
        return user.substr(at + 1U);
    }
    return {};
}

bool push_unique_non_empty(std::vector<std::string>& out, const std::string& value) {
    if (value.empty()) {
        return false;
    }
    for (const auto& existing : out) {
        if (existing == value) {
            return false;
        }
    }
    out.push_back(value);
    return true;
}

struct NtlmType3Fields {
    std::string username{};
    std::string domain{};
    const std::uint8_t* lm_response{nullptr};
    std::size_t lm_response_len{0U};
    const std::uint8_t* nt_response{nullptr};
    std::size_t nt_response_len{0U};
    const std::uint8_t* encrypted_session_key{nullptr};
    std::size_t encrypted_session_key_len{0U};
    std::uint32_t negotiate_flags{0U};
};

bool parse_ntlm_security_buffer(const std::uint8_t* blob_data,
                                std::size_t blob_size,
                                std::size_t ntlm_base,
                                std::size_t secbuf_offset,
                                const std::uint8_t*& out_ptr,
                                std::size_t& out_len) {
    SMB_EXPECT(blob_data != nullptr);
    out_ptr = nullptr;
    out_len = 0U;
    if ((ntlm_base + secbuf_offset + 8U) > blob_size) {
        return false;
    }
    const std::uint16_t len = read_blob_le16(blob_data + ntlm_base + secbuf_offset);
    const std::uint32_t off = read_blob_le32(blob_data + ntlm_base + secbuf_offset + 4U);
    const std::size_t begin = ntlm_base + static_cast<std::size_t>(off);
    const std::size_t end = begin + static_cast<std::size_t>(len);
    if (end > blob_size) {
        return false;
    }
    out_ptr = blob_data + begin;
    out_len = static_cast<std::size_t>(len);
    return true;
}

bool extract_ntlm_type3_fields(const std::uint8_t* blob_data, std::size_t blob_size, NtlmType3Fields& out) {
    SMB_EXPECT(blob_data != nullptr);
    out = NtlmType3Fields{};
    const auto msg_type = extract_ntlm_message_type(blob_data, blob_size);
    if (!msg_type.has_value() || (msg_type.value() != 3U)) {
        return false;
    }
    const auto sig_offset = find_ntlmssp_signature(blob_data, blob_size);
    if (!sig_offset.has_value()) {
        return false;
    }
    const std::size_t base = sig_offset.value();
    if ((base + 64U) > blob_size) {
        return false;
    }
    const std::uint8_t* user_ptr = nullptr;
    std::size_t user_len = 0U;
    const std::uint8_t* domain_ptr = nullptr;
    std::size_t domain_len = 0U;
    const std::uint8_t* workstation_ptr = nullptr;
    std::size_t workstation_len = 0U;
    if (!parse_ntlm_security_buffer(
            blob_data, blob_size, base, 12U, out.lm_response, out.lm_response_len) ||
        !parse_ntlm_security_buffer(
            blob_data, blob_size, base, 20U, out.nt_response, out.nt_response_len) ||
        !parse_ntlm_security_buffer(blob_data, blob_size, base, 28U, domain_ptr, domain_len) ||
        !parse_ntlm_security_buffer(blob_data, blob_size, base, 36U, user_ptr, user_len) ||
        !parse_ntlm_security_buffer(blob_data, blob_size, base, 44U, workstation_ptr, workstation_len) ||
        !parse_ntlm_security_buffer(
            blob_data, blob_size, base, 52U, out.encrypted_session_key, out.encrypted_session_key_len)) {
        return false;
    }
    (void)workstation_ptr;
    (void)workstation_len;
    if (!decode_utf16le_ascii_allow_empty(user_ptr, user_len, out.username) || out.username.empty()) {
        return false;
    }
    if (!decode_utf16le_ascii_allow_empty(domain_ptr, domain_len, out.domain)) {
        return false;
    }
    out.negotiate_flags = read_blob_le32(blob_data + base + 60U);

    if (out.nt_response_len < 16U) {
        return false;
    }
    return true;
}

std::uint32_t rotl32(std::uint32_t value, std::uint32_t shift) {
    return (value << shift) | (value >> (32U - shift));
}

struct Md4State {
    std::array<std::uint32_t, 4> h{};
    std::array<std::uint8_t, 64> buffer{};
    std::uint64_t bits{0U};
    std::size_t buffer_len{0U};
};

void md4_transform(std::array<std::uint32_t, 4>& h, const std::uint8_t* block) {
    SMB_EXPECT(block != nullptr);
    std::array<std::uint32_t, 16> x{};
    for (std::size_t i = 0U; i < 16U; ++i) {
        x[i] = read_blob_le32(block + (i * 4U));
    }

    const auto f = [](std::uint32_t a, std::uint32_t b, std::uint32_t c) {
        return (a & b) | (~a & c);
    };
    const auto g = [](std::uint32_t a, std::uint32_t b, std::uint32_t c) {
        return (a & b) | (a & c) | (b & c);
    };
    const auto hh = [](std::uint32_t a, std::uint32_t b, std::uint32_t c) {
        return a ^ b ^ c;
    };

    std::uint32_t a = h[0];
    std::uint32_t b = h[1];
    std::uint32_t c = h[2];
    std::uint32_t d = h[3];

    a = rotl32(a + f(b, c, d) + x[0], 3U);
    d = rotl32(d + f(a, b, c) + x[1], 7U);
    c = rotl32(c + f(d, a, b) + x[2], 11U);
    b = rotl32(b + f(c, d, a) + x[3], 19U);
    a = rotl32(a + f(b, c, d) + x[4], 3U);
    d = rotl32(d + f(a, b, c) + x[5], 7U);
    c = rotl32(c + f(d, a, b) + x[6], 11U);
    b = rotl32(b + f(c, d, a) + x[7], 19U);
    a = rotl32(a + f(b, c, d) + x[8], 3U);
    d = rotl32(d + f(a, b, c) + x[9], 7U);
    c = rotl32(c + f(d, a, b) + x[10], 11U);
    b = rotl32(b + f(c, d, a) + x[11], 19U);
    a = rotl32(a + f(b, c, d) + x[12], 3U);
    d = rotl32(d + f(a, b, c) + x[13], 7U);
    c = rotl32(c + f(d, a, b) + x[14], 11U);
    b = rotl32(b + f(c, d, a) + x[15], 19U);

    a = rotl32(a + g(b, c, d) + x[0] + 0x5A827999U, 3U);
    d = rotl32(d + g(a, b, c) + x[4] + 0x5A827999U, 5U);
    c = rotl32(c + g(d, a, b) + x[8] + 0x5A827999U, 9U);
    b = rotl32(b + g(c, d, a) + x[12] + 0x5A827999U, 13U);
    a = rotl32(a + g(b, c, d) + x[1] + 0x5A827999U, 3U);
    d = rotl32(d + g(a, b, c) + x[5] + 0x5A827999U, 5U);
    c = rotl32(c + g(d, a, b) + x[9] + 0x5A827999U, 9U);
    b = rotl32(b + g(c, d, a) + x[13] + 0x5A827999U, 13U);
    a = rotl32(a + g(b, c, d) + x[2] + 0x5A827999U, 3U);
    d = rotl32(d + g(a, b, c) + x[6] + 0x5A827999U, 5U);
    c = rotl32(c + g(d, a, b) + x[10] + 0x5A827999U, 9U);
    b = rotl32(b + g(c, d, a) + x[14] + 0x5A827999U, 13U);
    a = rotl32(a + g(b, c, d) + x[3] + 0x5A827999U, 3U);
    d = rotl32(d + g(a, b, c) + x[7] + 0x5A827999U, 5U);
    c = rotl32(c + g(d, a, b) + x[11] + 0x5A827999U, 9U);
    b = rotl32(b + g(c, d, a) + x[15] + 0x5A827999U, 13U);

    a = rotl32(a + hh(b, c, d) + x[0] + 0x6ED9EBA1U, 3U);
    d = rotl32(d + hh(a, b, c) + x[8] + 0x6ED9EBA1U, 9U);
    c = rotl32(c + hh(d, a, b) + x[4] + 0x6ED9EBA1U, 11U);
    b = rotl32(b + hh(c, d, a) + x[12] + 0x6ED9EBA1U, 15U);
    a = rotl32(a + hh(b, c, d) + x[2] + 0x6ED9EBA1U, 3U);
    d = rotl32(d + hh(a, b, c) + x[10] + 0x6ED9EBA1U, 9U);
    c = rotl32(c + hh(d, a, b) + x[6] + 0x6ED9EBA1U, 11U);
    b = rotl32(b + hh(c, d, a) + x[14] + 0x6ED9EBA1U, 15U);
    a = rotl32(a + hh(b, c, d) + x[1] + 0x6ED9EBA1U, 3U);
    d = rotl32(d + hh(a, b, c) + x[9] + 0x6ED9EBA1U, 9U);
    c = rotl32(c + hh(d, a, b) + x[5] + 0x6ED9EBA1U, 11U);
    b = rotl32(b + hh(c, d, a) + x[13] + 0x6ED9EBA1U, 15U);
    a = rotl32(a + hh(b, c, d) + x[3] + 0x6ED9EBA1U, 3U);
    d = rotl32(d + hh(a, b, c) + x[11] + 0x6ED9EBA1U, 9U);
    c = rotl32(c + hh(d, a, b) + x[7] + 0x6ED9EBA1U, 11U);
    b = rotl32(b + hh(c, d, a) + x[15] + 0x6ED9EBA1U, 15U);

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
}

void md4_init(Md4State& st) {
    st.h = {0x67452301U, 0xEFCDAB89U, 0x98BADCFEU, 0x10325476U};
    st.buffer.fill(0U);
    st.bits = 0U;
    st.buffer_len = 0U;
}

void md4_update(Md4State& st, const std::uint8_t* data, std::size_t len) {
    SMB_EXPECT(data != nullptr || len == 0U);
    st.bits += static_cast<std::uint64_t>(len) * 8U;
    std::size_t offset = 0U;
    while (offset < len) {
        const std::size_t to_copy = std::min<std::size_t>(64U - st.buffer_len, len - offset);
        std::memcpy(st.buffer.data() + st.buffer_len, data + offset, to_copy);
        st.buffer_len += to_copy;
        offset += to_copy;
        if (st.buffer_len == 64U) {
            md4_transform(st.h, st.buffer.data());
            st.buffer_len = 0U;
        }
    }
}

std::array<std::uint8_t, 16> md4_final(Md4State& st) {
    std::array<std::uint8_t, 16> out{};
    const std::uint64_t bit_len = st.bits;
    const std::uint8_t pad80 = 0x80U;
    md4_update(st, &pad80, 1U);
    const std::uint8_t zero = 0U;
    while (st.buffer_len != 56U) {
        md4_update(st, &zero, 1U);
    }
    std::array<std::uint8_t, 8> len_le{};
    for (std::size_t i = 0U; i < 8U; ++i) {
        len_le[i] = static_cast<std::uint8_t>((bit_len >> (i * 8U)) & 0xFFU);
    }
    md4_update(st, len_le.data(), len_le.size());
    for (std::size_t i = 0U; i < 4U; ++i) {
        const std::uint32_t v = st.h[i];
        out[i * 4U + 0U] = static_cast<std::uint8_t>(v & 0xFFU);
        out[i * 4U + 1U] = static_cast<std::uint8_t>((v >> 8U) & 0xFFU);
        out[i * 4U + 2U] = static_cast<std::uint8_t>((v >> 16U) & 0xFFU);
        out[i * 4U + 3U] = static_cast<std::uint8_t>((v >> 24U) & 0xFFU);
    }
    return out;
}

struct Md5State {
    std::array<std::uint32_t, 4> h{};
    std::array<std::uint8_t, 64> buffer{};
    std::uint64_t bits{0U};
    std::size_t buffer_len{0U};
};

void md5_transform(std::array<std::uint32_t, 4>& h, const std::uint8_t* block) {
    SMB_EXPECT(block != nullptr);
    static const std::array<std::uint32_t, 64> k = {
        0xd76aa478U, 0xe8c7b756U, 0x242070dbU, 0xc1bdceeeU, 0xf57c0fafU, 0x4787c62aU, 0xa8304613U, 0xfd469501U,
        0x698098d8U, 0x8b44f7afU, 0xffff5bb1U, 0x895cd7beU, 0x6b901122U, 0xfd987193U, 0xa679438eU, 0x49b40821U,
        0xf61e2562U, 0xc040b340U, 0x265e5a51U, 0xe9b6c7aaU, 0xd62f105dU, 0x02441453U, 0xd8a1e681U, 0xe7d3fbc8U,
        0x21e1cde6U, 0xc33707d6U, 0xf4d50d87U, 0x455a14edU, 0xa9e3e905U, 0xfcefa3f8U, 0x676f02d9U, 0x8d2a4c8aU,
        0xfffa3942U, 0x8771f681U, 0x6d9d6122U, 0xfde5380cU, 0xa4beea44U, 0x4bdecfa9U, 0xf6bb4b60U, 0xbebfbc70U,
        0x289b7ec6U, 0xeaa127faU, 0xd4ef3085U, 0x04881d05U, 0xd9d4d039U, 0xe6db99e5U, 0x1fa27cf8U, 0xc4ac5665U,
        0xf4292244U, 0x432aff97U, 0xab9423a7U, 0xfc93a039U, 0x655b59c3U, 0x8f0ccc92U, 0xffeff47dU, 0x85845dd1U,
        0x6fa87e4fU, 0xfe2ce6e0U, 0xa3014314U, 0x4e0811a1U, 0xf7537e82U, 0xbd3af235U, 0x2ad7d2bbU, 0xeb86d391U,
    };
    static const std::array<std::uint32_t, 64> s = {
        7U, 12U, 17U, 22U, 7U, 12U, 17U, 22U, 7U, 12U, 17U, 22U, 7U, 12U, 17U, 22U,
        5U, 9U, 14U, 20U, 5U, 9U, 14U, 20U, 5U, 9U, 14U, 20U, 5U, 9U, 14U, 20U,
        4U, 11U, 16U, 23U, 4U, 11U, 16U, 23U, 4U, 11U, 16U, 23U, 4U, 11U, 16U, 23U,
        6U, 10U, 15U, 21U, 6U, 10U, 15U, 21U, 6U, 10U, 15U, 21U, 6U, 10U, 15U, 21U,
    };
    std::array<std::uint32_t, 16> w{};
    for (std::size_t i = 0U; i < 16U; ++i) {
        w[i] = read_blob_le32(block + (i * 4U));
    }
    std::uint32_t a = h[0];
    std::uint32_t b = h[1];
    std::uint32_t c = h[2];
    std::uint32_t d = h[3];

    for (std::size_t i = 0U; i < 64U; ++i) {
        std::uint32_t f = 0U;
        std::uint32_t g = 0U;
        if (i < 16U) {
            f = (b & c) | ((~b) & d);
            g = static_cast<std::uint32_t>(i);
        } else if (i < 32U) {
            f = (d & b) | ((~d) & c);
            g = static_cast<std::uint32_t>((5U * i + 1U) % 16U);
        } else if (i < 48U) {
            f = b ^ c ^ d;
            g = static_cast<std::uint32_t>((3U * i + 5U) % 16U);
        } else {
            f = c ^ (b | (~d));
            g = static_cast<std::uint32_t>((7U * i) % 16U);
        }
        const std::uint32_t temp = d;
        d = c;
        c = b;
        b = b + rotl32(a + f + k[i] + w[g], s[i]);
        a = temp;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
}

void md5_init(Md5State& st) {
    st.h = {0x67452301U, 0xefcdab89U, 0x98badcfeU, 0x10325476U};
    st.buffer.fill(0U);
    st.bits = 0U;
    st.buffer_len = 0U;
}

void md5_update(Md5State& st, const std::uint8_t* data, std::size_t len) {
    SMB_EXPECT(data != nullptr || len == 0U);
    st.bits += static_cast<std::uint64_t>(len) * 8U;
    std::size_t offset = 0U;
    while (offset < len) {
        const std::size_t to_copy = std::min<std::size_t>(64U - st.buffer_len, len - offset);
        std::memcpy(st.buffer.data() + st.buffer_len, data + offset, to_copy);
        st.buffer_len += to_copy;
        offset += to_copy;
        if (st.buffer_len == 64U) {
            md5_transform(st.h, st.buffer.data());
            st.buffer_len = 0U;
        }
    }
}

std::array<std::uint8_t, 16> md5_final(Md5State& st) {
    std::array<std::uint8_t, 16> out{};
    const std::uint64_t bit_len = st.bits;
    const std::uint8_t pad80 = 0x80U;
    md5_update(st, &pad80, 1U);
    const std::uint8_t zero = 0U;
    while (st.buffer_len != 56U) {
        md5_update(st, &zero, 1U);
    }
    std::array<std::uint8_t, 8> len_le{};
    for (std::size_t i = 0U; i < 8U; ++i) {
        len_le[i] = static_cast<std::uint8_t>((bit_len >> (i * 8U)) & 0xFFU);
    }
    md5_update(st, len_le.data(), len_le.size());
    for (std::size_t i = 0U; i < 4U; ++i) {
        const std::uint32_t v = st.h[i];
        out[i * 4U + 0U] = static_cast<std::uint8_t>(v & 0xFFU);
        out[i * 4U + 1U] = static_cast<std::uint8_t>((v >> 8U) & 0xFFU);
        out[i * 4U + 2U] = static_cast<std::uint8_t>((v >> 16U) & 0xFFU);
        out[i * 4U + 3U] = static_cast<std::uint8_t>((v >> 24U) & 0xFFU);
    }
    return out;
}

std::array<std::uint8_t, 16> md5_hash(const std::vector<std::uint8_t>& data) {
    Md5State st{};
    md5_init(st);
    if (!data.empty()) {
        md5_update(st, data.data(), data.size());
    }
    return md5_final(st);
}

std::array<std::uint8_t, 16> hmac_md5(const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& msg) {
    std::array<std::uint8_t, 64> key_block{};
    key_block.fill(0U);
    if (key.size() > key_block.size()) {
        const std::array<std::uint8_t, 16> dig = md5_hash(key);
        std::memcpy(key_block.data(), dig.data(), dig.size());
    } else if (!key.empty()) {
        std::memcpy(key_block.data(), key.data(), key.size());
    }

    std::array<std::uint8_t, 64> ipad{};
    std::array<std::uint8_t, 64> opad{};
    for (std::size_t i = 0U; i < 64U; ++i) {
        ipad[i] = static_cast<std::uint8_t>(key_block[i] ^ 0x36U);
        opad[i] = static_cast<std::uint8_t>(key_block[i] ^ 0x5CU);
    }

    std::vector<std::uint8_t> inner{};
    inner.reserve(ipad.size() + msg.size());
    inner.insert(inner.end(), ipad.begin(), ipad.end());
    inner.insert(inner.end(), msg.begin(), msg.end());
    const std::array<std::uint8_t, 16> inner_hash = md5_hash(inner);

    std::vector<std::uint8_t> outer{};
    outer.reserve(opad.size() + inner_hash.size());
    outer.insert(outer.end(), opad.begin(), opad.end());
    outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
    return md5_hash(outer);
}

std::uint32_t rotr32(std::uint32_t value, std::uint32_t shift) {
    return (value >> shift) | (value << (32U - shift));
}

std::array<std::uint8_t, 32> sha256_hash(const std::vector<std::uint8_t>& data) {
    static const std::array<std::uint32_t, 64> k = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
    };

    std::array<std::uint32_t, 8> h = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
    };

    std::vector<std::uint8_t> msg = data;
    const std::uint64_t bit_len = static_cast<std::uint64_t>(msg.size()) * 8ULL;
    msg.push_back(0x80U);
    while ((msg.size() % 64U) != 56U) {
        msg.push_back(0U);
    }
    for (std::uint32_t shift = 56U;; shift -= 8U) {
        msg.push_back(static_cast<std::uint8_t>((bit_len >> shift) & 0xFFULL));
        if (shift == 0U) {
            break;
        }
    }

    for (std::size_t chunk = 0U; chunk < msg.size(); chunk += 64U) {
        std::array<std::uint32_t, 64> w{};
        for (std::size_t i = 0U; i < 16U; ++i) {
            const std::size_t off = chunk + (i * 4U);
            w[i] = (static_cast<std::uint32_t>(msg[off]) << 24U) |
                   (static_cast<std::uint32_t>(msg[off + 1U]) << 16U) |
                   (static_cast<std::uint32_t>(msg[off + 2U]) << 8U) |
                   static_cast<std::uint32_t>(msg[off + 3U]);
        }
        for (std::size_t i = 16U; i < 64U; ++i) {
            const std::uint32_t s0 = rotr32(w[i - 15U], 7U) ^ rotr32(w[i - 15U], 18U) ^ (w[i - 15U] >> 3U);
            const std::uint32_t s1 = rotr32(w[i - 2U], 17U) ^ rotr32(w[i - 2U], 19U) ^ (w[i - 2U] >> 10U);
            w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
        }

        std::uint32_t a = h[0];
        std::uint32_t b = h[1];
        std::uint32_t c = h[2];
        std::uint32_t d = h[3];
        std::uint32_t e = h[4];
        std::uint32_t f = h[5];
        std::uint32_t g = h[6];
        std::uint32_t hh = h[7];

        for (std::size_t i = 0U; i < 64U; ++i) {
            const std::uint32_t s1 = rotr32(e, 6U) ^ rotr32(e, 11U) ^ rotr32(e, 25U);
            const std::uint32_t ch = (e & f) ^ ((~e) & g);
            const std::uint32_t temp1 = hh + s1 + ch + k[i] + w[i];
            const std::uint32_t s0 = rotr32(a, 2U) ^ rotr32(a, 13U) ^ rotr32(a, 22U);
            const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t temp2 = s0 + maj;

            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    std::array<std::uint8_t, 32> out{};
    for (std::size_t i = 0U; i < h.size(); ++i) {
        out[i * 4U + 0U] = static_cast<std::uint8_t>((h[i] >> 24U) & 0xFFU);
        out[i * 4U + 1U] = static_cast<std::uint8_t>((h[i] >> 16U) & 0xFFU);
        out[i * 4U + 2U] = static_cast<std::uint8_t>((h[i] >> 8U) & 0xFFU);
        out[i * 4U + 3U] = static_cast<std::uint8_t>(h[i] & 0xFFU);
    }
    return out;
}

std::array<std::uint8_t, 32> hmac_sha256(const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& msg) {
    std::array<std::uint8_t, 64> key_block{};
    key_block.fill(0U);
    if (key.size() > key_block.size()) {
        const std::array<std::uint8_t, 32> dig = sha256_hash(key);
        std::memcpy(key_block.data(), dig.data(), dig.size());
    } else if (!key.empty()) {
        std::memcpy(key_block.data(), key.data(), key.size());
    }

    std::array<std::uint8_t, 64> ipad{};
    std::array<std::uint8_t, 64> opad{};
    for (std::size_t i = 0U; i < 64U; ++i) {
        ipad[i] = static_cast<std::uint8_t>(key_block[i] ^ 0x36U);
        opad[i] = static_cast<std::uint8_t>(key_block[i] ^ 0x5CU);
    }

    std::vector<std::uint8_t> inner{};
    inner.reserve(ipad.size() + msg.size());
    inner.insert(inner.end(), ipad.begin(), ipad.end());
    inner.insert(inner.end(), msg.begin(), msg.end());
    const std::array<std::uint8_t, 32> inner_hash = sha256_hash(inner);

    std::vector<std::uint8_t> outer{};
    outer.reserve(opad.size() + inner_hash.size());
    outer.insert(outer.end(), opad.begin(), opad.end());
    outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
    return sha256_hash(outer);
}

bool rc4_crypt(const std::vector<std::uint8_t>& key,
               const std::uint8_t* input,
               std::size_t input_len,
               std::uint8_t* output) {
    SMB_EXPECT(input != nullptr || input_len == 0U);
    SMB_EXPECT(output != nullptr || input_len == 0U);
    if (key.empty()) {
        return false;
    }

    std::array<std::uint8_t, 256> s{};
    for (std::size_t i = 0U; i < s.size(); ++i) {
        s[i] = static_cast<std::uint8_t>(i);
    }
    std::size_t j = 0U;
    for (std::size_t i = 0U; i < s.size(); ++i) {
        j = (j + s[i] + key[i % key.size()]) & 0xFFU;
        const std::uint8_t tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }

    std::size_t i = 0U;
    j = 0U;
    for (std::size_t n = 0U; n < input_len; ++n) {
        i = (i + 1U) & 0xFFU;
        j = (j + s[i]) & 0xFFU;
        const std::uint8_t tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
        const std::uint8_t k = s[(static_cast<std::size_t>(s[i]) + static_cast<std::size_t>(s[j])) & 0xFFU];
        output[n] = static_cast<std::uint8_t>(input[n] ^ k);
    }
    return true;
}

bool smb2_sign_packet(std::vector<std::uint8_t>& frame, const std::array<std::uint8_t, 16>& signing_key) {
    if (frame.size() < sizeof(Smb2Header)) {
        return false;
    }

    std::uint32_t flags = read_blob_le32(frame.data() + kSmb2HeaderFlagsOffset);
    flags |= kSmb2FlagSigned;
    const std::uint32_t flags_le = to_le32(flags);
    std::memcpy(frame.data() + kSmb2HeaderFlagsOffset, &flags_le, sizeof(flags_le));

    std::array<std::uint8_t, kSmb2SignatureSize> old_signature{};
    std::memcpy(old_signature.data(), frame.data() + kSmb2HeaderSignatureOffset, kSmb2SignatureSize);
    std::memset(frame.data() + kSmb2HeaderSignatureOffset, 0, kSmb2SignatureSize);

    const std::vector<std::uint8_t> key_vec(signing_key.begin(), signing_key.end());
    const std::array<std::uint8_t, 32> mac = hmac_sha256(key_vec, frame);
    std::memcpy(frame.data() + kSmb2HeaderSignatureOffset, mac.data(), kSmb2SignatureSize);
    (void)old_signature;
    return true;
}

bool smb2_verify_packet_signature(const std::vector<std::uint8_t>& frame, const std::array<std::uint8_t, 16>& signing_key) {
    if (frame.size() < sizeof(Smb2Header)) {
        return false;
    }
    const std::uint32_t flags = read_blob_le32(frame.data() + kSmb2HeaderFlagsOffset);
    if ((flags & kSmb2FlagSigned) == 0U) {
        return false;
    }

    std::array<std::uint8_t, kSmb2SignatureSize> signature{};
    std::memcpy(signature.data(), frame.data() + kSmb2HeaderSignatureOffset, kSmb2SignatureSize);

    std::vector<std::uint8_t> to_sign = frame;
    std::memset(to_sign.data() + kSmb2HeaderSignatureOffset, 0, kSmb2SignatureSize);
    const std::vector<std::uint8_t> key_vec(signing_key.begin(), signing_key.end());
    const std::array<std::uint8_t, 32> mac = hmac_sha256(key_vec, to_sign);
    return constant_time_equal_bytes(signature.data(), mac.data(), kSmb2SignatureSize);
}

std::vector<std::uint8_t> to_utf16le_ascii(const std::string& text, bool uppercase) {
    std::vector<std::uint8_t> out{};
    out.reserve(text.size() * 2U);
    for (char c : text) {
        unsigned char ch = static_cast<unsigned char>(c);
        if (uppercase) {
            ch = static_cast<unsigned char>(std::toupper(ch));
        }
        out.push_back(static_cast<std::uint8_t>(ch));
        out.push_back(0U);
    }
    return out;
}

std::array<std::uint8_t, 16> md4_hash(const std::vector<std::uint8_t>& data) {
    Md4State st{};
    md4_init(st);
    if (!data.empty()) {
        md4_update(st, data.data(), data.size());
    }
    return md4_final(st);
}

bool derive_userpass_signing_key(const std::string& username,
                                 const std::string& password,
                                 std::array<std::uint8_t, 16>& out_key) {
    out_key.fill(0U);
    if (username.empty() || password.empty()) {
        return false;
    }
    const std::vector<std::uint8_t> pass_utf16 = to_utf16le_ascii(password, false);
    const std::array<std::uint8_t, 16> nt_hash = md4_hash(pass_utf16);
    std::vector<std::uint8_t> nt_hash_key(nt_hash.begin(), nt_hash.end());
    const std::vector<std::uint8_t> user_utf16 = to_utf16le_ascii(ascii_upper_copy(username), false);
    out_key = hmac_md5(nt_hash_key, user_utf16);
    return true;
}

std::array<std::uint8_t, 16> apply_ntlm_key_exchange_if_needed(
    const NtlmType3Fields& fields,
    const std::array<std::uint8_t, 16>& session_base_key) {
    constexpr std::uint32_t kNtlmNegotiateKeyExchange = 0x40000000U;
    if (((fields.negotiate_flags & kNtlmNegotiateKeyExchange) == 0U) ||
        (fields.encrypted_session_key == nullptr) ||
        (fields.encrypted_session_key_len != 16U)) {
        return session_base_key;
    }

    std::vector<std::uint8_t> rc4_key(session_base_key.begin(), session_base_key.end());
    std::array<std::uint8_t, 16> exported{};
    if (!rc4_crypt(rc4_key, fields.encrypted_session_key, fields.encrypted_session_key_len, exported.data())) {
        return session_base_key;
    }
    return exported;
}

std::uint64_t read_be64(const std::uint8_t* data) {
    SMB_EXPECT(data != nullptr);
    std::uint64_t out = 0U;
    for (std::size_t i = 0U; i < 8U; ++i) {
        out = (out << 8U) | static_cast<std::uint64_t>(data[i]);
    }
    return out;
}

void write_be64(std::uint64_t value, std::uint8_t* out) {
    SMB_EXPECT(out != nullptr);
    for (std::size_t i = 0U; i < 8U; ++i) {
        const std::size_t shift = (7U - i) * 8U;
        out[i] = static_cast<std::uint8_t>((value >> shift) & 0xFFU);
    }
}

std::uint8_t des_set_odd_parity(std::uint8_t value) {
    value = static_cast<std::uint8_t>(value & 0xFEU);
    std::uint8_t ones = 0U;
    for (std::size_t bit = 1U; bit < 8U; ++bit) {
        ones = static_cast<std::uint8_t>(ones + ((value >> bit) & 0x01U));
    }
    if ((ones % 2U) == 0U) {
        value = static_cast<std::uint8_t>(value | 0x01U);
    }
    return value;
}

std::array<std::uint8_t, 8> ntlm_expand_des_key_56_to_64(const std::uint8_t* key7) {
    SMB_EXPECT(key7 != nullptr);
    std::array<std::uint8_t, 8> out{};
    const std::uint32_t k0 = static_cast<std::uint32_t>(key7[0]);
    const std::uint32_t k1 = static_cast<std::uint32_t>(key7[1]);
    const std::uint32_t k2 = static_cast<std::uint32_t>(key7[2]);
    const std::uint32_t k3 = static_cast<std::uint32_t>(key7[3]);
    const std::uint32_t k4 = static_cast<std::uint32_t>(key7[4]);
    const std::uint32_t k5 = static_cast<std::uint32_t>(key7[5]);
    const std::uint32_t k6 = static_cast<std::uint32_t>(key7[6]);
    out[0] = static_cast<std::uint8_t>(k0 & 0xFEU);
    out[1] = static_cast<std::uint8_t>(((k0 << 7U) | (k1 >> 1U)) & 0xFEU);
    out[2] = static_cast<std::uint8_t>(((k1 << 6U) | (k2 >> 2U)) & 0xFEU);
    out[3] = static_cast<std::uint8_t>(((k2 << 5U) | (k3 >> 3U)) & 0xFEU);
    out[4] = static_cast<std::uint8_t>(((k3 << 4U) | (k4 >> 4U)) & 0xFEU);
    out[5] = static_cast<std::uint8_t>(((k4 << 3U) | (k5 >> 5U)) & 0xFEU);
    out[6] = static_cast<std::uint8_t>(((k5 << 2U) | (k6 >> 6U)) & 0xFEU);
    out[7] = static_cast<std::uint8_t>((k6 << 1U) & 0xFEU);
    for (auto& b : out) {
        b = des_set_odd_parity(b);
    }
    return out;
}

std::uint64_t des_permute(std::uint64_t input,
                          const std::uint8_t* table,
                          std::size_t out_bits,
                          std::size_t in_bits) {
    SMB_EXPECT(table != nullptr);
    std::uint64_t out = 0U;
    for (std::size_t i = 0U; i < out_bits; ++i) {
        out <<= 1U;
        const std::size_t src = static_cast<std::size_t>(table[i] - 1U);
        const std::size_t shift = (in_bits - 1U) - src;
        out |= (input >> shift) & 0x01ULL;
    }
    return out;
}

const std::array<std::uint8_t, 64> kDesIp = {
    58U, 50U, 42U, 34U, 26U, 18U, 10U, 2U,
    60U, 52U, 44U, 36U, 28U, 20U, 12U, 4U,
    62U, 54U, 46U, 38U, 30U, 22U, 14U, 6U,
    64U, 56U, 48U, 40U, 32U, 24U, 16U, 8U,
    57U, 49U, 41U, 33U, 25U, 17U, 9U, 1U,
    59U, 51U, 43U, 35U, 27U, 19U, 11U, 3U,
    61U, 53U, 45U, 37U, 29U, 21U, 13U, 5U,
    63U, 55U, 47U, 39U, 31U, 23U, 15U, 7U,
};

const std::array<std::uint8_t, 64> kDesFp = {
    40U, 8U, 48U, 16U, 56U, 24U, 64U, 32U,
    39U, 7U, 47U, 15U, 55U, 23U, 63U, 31U,
    38U, 6U, 46U, 14U, 54U, 22U, 62U, 30U,
    37U, 5U, 45U, 13U, 53U, 21U, 61U, 29U,
    36U, 4U, 44U, 12U, 52U, 20U, 60U, 28U,
    35U, 3U, 43U, 11U, 51U, 19U, 59U, 27U,
    34U, 2U, 42U, 10U, 50U, 18U, 58U, 26U,
    33U, 1U, 41U, 9U, 49U, 17U, 57U, 25U,
};

const std::array<std::uint8_t, 48> kDesE = {
    32U, 1U, 2U, 3U, 4U, 5U,
    4U, 5U, 6U, 7U, 8U, 9U,
    8U, 9U, 10U, 11U, 12U, 13U,
    12U, 13U, 14U, 15U, 16U, 17U,
    16U, 17U, 18U, 19U, 20U, 21U,
    20U, 21U, 22U, 23U, 24U, 25U,
    24U, 25U, 26U, 27U, 28U, 29U,
    28U, 29U, 30U, 31U, 32U, 1U,
};

const std::array<std::uint8_t, 32> kDesP = {
    16U, 7U, 20U, 21U, 29U, 12U, 28U, 17U,
    1U, 15U, 23U, 26U, 5U, 18U, 31U, 10U,
    2U, 8U, 24U, 14U, 32U, 27U, 3U, 9U,
    19U, 13U, 30U, 6U, 22U, 11U, 4U, 25U,
};

const std::array<std::uint8_t, 56> kDesPc1 = {
    57U, 49U, 41U, 33U, 25U, 17U, 9U,
    1U, 58U, 50U, 42U, 34U, 26U, 18U,
    10U, 2U, 59U, 51U, 43U, 35U, 27U,
    19U, 11U, 3U, 60U, 52U, 44U, 36U,
    63U, 55U, 47U, 39U, 31U, 23U, 15U,
    7U, 62U, 54U, 46U, 38U, 30U, 22U,
    14U, 6U, 61U, 53U, 45U, 37U, 29U,
    21U, 13U, 5U, 28U, 20U, 12U, 4U,
};

const std::array<std::uint8_t, 48> kDesPc2 = {
    14U, 17U, 11U, 24U, 1U, 5U,
    3U, 28U, 15U, 6U, 21U, 10U,
    23U, 19U, 12U, 4U, 26U, 8U,
    16U, 7U, 27U, 20U, 13U, 2U,
    41U, 52U, 31U, 37U, 47U, 55U,
    30U, 40U, 51U, 45U, 33U, 48U,
    44U, 49U, 39U, 56U, 34U, 53U,
    46U, 42U, 50U, 36U, 29U, 32U,
};

const std::array<std::uint8_t, 16> kDesKeyShifts = {
    1U, 1U, 2U, 2U, 2U, 2U, 2U, 2U,
    1U, 2U, 2U, 2U, 2U, 2U, 2U, 1U,
};

const std::array<std::array<std::uint8_t, 64>, 8> kDesSBoxes = {{
    {14U, 4U, 13U, 1U, 2U, 15U, 11U, 8U, 3U, 10U, 6U, 12U, 5U, 9U, 0U, 7U,
     0U, 15U, 7U, 4U, 14U, 2U, 13U, 1U, 10U, 6U, 12U, 11U, 9U, 5U, 3U, 8U,
     4U, 1U, 14U, 8U, 13U, 6U, 2U, 11U, 15U, 12U, 9U, 7U, 3U, 10U, 5U, 0U,
     15U, 12U, 8U, 2U, 4U, 9U, 1U, 7U, 5U, 11U, 3U, 14U, 10U, 0U, 6U, 13U},
    {15U, 1U, 8U, 14U, 6U, 11U, 3U, 4U, 9U, 7U, 2U, 13U, 12U, 0U, 5U, 10U,
     3U, 13U, 4U, 7U, 15U, 2U, 8U, 14U, 12U, 0U, 1U, 10U, 6U, 9U, 11U, 5U,
     0U, 14U, 7U, 11U, 10U, 4U, 13U, 1U, 5U, 8U, 12U, 6U, 9U, 3U, 2U, 15U,
     13U, 8U, 10U, 1U, 3U, 15U, 4U, 2U, 11U, 6U, 7U, 12U, 0U, 5U, 14U, 9U},
    {10U, 0U, 9U, 14U, 6U, 3U, 15U, 5U, 1U, 13U, 12U, 7U, 11U, 4U, 2U, 8U,
     13U, 7U, 0U, 9U, 3U, 4U, 6U, 10U, 2U, 8U, 5U, 14U, 12U, 11U, 15U, 1U,
     13U, 6U, 4U, 9U, 8U, 15U, 3U, 0U, 11U, 1U, 2U, 12U, 5U, 10U, 14U, 7U,
     1U, 10U, 13U, 0U, 6U, 9U, 8U, 7U, 4U, 15U, 14U, 3U, 11U, 5U, 2U, 12U},
    {7U, 13U, 14U, 3U, 0U, 6U, 9U, 10U, 1U, 2U, 8U, 5U, 11U, 12U, 4U, 15U,
     13U, 8U, 11U, 5U, 6U, 15U, 0U, 3U, 4U, 7U, 2U, 12U, 1U, 10U, 14U, 9U,
     10U, 6U, 9U, 0U, 12U, 11U, 7U, 13U, 15U, 1U, 3U, 14U, 5U, 2U, 8U, 4U,
     3U, 15U, 0U, 6U, 10U, 1U, 13U, 8U, 9U, 4U, 5U, 11U, 12U, 7U, 2U, 14U},
    {2U, 12U, 4U, 1U, 7U, 10U, 11U, 6U, 8U, 5U, 3U, 15U, 13U, 0U, 14U, 9U,
     14U, 11U, 2U, 12U, 4U, 7U, 13U, 1U, 5U, 0U, 15U, 10U, 3U, 9U, 8U, 6U,
     4U, 2U, 1U, 11U, 10U, 13U, 7U, 8U, 15U, 9U, 12U, 5U, 6U, 3U, 0U, 14U,
     11U, 8U, 12U, 7U, 1U, 14U, 2U, 13U, 6U, 15U, 0U, 9U, 10U, 4U, 5U, 3U},
    {12U, 1U, 10U, 15U, 9U, 2U, 6U, 8U, 0U, 13U, 3U, 4U, 14U, 7U, 5U, 11U,
     10U, 15U, 4U, 2U, 7U, 12U, 9U, 5U, 6U, 1U, 13U, 14U, 0U, 11U, 3U, 8U,
     9U, 14U, 15U, 5U, 2U, 8U, 12U, 3U, 7U, 0U, 4U, 10U, 1U, 13U, 11U, 6U,
     4U, 3U, 2U, 12U, 9U, 5U, 15U, 10U, 11U, 14U, 1U, 7U, 6U, 0U, 8U, 13U},
    {4U, 11U, 2U, 14U, 15U, 0U, 8U, 13U, 3U, 12U, 9U, 7U, 5U, 10U, 6U, 1U,
     13U, 0U, 11U, 7U, 4U, 9U, 1U, 10U, 14U, 3U, 5U, 12U, 2U, 15U, 8U, 6U,
     1U, 4U, 11U, 13U, 12U, 3U, 7U, 14U, 10U, 15U, 6U, 8U, 0U, 5U, 9U, 2U,
     6U, 11U, 13U, 8U, 1U, 4U, 10U, 7U, 9U, 5U, 0U, 15U, 14U, 2U, 3U, 12U},
    {13U, 2U, 8U, 4U, 6U, 15U, 11U, 1U, 10U, 9U, 3U, 14U, 5U, 0U, 12U, 7U,
     1U, 15U, 13U, 8U, 10U, 3U, 7U, 4U, 12U, 5U, 6U, 11U, 0U, 14U, 9U, 2U,
     7U, 11U, 4U, 1U, 9U, 12U, 14U, 2U, 0U, 6U, 10U, 13U, 15U, 3U, 5U, 8U,
     2U, 1U, 14U, 7U, 4U, 10U, 8U, 13U, 15U, 12U, 9U, 0U, 3U, 5U, 6U, 11U},
}};

std::array<std::uint64_t, 16> des_build_subkeys(const std::array<std::uint8_t, 8>& key64) {
    const std::uint64_t key_bits = read_be64(key64.data());
    const std::uint64_t key56 = des_permute(key_bits, kDesPc1.data(), 56U, 64U);
    std::uint32_t c = static_cast<std::uint32_t>((key56 >> 28U) & 0x0FFFFFFFU);
    std::uint32_t d = static_cast<std::uint32_t>(key56 & 0x0FFFFFFFU);
    std::array<std::uint64_t, 16> subkeys{};
    for (std::size_t round = 0U; round < subkeys.size(); ++round) {
        const std::uint8_t shift = kDesKeyShifts[round];
        c = static_cast<std::uint32_t>(((c << shift) | (c >> (28U - shift))) & 0x0FFFFFFFU);
        d = static_cast<std::uint32_t>(((d << shift) | (d >> (28U - shift))) & 0x0FFFFFFFU);
        const std::uint64_t cd = (static_cast<std::uint64_t>(c) << 28U) | static_cast<std::uint64_t>(d);
        subkeys[round] = des_permute(cd, kDesPc2.data(), 48U, 56U);
    }
    return subkeys;
}

std::uint32_t des_feistel(std::uint32_t right, std::uint64_t subkey) {
    const std::uint64_t expanded = des_permute(static_cast<std::uint64_t>(right), kDesE.data(), 48U, 32U);
    const std::uint64_t mixed = expanded ^ subkey;
    std::uint32_t sbox_out = 0U;
    for (std::size_t box = 0U; box < 8U; ++box) {
        const std::size_t shift = 42U - (box * 6U);
        const std::uint8_t bits6 = static_cast<std::uint8_t>((mixed >> shift) & 0x3FU);
        const std::uint8_t row =
            static_cast<std::uint8_t>(((bits6 & 0x20U) >> 4U) | (bits6 & 0x01U));
        const std::uint8_t col = static_cast<std::uint8_t>((bits6 >> 1U) & 0x0FU);
        const std::uint8_t value = kDesSBoxes[box][static_cast<std::size_t>(row) * 16U + col];
        sbox_out = static_cast<std::uint32_t>((sbox_out << 4U) | value);
    }
    return static_cast<std::uint32_t>(des_permute(static_cast<std::uint64_t>(sbox_out), kDesP.data(), 32U, 32U));
}

std::array<std::uint8_t, 8> des_encrypt_block(const std::array<std::uint8_t, 8>& key64,
                                               const std::array<std::uint8_t, 8>& plaintext) {
    const auto subkeys = des_build_subkeys(key64);
    const std::uint64_t input = read_be64(plaintext.data());
    const std::uint64_t ip = des_permute(input, kDesIp.data(), 64U, 64U);
    std::uint32_t l = static_cast<std::uint32_t>((ip >> 32U) & 0xFFFFFFFFU);
    std::uint32_t r = static_cast<std::uint32_t>(ip & 0xFFFFFFFFU);
    for (std::size_t round = 0U; round < subkeys.size(); ++round) {
        const std::uint32_t new_l = r;
        const std::uint32_t new_r = static_cast<std::uint32_t>(l ^ des_feistel(r, subkeys[round]));
        l = new_l;
        r = new_r;
    }
    const std::uint64_t pre_output = (static_cast<std::uint64_t>(r) << 32U) | static_cast<std::uint64_t>(l);
    const std::uint64_t output = des_permute(pre_output, kDesFp.data(), 64U, 64U);
    std::array<std::uint8_t, 8> out{};
    write_be64(output, out.data());
    return out;
}

std::array<std::uint8_t, 24> ntlm_desl_encrypt(const std::array<std::uint8_t, 16>& nt_hash,
                                                const std::array<std::uint8_t, 8>& challenge) {
    std::array<std::uint8_t, 21> key21{};
    std::memcpy(key21.data(), nt_hash.data(), nt_hash.size());
    std::array<std::uint8_t, 24> out{};
    for (std::size_t i = 0U; i < 3U; ++i) {
        const std::array<std::uint8_t, 8> key64 = ntlm_expand_des_key_56_to_64(key21.data() + (i * 7U));
        const std::array<std::uint8_t, 8> block = des_encrypt_block(key64, challenge);
        std::memcpy(out.data() + (i * 8U), block.data(), block.size());
    }
    return out;
}

bool des_known_vector_ok() {
    const std::array<std::uint8_t, 8> key = {0x13U, 0x34U, 0x57U, 0x79U, 0x9BU, 0xBCU, 0xDFU, 0xF1U};
    const std::array<std::uint8_t, 8> plain = {0x01U, 0x23U, 0x45U, 0x67U, 0x89U, 0xABU, 0xCDU, 0xEFU};
    const std::array<std::uint8_t, 8> expected = {0x85U, 0xE8U, 0x13U, 0x54U, 0x0FU, 0x0AU, 0xB4U, 0x05U};
    return des_encrypt_block(key, plain) == expected;
}

bool verify_ntlm_legacy_response(const NtlmType3Fields& fields,
                                 const std::array<std::uint8_t, 16>& nt_hash,
                                 const std::array<std::uint8_t, 8>& challenge) {
    if (fields.nt_response_len != 24U) {
        return false;
    }

    const std::array<std::uint8_t, 24> expected_ntlmv1 = ntlm_desl_encrypt(nt_hash, challenge);
    if (constant_time_equal_bytes(fields.nt_response, expected_ntlmv1.data(), expected_ntlmv1.size())) {
        return true;
    }

    if (fields.lm_response_len < 8U) {
        return false;
    }

    std::vector<std::uint8_t> ntlm2_input{};
    ntlm2_input.reserve(challenge.size() + 8U);
    ntlm2_input.insert(ntlm2_input.end(), challenge.begin(), challenge.end());
    ntlm2_input.insert(ntlm2_input.end(), fields.lm_response, fields.lm_response + 8U);
    const std::array<std::uint8_t, 16> ntlm2_hash = md5_hash(ntlm2_input);
    std::array<std::uint8_t, 8> session_challenge{};
    std::memcpy(session_challenge.data(), ntlm2_hash.data(), session_challenge.size());
    const std::array<std::uint8_t, 24> expected_ntlm2_session = ntlm_desl_encrypt(nt_hash, session_challenge);
    return constant_time_equal_bytes(fields.nt_response, expected_ntlm2_session.data(), expected_ntlm2_session.size());
}

bool verify_ntlm_type3_ntlmv2(const std::uint8_t* blob_data,
                              std::size_t blob_size,
                              const AuthConfig& auth,
                              const std::array<std::uint8_t, 8>& challenge,
                              std::array<std::uint8_t, 16>* out_session_key) {
    SMB_EXPECT(blob_data != nullptr);
    if (out_session_key != nullptr) {
        out_session_key->fill(0U);
    }
    if (auth.username.empty() || auth.password.empty()) {
        return false;
    }
    NtlmType3Fields fields{};
    if (!extract_ntlm_type3_fields(blob_data, blob_size, fields)) {
        return false;
    }
    const std::string canonical_user = strip_qualified_username(fields.username);
    if (!ascii_case_equal(canonical_user, auth.username)) {
        return false;
    }

    const std::vector<std::uint8_t> pass_utf16 = to_utf16le_ascii(auth.password, false);
    const std::array<std::uint8_t, 16> nt_hash = md4_hash(pass_utf16);
    std::vector<std::uint8_t> nt_hash_key(nt_hash.begin(), nt_hash.end());

    if (fields.nt_response_len <= 24U) {
        return false;
    }
    std::vector<std::string> user_candidates{};
    (void)push_unique_non_empty(user_candidates, fields.username);
    (void)push_unique_non_empty(user_candidates, canonical_user);
    (void)push_unique_non_empty(user_candidates, auth.username);

    std::vector<std::string> domain_candidates{};
    (void)push_unique_non_empty(domain_candidates, fields.domain);
    (void)push_unique_non_empty(domain_candidates, domain_from_qualified_username(fields.username));
    (void)push_unique_non_empty(domain_candidates, ascii_upper_copy(fields.domain));
    (void)push_unique_non_empty(domain_candidates, ascii_lower_copy(fields.domain));
    domain_candidates.push_back(std::string{});  // many clients send/expect empty domain in NTLMv2 hash

    const std::size_t blob_part_len = fields.nt_response_len - 16U;
    std::vector<std::uint8_t> proof_input{};
    proof_input.reserve(challenge.size() + blob_part_len);
    proof_input.insert(proof_input.end(), challenge.begin(), challenge.end());
    proof_input.insert(proof_input.end(),
                       fields.nt_response + 16U,
                       fields.nt_response + fields.nt_response_len);

    for (const auto& user_for_hash : user_candidates) {
        const std::vector<std::uint8_t> user_utf16 = to_utf16le_ascii(user_for_hash, true);
        for (const auto& domain_for_hash : domain_candidates) {
            std::vector<std::uint8_t> identity = user_utf16;
            const std::vector<std::uint8_t> domain_utf16 = to_utf16le_ascii(domain_for_hash, false);
            identity.insert(identity.end(), domain_utf16.begin(), domain_utf16.end());
            const std::array<std::uint8_t, 16> ntlm_v2_hash = hmac_md5(nt_hash_key, identity);
            std::vector<std::uint8_t> ntlm_v2_key(ntlm_v2_hash.begin(), ntlm_v2_hash.end());
            const std::array<std::uint8_t, 16> expected_proof = hmac_md5(ntlm_v2_key, proof_input);
            if (constant_time_equal_bytes(fields.nt_response, expected_proof.data(), expected_proof.size())) {
                if (out_session_key != nullptr) {
                    std::vector<std::uint8_t> nt_proof(fields.nt_response, fields.nt_response + 16U);
                    const std::array<std::uint8_t, 16> session_base_key = hmac_md5(ntlm_v2_key, nt_proof);
                    *out_session_key = apply_ntlm_key_exchange_if_needed(fields, session_base_key);
                }
                return true;
            }
        }
    }
    return false;
}

bool is_authenticated_and_tree_ready(const ParsedRequestHeader& parsed, const ConnectionState& state) {
    if (!state.session_established) {
        return false;
    }
    if (parsed.session_id != state.session_id) {
        return false;
    }
    if (!state.tree_connected) {
        return false;
    }
    if (parsed.tree_id != state.tree_id) {
        return false;
    }
    return true;
}

bool compute_write_access(std::uint32_t desired_access) {
    return (desired_access & 0x40000000U) != 0U ||
           (desired_access & 0x00000002U) != 0U ||
           (desired_access & 0x00000004U) != 0U ||
           (desired_access & 0x00000100U) != 0U;
}

bool compute_delete_access(std::uint32_t desired_access) {
    return (desired_access & kDesiredAccessDelete) != 0U;
}

std::uint32_t remove_path_for_delete_on_close(const std::string& full_path) {
    std::error_code ec{};
    const std::filesystem::path path(full_path);
    const bool removed = std::filesystem::remove(path, ec);
    if (ec) {
        if ((ec == std::errc::permission_denied) ||
            (ec == std::errc::operation_not_permitted) ||
            (ec == std::errc::directory_not_empty) ||
            (ec == std::errc::device_or_resource_busy)) {
            return kStatusAccessDenied;
        }
        if (ec == std::errc::no_such_file_or_directory) {
            return kStatusObjectNameNotFound;
        }
        return kStatusInternalError;
    }
    if (removed) {
        return kStatusSuccess;
    }
    const bool exists = std::filesystem::exists(path, ec);
    if (ec) {
        return kStatusInternalError;
    }
    return exists ? kStatusAccessDenied : kStatusObjectNameNotFound;
}

std::uint32_t rename_path_for_set_info(const std::string& source_full_path,
                                       const std::string& target_full_path,
                                       bool replace_if_exists,
                                       bool source_is_directory) {
    if (source_full_path == target_full_path) {
        return kStatusSuccess;
    }

    std::error_code ec{};
    const std::filesystem::path source_path(source_full_path);
    const std::filesystem::path target_path(target_full_path);
    const bool target_exists = std::filesystem::exists(target_path, ec);
    if (ec) {
        return kStatusInternalError;
    }
    if (target_exists) {
        const bool target_is_directory = std::filesystem::is_directory(target_path, ec);
        if (ec) {
            return kStatusInternalError;
        }
        if (!replace_if_exists) {
            return kStatusObjectNameCollision;
        }
        if (target_is_directory != source_is_directory) {
            return kStatusAccessDenied;
        }
        if (target_is_directory) {
            const bool target_is_empty = std::filesystem::is_empty(target_path, ec);
            if (ec) {
                return kStatusInternalError;
            }
            if (!target_is_empty) {
                return kStatusAccessDenied;
            }
        }
        const bool removed = std::filesystem::remove(target_path, ec);
        if (ec) {
            if ((ec == std::errc::permission_denied) ||
                (ec == std::errc::operation_not_permitted) ||
                (ec == std::errc::directory_not_empty) ||
                (ec == std::errc::device_or_resource_busy)) {
                return kStatusAccessDenied;
            }
            return kStatusInternalError;
        }
        if (!removed) {
            return kStatusAccessDenied;
        }
    }

    std::filesystem::rename(source_path, target_path, ec);
    if (!ec) {
        return kStatusSuccess;
    }
    if ((ec == std::errc::permission_denied) ||
        (ec == std::errc::operation_not_permitted) ||
        (ec == std::errc::directory_not_empty) ||
        (ec == std::errc::device_or_resource_busy) ||
        (ec == std::errc::cross_device_link)) {
        return kStatusAccessDenied;
    }
    if (ec == std::errc::file_exists) {
        return kStatusObjectNameCollision;
    }
    if (ec == std::errc::no_such_file_or_directory) {
        return kStatusObjectNameNotFound;
    }
    return kStatusInternalError;
}

std::uint32_t open_or_create_file(const std::string& full_path,
                                  std::uint32_t desired_access,
                                  std::uint32_t disposition,
                                  const ShareSecurityConfig& hardening,
                                  ConnectionState::OpenFileHandle& out_file,
                                  std::uint32_t& create_action) {
    const bool wants_write = compute_write_access(desired_access);
    const bool wants_delete = compute_delete_access(desired_access);
    if (hardening.read_only && (wants_write || wants_delete)) {
        return kStatusAccessDenied;
    }
    std::error_code ec{};
    const std::filesystem::path file_path(full_path);
    const std::filesystem::path parent = file_path.parent_path();
    if (parent.empty() || !std::filesystem::exists(parent, ec) || !std::filesystem::is_directory(parent, ec)) {
        return kStatusObjectPathNotFound;
    }
    if (ec) {
        return kStatusInternalError;
    }

    const bool exists = std::filesystem::exists(file_path, ec);
    if (ec) {
        return kStatusInternalError;
    }
    if (!hardening.allow_overwrite && exists &&
        ((disposition == kFileSupersede) || (disposition == kFileOverwrite) || (disposition == kFileOverwriteIf))) {
        return kStatusAccessDenied;
    }

    const char* mode = nullptr;
    switch (disposition) {
        case kFileSupersede:
            if (!wants_write) {
                return kStatusAccessDenied;
            }
            mode = "w+b";
            create_action = exists ? kFileActionSuperseded : kFileActionCreated;
            break;
        case kFileOpen:
            if (!exists) {
                return kStatusObjectNameNotFound;
            }
            mode = wants_write ? "r+b" : "rb";
            create_action = kFileActionOpened;
            break;
        case kFileCreate:
            if (exists) {
                return kStatusObjectNameCollision;
            }
            if (!wants_write) {
                return kStatusAccessDenied;
            }
            mode = "w+b";
            create_action = kFileActionCreated;
            break;
        case kFileOpenIf:
            if (exists) {
                mode = wants_write ? "r+b" : "rb";
                create_action = kFileActionOpened;
            } else {
                if (!wants_write) {
                    return kStatusAccessDenied;
                }
                mode = "w+b";
                create_action = kFileActionCreated;
            }
            break;
        case kFileOverwrite:
            if (!exists) {
                return kStatusObjectNameNotFound;
            }
            if (!wants_write) {
                return kStatusAccessDenied;
            }
            mode = "w+b";
            create_action = kFileActionOverwritten;
            break;
        case kFileOverwriteIf:
            if (!wants_write) {
                return kStatusAccessDenied;
            }
            mode = "w+b";
            create_action = exists ? kFileActionOverwritten : kFileActionCreated;
            break;
        default:
            return kStatusInvalidParameter;
    }

    errno = 0;
    std::FILE* f = std::fopen(full_path.c_str(), mode);
    if (f == nullptr) {
        if ((errno == EACCES) || (errno == EPERM)) {
            return kStatusAccessDenied;
        }
        if (errno == ENOENT) {
            return kStatusObjectPathNotFound;
        }
        return kStatusInternalError;
    }

    out_file.persistent_id = g_next_file_id.fetch_add(1U, std::memory_order_relaxed);
    out_file.volatile_id = g_next_file_id.fetch_add(1U, std::memory_order_relaxed);
    out_file.stream = f;
    out_file.writable = wants_write;
    out_file.delete_allowed = wants_delete;
    out_file.full_path = full_path;
    return kStatusSuccess;
}

RequestResult process_request_single(const std::vector<std::uint8_t>& payload,
                                    ConnectionState& state,
                                    const AuthConfig& auth,
                                    const std::string& share_dir,
                                    const ShareSecurityConfig& hardening,
                                    const std::string& client_ip,
                                    const AbuseProtectionConfig& abuse_cfg,
                                    const std::array<std::uint8_t, 16>& server_guid,
                                    std::uint64_t start_time_filetime) {
    const auto parsed = parse_request_header(payload);
    if (!parsed.has_value()) {
        return {std::vector<std::uint8_t>{}, false};
    }

    if (parsed->command == static_cast<std::uint16_t>(Smb2Command::Negotiate)) {
        if (!validate_negotiate_request(payload)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    false};
        }
        close_all_open_files(state);
        state.negotiated = true;
        state.session_established = false;
        state.session_setup_token_sent = false;
        state.signing_key_valid = false;
        state.signing_key.fill(0U);
        state.ntlm_challenge_sent = false;
        state.ntlm_challenge_valid = false;
        state.seen_signed_message_ids.clear();
        state.session_id = 0U;
        state.tree_connected = false;
        state.tree_id = 0U;
        std::uint16_t security_mode = 0U;
        if (auth.signing_enabled && auth.require_auth) {
            security_mode = static_cast<std::uint16_t>(security_mode | 0x0001U);  // SMB2_NEGOTIATE_SIGNING_ENABLED
            if (auth.signing_required) {
                security_mode = static_cast<std::uint16_t>(security_mode | 0x0002U);  // SMB2_NEGOTIATE_SIGNING_REQUIRED
            }
        }
        return {build_negotiate_response(parsed->message_id, server_guid, start_time_filetime, security_mode), true};
    }

    if (parsed->command == static_cast<std::uint16_t>(Smb2Command::SessionSetup)) {
        if (!state.negotiated) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusRequestNotAccepted,
                                         parsed->session_id,
                                         parsed->tree_id),
                    false};
        }
        if (!validate_session_setup_request(payload)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    false};
        }
        const std::uint8_t* blob_data = nullptr;
        std::size_t blob_size = 0U;
        if (!extract_session_setup_security_blob(payload, blob_data, blob_size)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    false};
        }
        // Minimal SPNEGO NegTokenResp accept-completed + NTLMSSP OID improves smbclient interoperability.
        static const std::vector<std::uint8_t> kSpnegoAcceptCompleted = {
            0xA1U, 0x15U, 0x30U, 0x13U, 0xA0U, 0x03U, 0x0AU, 0x01U, 0x00U, 0xA1U, 0x0CU,
            0x06U, 0x0AU, 0x2BU, 0x06U, 0x01U, 0x04U, 0x01U, 0x82U, 0x37U, 0x02U, 0x02U, 0x0AU,
        };
        const auto reset_auth_state = [&]() {
            close_all_open_files(state);
            state.session_established = false;
            state.session_setup_token_sent = false;
            state.ntlm_challenge_sent = false;
            state.signing_key_valid = false;
            state.signing_key.fill(0U);
            state.session_id = 0U;
            state.tree_connected = false;
            state.tree_id = 0U;
            state.ntlm_challenge_valid = false;
            state.seen_signed_message_ids.clear();
        };
        const auto fail_logon = [&]() -> RequestResult {
            reset_auth_state();
            record_auth_failure_for_ip(client_ip, abuse_cfg);
            log_line("[warn] auth failure ip=" + client_ip);
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusLogonFailure,
                                         parsed->session_id,
                                         parsed->tree_id),
                    false};
        };

        if (!auth.require_auth) {
            if (!state.session_established) {
                state.session_id = g_next_session_id.fetch_add(1U, std::memory_order_relaxed);
                state.session_established = true;
                state.session_setup_token_sent = false;
                state.ntlm_challenge_sent = false;
                state.signing_key_valid = false;
                state.signing_key.fill(0U);
                state.tree_connected = false;
                state.tree_id = 0U;
                state.ntlm_challenge_valid = false;
                close_all_open_files(state);
                state.seen_signed_message_ids.clear();
            }
            std::vector<std::uint8_t> out_token{};
            std::uint16_t out_flags = 0U;
            if (!state.session_setup_token_sent) {
                out_token = kSpnegoAcceptCompleted;
                out_flags = 0x0001U;  // guest
                state.session_setup_token_sent = true;
            }
            return {
                build_session_setup_response(parsed->message_id, state.session_id, kStatusSuccess, out_flags, out_token),
                true,
            };
        }

        if ((blob_data == nullptr) || (blob_size == 0U)) {
            if (state.session_id == 0U) {
                state.session_id = g_next_session_id.fetch_add(1U, std::memory_order_relaxed);
            }
            state.session_established = false;
            state.tree_connected = false;
            state.tree_id = 0U;
            state.signing_key_valid = false;
            state.signing_key.fill(0U);
            close_all_open_files(state);
            const auto challenge = make_ntlm_server_challenge();
            if (!challenge.has_value()) {
                reset_auth_state();
                return {build_error_response(parsed->message_id,
                                             parsed->command,
                                             kStatusInternalError,
                                             parsed->session_id,
                                             parsed->tree_id),
                        false};
            }
            state.ntlm_challenge = challenge.value();
            state.ntlm_challenge_sent = true;
            state.ntlm_challenge_valid = true;
            const std::vector<std::uint8_t> challenge_token = build_ntlm_type2_challenge_token(state.ntlm_challenge);
            return {build_session_setup_response(parsed->message_id,
                                                 state.session_id,
                                                 kStatusMoreProcessingRequired,
                                                 0U,
                                                 challenge_token),
                    true};
        }

        if (blob_starts_with_user_pass_auth(blob_data, blob_size)) {
            return fail_logon();
        }

        const auto ntlm_type = extract_ntlm_message_type(blob_data, blob_size);
        if (!ntlm_type.has_value()) {
            return fail_logon();
        }
        if (ntlm_type.value() == 1U) {
            if (state.session_id == 0U) {
                state.session_id = g_next_session_id.fetch_add(1U, std::memory_order_relaxed);
            }
            state.session_established = false;
            state.tree_connected = false;
            state.tree_id = 0U;
            state.signing_key_valid = false;
            state.signing_key.fill(0U);
            close_all_open_files(state);
            const auto challenge = make_ntlm_server_challenge();
            if (!challenge.has_value()) {
                reset_auth_state();
                return {build_error_response(parsed->message_id,
                                             parsed->command,
                                             kStatusInternalError,
                                             parsed->session_id,
                                             parsed->tree_id),
                        false};
            }
            state.ntlm_challenge = challenge.value();
            state.ntlm_challenge_sent = true;
            state.ntlm_challenge_valid = true;
            const std::vector<std::uint8_t> challenge_token = build_ntlm_type2_challenge_token(state.ntlm_challenge);
            return {build_session_setup_response(parsed->message_id,
                                                 state.session_id,
                                                 kStatusMoreProcessingRequired,
                                                 0U,
                                                 challenge_token),
                    true};
        }
        if (ntlm_type.value() == 3U) {
            if ((state.session_id == 0U) || !state.ntlm_challenge_sent || !state.ntlm_challenge_valid ||
                ((parsed->session_id != 0U) && (parsed->session_id != state.session_id))) {
                return fail_logon();
            }
            std::array<std::uint8_t, 16> ntlm_session_key{};
            if (!verify_ntlm_type3_ntlmv2(blob_data, blob_size, auth, state.ntlm_challenge, &ntlm_session_key)) {
                return fail_logon();
            }
            state.session_established = true;
            state.session_setup_token_sent = true;
            state.ntlm_challenge_sent = false;
            state.ntlm_challenge_valid = false;
            state.tree_connected = false;
            state.tree_id = 0U;
            if (auth.signing_enabled) {
                state.signing_key = ntlm_session_key;
                state.signing_key_valid = true;
            } else {
                state.signing_key_valid = false;
                state.signing_key.fill(0U);
            }
            close_all_open_files(state);
            state.seen_signed_message_ids.clear();
            record_auth_success_for_ip(client_ip);
            return {build_session_setup_response(
                        parsed->message_id,
                        state.session_id,
                        kStatusSuccess,
                        auth.auth_session_guest_compat ? 0x0001U : 0U,
                        kSpnegoAcceptCompleted),
                    true};
        }

        return fail_logon();
    }

    if (parsed->command == static_cast<std::uint16_t>(Smb2Command::Logoff)) {
        if (!state.session_established || (parsed->session_id != state.session_id)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusRequestNotAccepted,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if (!validate_logoff_request(payload)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        const std::uint64_t old_session_id = state.session_id;
        close_all_open_files(state);
        state.session_established = false;
        state.session_setup_token_sent = false;
        state.ntlm_challenge_sent = false;
        state.ntlm_challenge_valid = false;
        state.signing_key_valid = false;
        state.signing_key.fill(0U);
        state.seen_signed_message_ids.clear();
        state.session_id = 0U;
        state.tree_connected = false;
        state.tree_id = 0U;
        return {build_logoff_response(parsed->message_id, old_session_id), true};
    }

    if (parsed->command == static_cast<std::uint16_t>(Smb2Command::TreeConnect)) {
        if (!state.session_established || (parsed->session_id != state.session_id)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusRequestNotAccepted,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        TreeConnectRequestFields req{};
        if (!parse_tree_connect_request(payload, req)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if (req.share_path.empty()) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusBadNetworkName,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if (!state.tree_connected) {
            state.tree_id = g_next_tree_id.fetch_add(1U, std::memory_order_relaxed);
            state.tree_connected = true;
        }
        return {build_tree_connect_response(parsed->message_id, state.session_id, state.tree_id), true};
    }

    if (parsed->command == static_cast<std::uint16_t>(Smb2Command::TreeDisconnect)) {
        if (!state.session_established || !state.tree_connected || (parsed->session_id != state.session_id) ||
            (parsed->tree_id != state.tree_id)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusRequestNotAccepted,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if (!validate_tree_disconnect_request(payload)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        close_all_open_files(state);
        const std::uint32_t response_tree_id = state.tree_id;
        state.tree_connected = false;
        state.tree_id = 0U;
        return {build_tree_disconnect_response(parsed->message_id, state.session_id, response_tree_id), true};
    }

    if (parsed->command == static_cast<std::uint16_t>(Smb2Command::Create)) {
        if (!is_authenticated_and_tree_ready(*parsed, state)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusRequestNotAccepted,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        CreateRequestFields req{};
        if (!parse_create_request(payload, req)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }

        std::string create_lookup_path = req.relative_path;
        if (contains_wildcards(create_lookup_path)) {
            const std::size_t slash = create_lookup_path.rfind('/');
            if (slash == std::string::npos) {
                create_lookup_path.clear();
            } else {
                create_lookup_path = create_lookup_path.substr(0U, slash);
            }
        }

        std::string full_path{};
        if (!resolve_share_file_path(share_dir, create_lookup_path, true, hardening.deny_dot_files, full_path)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusAccessDenied,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if (state.open_files.size() >= hardening.max_open_files) {
            const std::size_t target = (hardening.max_open_files > 0U) ? (hardening.max_open_files - 1U) : 0U;
            trim_open_directory_handles(state, target);
        }
        if (state.open_files.size() >= hardening.max_open_files) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInsufficientResources,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }

        std::error_code create_ec{};
        const std::filesystem::path create_path(full_path);
        const bool path_exists = std::filesystem::exists(create_path, create_ec);
        if (create_ec) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInternalError,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        const bool path_is_dir = path_exists && std::filesystem::is_directory(create_path, create_ec);
        if (create_ec) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInternalError,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        const bool directory_option = (req.create_options & 0x00000001U) != 0U;
        const bool wildcard_lookup = contains_wildcards(req.relative_path);
        if (directory_option) {
            std::uint32_t create_action = kFileActionOpened;
            if (path_exists) {
                if (!path_is_dir) {
                    return {build_error_response(parsed->message_id,
                                                 parsed->command,
                                                 kStatusAccessDenied,
                                                 parsed->session_id,
                                                 parsed->tree_id),
                            true};
                }
                if (req.create_disposition == kFileCreate) {
                    return {build_error_response(parsed->message_id,
                                                 parsed->command,
                                                 kStatusObjectNameCollision,
                                                 parsed->session_id,
                                                 parsed->tree_id),
                            true};
                }
                if ((req.create_disposition == kFileSupersede) ||
                    (req.create_disposition == kFileOverwrite) ||
                    (req.create_disposition == kFileOverwriteIf)) {
                    return {build_error_response(parsed->message_id,
                                                 parsed->command,
                                                 kStatusAccessDenied,
                                                 parsed->session_id,
                                                 parsed->tree_id),
                            true};
                }
                create_action = kFileActionOpened;
            } else {
                if ((req.create_disposition == kFileOpen) ||
                    (req.create_disposition == kFileOverwrite) ||
                    (req.create_disposition == kFileSupersede)) {
                    return {build_error_response(parsed->message_id,
                                                 parsed->command,
                                                 kStatusObjectNameNotFound,
                                                 parsed->session_id,
                                                 parsed->tree_id),
                            true};
                }
                if (req.create_disposition == kFileOverwriteIf) {
                    return {build_error_response(parsed->message_id,
                                                 parsed->command,
                                                 kStatusAccessDenied,
                                                 parsed->session_id,
                                                 parsed->tree_id),
                            true};
                }
                if (hardening.read_only) {
                    return {build_error_response(parsed->message_id,
                                                 parsed->command,
                                                 kStatusAccessDenied,
                                                 parsed->session_id,
                                                 parsed->tree_id),
                            true};
                }
                const bool created = std::filesystem::create_directory(create_path, create_ec);
                if (create_ec) {
                    if ((create_ec == std::errc::permission_denied) ||
                        (create_ec == std::errc::operation_not_permitted)) {
                        return {build_error_response(parsed->message_id,
                                                     parsed->command,
                                                     kStatusAccessDenied,
                                                     parsed->session_id,
                                                     parsed->tree_id),
                                true};
                    }
                    return {build_error_response(parsed->message_id,
                                                 parsed->command,
                                                 kStatusObjectPathNotFound,
                                                 parsed->session_id,
                                                 parsed->tree_id),
                            true};
                }
                if (!created) {
                    return {build_error_response(parsed->message_id,
                                                 parsed->command,
                                                 kStatusObjectNameCollision,
                                                 parsed->session_id,
                                                 parsed->tree_id),
                            true};
                }
                create_action = kFileActionCreated;
            }

            ConnectionState::OpenFileHandle dir_handle{};
            dir_handle.persistent_id = g_next_file_id.fetch_add(1U, std::memory_order_relaxed);
            dir_handle.volatile_id = g_next_file_id.fetch_add(1U, std::memory_order_relaxed);
            dir_handle.stream = nullptr;
            dir_handle.is_directory = true;
            dir_handle.writable = compute_write_access(req.desired_access);
            dir_handle.delete_allowed = compute_delete_access(req.desired_access);
            dir_handle.full_path = full_path;
            state.open_files.emplace(dir_handle.persistent_id, dir_handle);
            const FileIdPair dir_id{dir_handle.persistent_id, dir_handle.volatile_id};
            return {build_create_response(parsed->message_id,
                                          parsed->session_id,
                                          parsed->tree_id,
                                          dir_id,
                                          create_action,
                                          0U,
                                          true),
                    true};
        }
        if (path_is_dir || wildcard_lookup) {
            ConnectionState::OpenFileHandle dir_handle{};
            dir_handle.persistent_id = g_next_file_id.fetch_add(1U, std::memory_order_relaxed);
            dir_handle.volatile_id = g_next_file_id.fetch_add(1U, std::memory_order_relaxed);
            dir_handle.stream = nullptr;
            dir_handle.is_directory = true;
            dir_handle.writable = compute_write_access(req.desired_access);
            dir_handle.delete_allowed = compute_delete_access(req.desired_access);
            dir_handle.full_path = full_path;
            state.open_files.emplace(dir_handle.persistent_id, dir_handle);
            const FileIdPair dir_id{dir_handle.persistent_id, dir_handle.volatile_id};
            return {build_create_response(parsed->message_id,
                                          parsed->session_id,
                                          parsed->tree_id,
                                          dir_id,
                                          kFileActionOpened,
                                          0U,
                                          true),
                    true};
        }

        ConnectionState::OpenFileHandle open_file{};
        std::uint32_t create_action = kFileActionOpened;
        const std::uint32_t open_status =
            open_or_create_file(full_path, req.desired_access, req.create_disposition, hardening, open_file, create_action);
        if (open_status != kStatusSuccess) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         open_status,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }

        const auto file_size = query_file_size(open_file.stream);
        if (!file_size.has_value()) {
            (void)close_open_file_entry(open_file);
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInternalError,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if (file_size.value() > hardening.max_file_size_bytes) {
            (void)close_open_file_entry(open_file);
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusAccessDenied,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        const FileIdPair file_id{open_file.persistent_id, open_file.volatile_id};
        state.open_files.emplace(open_file.persistent_id, std::move(open_file));
        return {build_create_response(parsed->message_id,
                                      parsed->session_id,
                                      parsed->tree_id,
                                      file_id,
                                      create_action,
                                      file_size.value(),
                                      false),
                true};
    }

    if (parsed->command == static_cast<std::uint16_t>(Smb2Command::Write)) {
        if (!is_authenticated_and_tree_ready(*parsed, state)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusRequestNotAccepted,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        WriteRequestFields req{};
        if (!parse_write_request(payload, req)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if (hardening.read_only) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusAccessDenied,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        const std::uint64_t req_len_u64 = static_cast<std::uint64_t>(req.length);
        if ((req.offset > hardening.max_file_size_bytes) ||
            (req_len_u64 > hardening.max_file_size_bytes) ||
            (req.offset > (hardening.max_file_size_bytes - req_len_u64))) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusAccessDenied,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        ConnectionState::OpenFileHandle* file = find_open_file(state, req.file_id);
        if (file == nullptr) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidHandle,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if (file->is_directory) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusAccessDenied,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if (!file->writable) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusAccessDenied,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if (!seek_file(file->stream, req.offset)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }

        const std::size_t requested = static_cast<std::size_t>(req.length);
        const std::size_t written =
            std::fwrite(payload.data() + req.data_offset, sizeof(std::uint8_t), requested, file->stream);
        if ((written != requested) || (std::fflush(file->stream) != 0)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInternalError,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        return {build_write_response(parsed->message_id, parsed->session_id, parsed->tree_id, req.length), true};
    }

    if (parsed->command == static_cast<std::uint16_t>(Smb2Command::Read)) {
        if (!is_authenticated_and_tree_ready(*parsed, state)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusRequestNotAccepted,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        ReadRequestFields req{};
        if (!parse_read_request(payload, req)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        const std::uint64_t req_len_u64 = static_cast<std::uint64_t>(req.length);
        if ((req.offset > hardening.max_file_size_bytes) ||
            (req_len_u64 > hardening.max_file_size_bytes) ||
            (req.offset > (hardening.max_file_size_bytes - req_len_u64))) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusAccessDenied,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        ConnectionState::OpenFileHandle* file = find_open_file(state, req.file_id);
        if (file == nullptr) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidHandle,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if (file->is_directory) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusAccessDenied,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if (!seek_file(file->stream, req.offset)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }

        std::vector<std::uint8_t> data(static_cast<std::size_t>(req.length), 0U);
        const std::size_t read_count =
            std::fread(data.data(), sizeof(std::uint8_t), static_cast<std::size_t>(req.length), file->stream);
        if (std::ferror(file->stream) != 0) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInternalError,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        data.resize(read_count);
        return {build_read_response(parsed->message_id, parsed->session_id, parsed->tree_id, data), true};
    }

    if (parsed->command == static_cast<std::uint16_t>(Smb2Command::Close)) {
        if (!is_authenticated_and_tree_ready(*parsed, state)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusRequestNotAccepted,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        FileIdPair req{};
        if (!parse_close_request(payload, req)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        ConnectionState::OpenFileHandle* file = find_open_file(state, req);
        if (file == nullptr) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidHandle,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        std::uint64_t size_before_close = 0U;
        if (!file->is_directory) {
            const auto queried = query_file_size(file->stream);
            if (!queried.has_value()) {
                return {build_error_response(parsed->message_id,
                                             parsed->command,
                                             kStatusInternalError,
                                             parsed->session_id,
                                             parsed->tree_id),
                        true};
            }
            size_before_close = queried.value();
        }
        const bool delete_on_close = file->delete_on_close;
        const std::string delete_path = file->full_path;
        const bool close_ok = close_open_file_entry(*file);
        state.open_files.erase(req.persistent_id);
        if (!close_ok) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInternalError,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if (delete_on_close) {
            const std::uint32_t delete_status = remove_path_for_delete_on_close(delete_path);
            if (delete_status != kStatusSuccess) {
                return {build_error_response(parsed->message_id,
                                             parsed->command,
                                             delete_status,
                                             parsed->session_id,
                                             parsed->tree_id),
                        true};
            }
        }
        return {build_close_response(parsed->message_id, parsed->session_id, parsed->tree_id, size_before_close),
                true};
    }

    if (parsed->command == static_cast<std::uint16_t>(Smb2Command::Flush)) {
        if (!is_authenticated_and_tree_ready(*parsed, state)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusRequestNotAccepted,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        FileIdPair req{};
        if (!parse_flush_request(payload, req)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        ConnectionState::OpenFileHandle* file = find_open_file(state, req);
        if (file == nullptr) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidHandle,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if (file->is_directory) {
            return {build_flush_response(parsed->message_id, parsed->session_id, parsed->tree_id), true};
        }
        if (std::fflush(file->stream) != 0) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInternalError,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        return {build_flush_response(parsed->message_id, parsed->session_id, parsed->tree_id), true};
    }

    if (parsed->command == static_cast<std::uint16_t>(Smb2Command::Lock)) {
        if (!is_authenticated_and_tree_ready(*parsed, state)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusRequestNotAccepted,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        LockRequestFields req{};
        if (!parse_lock_request(payload, req)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        ConnectionState::OpenFileHandle* file = find_open_file(state, req.file_id);
        if (file == nullptr) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidHandle,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if (file->is_directory) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusAccessDenied,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        return {build_lock_response(parsed->message_id, parsed->session_id, parsed->tree_id), true};
    }

    if (parsed->command == static_cast<std::uint16_t>(Smb2Command::Ioctl)) {
        if (!state.session_established || (parsed->session_id != state.session_id)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusRequestNotAccepted,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        IoctlRequestFields req{};
        if (!parse_ioctl_request(payload, req)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }

        if (!is_special_ioctl_file_id(req.file_id)) {
            if (!state.tree_connected || (parsed->tree_id != state.tree_id)) {
                return {build_error_response(parsed->message_id,
                                             parsed->command,
                                             kStatusRequestNotAccepted,
                                             parsed->session_id,
                                             parsed->tree_id),
                        true};
            }
            if (find_open_file(state, req.file_id) == nullptr) {
                return {build_error_response(parsed->message_id,
                                             parsed->command,
                                             kStatusInvalidHandle,
                                             parsed->session_id,
                                             parsed->tree_id),
                        true};
            }
        }

        std::vector<std::uint8_t> ioctl_output{};
        switch (req.ctl_code) {
            case kFsctlDfsGetReferrals:
            case kFsctlLmrRequestResiliency:
            case kFsctlQueryNetworkInterfaceInfo:
                break;
            case kFsctlValidateNegotiateInfo:
                ioctl_output = build_validate_negotiate_info_blob(server_guid);
                break;
            default:
                return {build_error_response(parsed->message_id,
                                             parsed->command,
                                             kStatusNotSupported,
                                             parsed->session_id,
                                             parsed->tree_id),
                        true};
        }

        if (static_cast<std::uint64_t>(req.max_output_response) < static_cast<std::uint64_t>(ioctl_output.size())) {
            ioctl_output.resize(static_cast<std::size_t>(req.max_output_response));
        }

        return {build_ioctl_response(parsed->message_id,
                                     parsed->session_id,
                                     parsed->tree_id,
                                     req.ctl_code,
                                     req.file_id,
                                     req.flags,
                                     ioctl_output),
                true};
    }

    if (parsed->command == static_cast<std::uint16_t>(Smb2Command::Cancel)) {
        if (!parse_cancel_request(payload)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        return {build_cancel_response(parsed->message_id, parsed->session_id, parsed->tree_id), true};
    }

    if (parsed->command == static_cast<std::uint16_t>(Smb2Command::Echo)) {
        if (!parse_echo_request(payload)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        return {build_echo_response(parsed->message_id, parsed->session_id, parsed->tree_id), true};
    }

    if (parsed->command == static_cast<std::uint16_t>(Smb2Command::ChangeNotify)) {
        if (!is_authenticated_and_tree_ready(*parsed, state)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusRequestNotAccepted,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        ChangeNotifyRequestFields req{};
        if (!parse_change_notify_request(payload, req)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        ConnectionState::OpenFileHandle* file = find_open_file(state, req.file_id);
        if (file == nullptr) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidHandle,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if (!file->is_directory) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        std::vector<std::uint8_t> notify_data{};
        return {build_change_notify_response(parsed->message_id, parsed->session_id, parsed->tree_id, notify_data), true};
    }

    if (parsed->command == static_cast<std::uint16_t>(Smb2Command::SetInfo)) {
        if (!is_authenticated_and_tree_ready(*parsed, state)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusRequestNotAccepted,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        SetInfoRequestFields req{};
        if (!parse_set_info_request(payload, req)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if (req.info_type != kInfoTypeFile) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusNotSupported,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        ConnectionState::OpenFileHandle* file = find_open_file(state, req.file_id);
        if (file == nullptr) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidHandle,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }

        if (req.file_info_class == kFileRenameInformationClass) {
            bool replace_if_exists = false;
            std::string rename_relative_path{};
            if (!parse_set_info_rename_target(req, replace_if_exists, rename_relative_path)) {
                return {build_error_response(parsed->message_id,
                                             parsed->command,
                                             kStatusInvalidParameter,
                                             parsed->session_id,
                                             parsed->tree_id),
                        true};
            }
            if (hardening.read_only || !(file->delete_allowed || file->writable)) {
                return {build_error_response(parsed->message_id,
                                             parsed->command,
                                             kStatusAccessDenied,
                                             parsed->session_id,
                                             parsed->tree_id),
                        true};
            }

            std::string target_full_path{};
            if (!resolve_share_file_path(
                    share_dir, rename_relative_path, true, hardening.deny_dot_files, target_full_path)) {
                return {build_error_response(parsed->message_id,
                                             parsed->command,
                                             kStatusAccessDenied,
                                             parsed->session_id,
                                             parsed->tree_id),
                        true};
            }
            const std::uint32_t rename_status =
                rename_path_for_set_info(file->full_path, target_full_path, replace_if_exists, file->is_directory);
            if (rename_status != kStatusSuccess) {
                return {build_error_response(parsed->message_id,
                                             parsed->command,
                                             rename_status,
                                             parsed->session_id,
                                             parsed->tree_id),
                        true};
            }
            file->full_path = target_full_path;
            return {build_set_info_response(parsed->message_id, parsed->session_id, parsed->tree_id), true};
        }

        bool delete_pending = false;
        if (req.file_info_class == kFileDispositionInformationClass) {
            if (req.buffer_len < 1U) {
                return {build_error_response(parsed->message_id,
                                             parsed->command,
                                             kStatusInvalidParameter,
                                             parsed->session_id,
                                             parsed->tree_id),
                        true};
            }
            delete_pending = req.buffer_data[0] != 0U;
        } else if (req.file_info_class == kFileDispositionInformationExClass) {
            if (req.buffer_len < 4U) {
                return {build_error_response(parsed->message_id,
                                             parsed->command,
                                             kStatusInvalidParameter,
                                             parsed->session_id,
                                             parsed->tree_id),
                        true};
            }
            const std::uint32_t flags = static_cast<std::uint32_t>(req.buffer_data[0]) |
                                        (static_cast<std::uint32_t>(req.buffer_data[1]) << 8U) |
                                        (static_cast<std::uint32_t>(req.buffer_data[2]) << 16U) |
                                        (static_cast<std::uint32_t>(req.buffer_data[3]) << 24U);
            delete_pending = (flags & kDispositionDeleteFlag) != 0U;
        } else {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusNotSupported,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }

        if (delete_pending) {
            if (hardening.read_only || !(file->delete_allowed || file->writable)) {
                return {build_error_response(parsed->message_id,
                                             parsed->command,
                                             kStatusAccessDenied,
                                             parsed->session_id,
                                             parsed->tree_id),
                        true};
            }
        }

        file->delete_on_close = delete_pending;
        return {build_set_info_response(parsed->message_id, parsed->session_id, parsed->tree_id), true};
    }

    if (parsed->command == static_cast<std::uint16_t>(Smb2Command::QueryInfo)) {
        std::uint8_t info_type = 0U;
        std::uint8_t info_class = 0U;
        FileIdPair file_id{};
        if (!parse_query_info_request(payload, info_type, info_class, file_id)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if (!is_authenticated_and_tree_ready(*parsed, state)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusRequestNotAccepted,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if (info_type == 0x02U) {  // SMB2_0_INFO_FILESYSTEM
            std::error_code space_ec{};
            std::filesystem::space_info sp = std::filesystem::space(std::filesystem::path(share_dir), space_ec);
            if (space_ec) {
                sp = std::filesystem::space_info{};
            }
            if (info_class == 0x03U) {  // FILE_FS_SIZE_INFORMATION
                return {build_query_info_response(parsed->message_id,
                                                  parsed->session_id,
                                                  parsed->tree_id,
                                                  build_file_fs_size_information_blob(sp)),
                        true};
            }
            if (info_class == 0x07U) {  // FILE_FS_FULL_SIZE_INFORMATION
                return {build_query_info_response(parsed->message_id,
                                                  parsed->session_id,
                                                  parsed->tree_id,
                                                  build_file_fs_full_size_information_blob(sp)),
                        true};
            }
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusNotSupported,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }

        ConnectionState::OpenFileHandle* file = find_open_file(state, file_id);
        if (file == nullptr) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidHandle,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if ((info_type == 0x01U) && (info_class == 18U)) {  // FILE_ALL_INFORMATION
            std::uint64_t size = 0U;
            if (!file->is_directory) {
                const auto file_size = query_file_size(file->stream);
                if (!file_size.has_value()) {
                    return {build_error_response(parsed->message_id,
                                                 parsed->command,
                                                 kStatusInternalError,
                                                 parsed->session_id,
                                                 parsed->tree_id),
                            true};
                }
                size = file_size.value();
            }
            return {build_query_info_response(parsed->message_id,
                                              parsed->session_id,
                                              parsed->tree_id,
                                              build_file_all_information_blob(size, file->is_directory)),
                    true};
        }
        return {build_error_response(parsed->message_id,
                                     parsed->command,
                                     kStatusNotSupported,
                                     parsed->session_id,
                                     parsed->tree_id),
                true};
    }

    if (parsed->command == static_cast<std::uint16_t>(Smb2Command::QueryDirectory)) {
        QueryDirectoryRequestFields req{};
        if (!parse_query_directory_request(payload, req)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if (!is_authenticated_and_tree_ready(*parsed, state)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusRequestNotAccepted,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        ConnectionState::OpenFileHandle* file = find_open_file(state, req.file_id);
        if ((file == nullptr) || !file->is_directory) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidHandle,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if ((req.file_info_class != 0x25U) && (req.file_info_class != 0x03U)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusNotSupported,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        const bool restart_scan = (req.flags & 0x01U) != 0U;  // SMB2_RESTART_SCANS
        const bool reopen = (req.flags & 0x10U) != 0U;        // SMB2_REOPEN
        const bool return_single = (req.flags & 0x02U) != 0U; // SMB2_RETURN_SINGLE_ENTRY
        if (restart_scan || reopen) {
            file->directory_listing_sent = false;
        }
        if (file->directory_listing_sent) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusNoMoreFiles,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }

        std::vector<std::uint8_t> listing_blob{};
        bool has_entries = false;
        if (!build_query_directory_id_both_blob(file->full_path,
                                                req.file_name_pattern,
                                                return_single,
                                                hardening.deny_dot_files,
                                                req.output_buffer_length,
                                                listing_blob,
                                                has_entries)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInternalError,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        file->directory_listing_sent = true;
        if (!has_entries) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusNoMoreFiles,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        return {build_query_directory_response(parsed->message_id,
                                               parsed->session_id,
                                               parsed->tree_id,
                                               listing_blob),
                true};
    }

    if (parsed->command == static_cast<std::uint16_t>(Smb2Command::OplockBreak)) {
        if (!state.session_established || (parsed->session_id != state.session_id)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusRequestNotAccepted,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        OplockBreakRequestFields req{};
        if (!parse_oplock_break_request(payload, req)) {
            return {build_error_response(parsed->message_id,
                                         parsed->command,
                                         kStatusInvalidParameter,
                                         parsed->session_id,
                                         parsed->tree_id),
                    true};
        }
        if ((req.file_id.persistent_id != 0U) || (req.file_id.volatile_id != 0U)) {
            if (find_open_file(state, req.file_id) == nullptr) {
                return {build_error_response(parsed->message_id,
                                             parsed->command,
                                             kStatusInvalidHandle,
                                             parsed->session_id,
                                             parsed->tree_id),
                        true};
            }
        }
        return {build_oplock_break_response(parsed->message_id, parsed->session_id, parsed->tree_id, req), true};
    }

    return {build_error_response(parsed->message_id,
                                 parsed->command,
                                 kStatusNotSupported,
                                 parsed->session_id,
                                 parsed->tree_id),
            true};
}

void write_le32_at(std::vector<std::uint8_t>& buf, std::size_t offset, std::uint32_t value) {
    if ((offset + 4U) > buf.size()) {
        return;
    }
    const std::uint32_t le = to_le32(value);
    std::memcpy(buf.data() + offset, &le, sizeof(le));
}

RequestResult process_request(const std::vector<std::uint8_t>& payload,
                              ConnectionState& state,
                              const AuthConfig& auth,
                              const std::string& share_dir,
                              const ShareSecurityConfig& hardening,
                              const std::string& client_ip,
                              const AbuseProtectionConfig& abuse_cfg,
                              const std::array<std::uint8_t, 16>& server_guid,
                              std::uint64_t start_time_filetime) {
    const auto first = parse_request_header(payload);
    if (!first.has_value()) {
        return {std::vector<std::uint8_t>{}, false};
    }
    const auto finalize = [&](std::vector<std::uint8_t> response,
                              bool keep,
                              bool allow_sign = true) -> RequestResult {
        if (allow_sign &&
            auth.signing_enabled &&
            state.session_established &&
            state.signing_key_valid &&
            (response.size() >= sizeof(Smb2Header))) {
            (void)smb2_sign_packet(response, state.signing_key);
        }
        return {std::move(response), keep};
    };

    if (first->next_command != 0U) {
        return finalize(build_error_response(first->message_id,
                                             first->command,
                                             kStatusInvalidParameter,
                                             first->session_id,
                                             first->tree_id),
                        false);
    }

    if (auth.signing_enabled &&
        state.session_established &&
        state.signing_key_valid &&
        (first->command != static_cast<std::uint16_t>(Smb2Command::Negotiate))) {
        const bool request_signed = (first->flags & kSmb2FlagSigned) != 0U;
        if (auth.signing_required && !request_signed) {
            return finalize(build_error_response(first->message_id,
                                                 first->command,
                                                 kStatusAccessDenied,
                                                 first->session_id,
                                                 first->tree_id),
                            false);
        }
        if (request_signed && !smb2_verify_packet_signature(payload, state.signing_key)) {
            return finalize(build_error_response(first->message_id,
                                                 first->command,
                                                 kStatusAccessDenied,
                                                 first->session_id,
                                                 first->tree_id),
                            false);
        }
        if (request_signed) {
            const auto inserted = state.seen_signed_message_ids.insert(first->message_id);
            if (!inserted.second) {
                return finalize(build_error_response(first->message_id,
                                                     first->command,
                                                     kStatusAccessDenied,
                                                     first->session_id,
                                                     first->tree_id),
                                false);
            }
        }
    }

    RequestResult one =
        process_request_single(payload, state, auth, share_dir, hardening, client_ip, abuse_cfg, server_guid, start_time_filetime);
    if (one.payload.empty()) {
        return one;
    }
    return finalize(std::move(one.payload), one.keep_connection);
}

RequestResult process_request(const std::vector<std::uint8_t>& payload,
                              ConnectionState& state,
                              const AuthConfig& auth,
                              const std::string& share_dir,
                              const ShareSecurityConfig& hardening,
                              const std::array<std::uint8_t, 16>& server_guid,
                              std::uint64_t start_time_filetime) {
    static const AbuseProtectionConfig kLocalAbuse{};
    return process_request(payload,
                           state,
                           auth,
                           share_dir,
                           hardening,
                           std::string("127.0.0.1"),
                           kLocalAbuse,
                           server_guid,
                           start_time_filetime);
}

// -------------------------------
// Server runtime
// -------------------------------

struct ServerConfig {
    std::uint16_t port{kDefaultPort};
    bool once{false};
    bool verbose{true};
    bool debug{false};
    bool production_profile{false};
    std::size_t max_clients{kDefaultMaxConcurrentClients};
    int timeout_seconds{kDefaultSocketTimeoutSeconds};
    std::size_t min_password_length{kMinRecommendedPasswordLength};
    std::string share_dir{"."};
    AuthConfig auth{};
    ShareSecurityConfig hardening{};
    AbuseProtectionConfig abuse{};
};

bool resolve_and_validate_share_dir(const std::string& input_dir, std::string& out_dir) {
    if (input_dir.empty()) {
        return false;
    }

    const std::filesystem::path candidate(input_dir);
    std::error_code ec{};
    const std::filesystem::path normalized = std::filesystem::weakly_canonical(candidate, ec);
    if (ec) {
        return false;
    }
    const bool exists = std::filesystem::exists(normalized, ec);
    if (ec || !exists) {
        return false;
    }
    const bool is_dir = std::filesystem::is_directory(normalized, ec);
    if (ec || !is_dir) {
        return false;
    }

    out_dir = normalized.string();
    return !out_dir.empty();
}

void handle_client(socket_t client,
                   const std::string& peer,
                   const std::string& peer_ip,
                   const ServerConfig& cfg,
                   const std::array<std::uint8_t, 16>& server_guid,
                   std::uint64_t start_time_filetime) {
    SMB_EXPECT(client != kInvalidSocket);
    (void)set_socket_timeouts(client, cfg.timeout_seconds);
    (void)set_socket_keepalive(client);

    ConnectionState state{};
    for (std::size_t request_idx = 0U; request_idx < kMaxRequestsPerConnection; ++request_idx) {
        InputFrame frame{};
        if (!recv_smb_frame(client, frame)) {
            if (cfg.verbose && (request_idx == 0U)) {
                log_line("[warn] " + peer + " failed to read SMB frame");
            }
            break;
        }

        const RequestResult result =
            process_request(
                frame.payload,
                state,
                cfg.auth,
                cfg.share_dir,
                cfg.hardening,
                peer_ip,
                cfg.abuse,
                server_guid,
                start_time_filetime);
        if (result.payload.empty()) {
            break;
        }
        if (cfg.debug) {
            log_line("[debug] " + peer + " " + summarize_response_statuses(result.payload));
        }

        const std::vector<std::uint8_t> wire = frame.has_nbss_header ? add_nbss_header(result.payload) : result.payload;
        if (!send_all(client, wire.data(), wire.size())) {
            if (cfg.verbose) {
                log_line("[warn] " + peer + " failed to send SMB response");
            }
            break;
        }
        if (!result.keep_connection) {
            break;
        }
    }
    close_all_open_files(state);
    close_socket(client);
}

int run_server(const ServerConfig& cfg) {
    if (cfg.min_password_length < kMinRecommendedPasswordLength) {
        std::cerr << "[error] --min-password-length must be >= "
                  << static_cast<unsigned int>(kMinRecommendedPasswordLength) << std::endl;
        return static_cast<int>(ExitCode::InvalidArguments);
    }
    if (cfg.production_profile && !cfg.auth.require_auth) {
        std::cerr << "[error] --prod-profile cannot be used with --allow-anonymous" << std::endl;
        return static_cast<int>(ExitCode::InvalidArguments);
    }
    if (cfg.production_profile && (cfg.share_dir == ".")) {
        std::cerr << "[error] --prod-profile requires explicit --share-dir (not current directory)" << std::endl;
        return static_cast<int>(ExitCode::InvalidArguments);
    }
    if (cfg.auth.require_auth && (cfg.auth.username.empty() || cfg.auth.password.empty())) {
        std::cerr << "[error] authentication enabled but --username/--password were not provided" << std::endl;
        return static_cast<int>(ExitCode::InvalidArguments);
    }
    if (cfg.auth.require_auth && (cfg.auth.password.size() < cfg.min_password_length)) {
        std::cerr << "[error] password too short; use at least "
                  << static_cast<unsigned int>(cfg.min_password_length) << " characters" << std::endl;
        return static_cast<int>(ExitCode::InvalidArguments);
    }
    if (cfg.auth.signing_required && !cfg.auth.signing_enabled) {
        std::cerr << "[error] --require-signing requires --enable-signing" << std::endl;
        return static_cast<int>(ExitCode::InvalidArguments);
    }
    if (cfg.auth.signing_required && !cfg.auth.require_auth) {
        std::cerr << "[error] --require-signing cannot be used with --allow-anonymous" << std::endl;
        return static_cast<int>(ExitCode::InvalidArguments);
    }
    if (cfg.auth.signing_enabled && !cfg.auth.require_auth) {
        std::cerr << "[error] --enable-signing requires authentication (remove --allow-anonymous)" << std::endl;
        return static_cast<int>(ExitCode::InvalidArguments);
    }
    if ((cfg.hardening.max_open_files == 0U) || (cfg.hardening.max_file_size_bytes == 0U)) {
        std::cerr << "[error] invalid hardening limits (--max-open-files / --max-file-size)" << std::endl;
        return static_cast<int>(ExitCode::InvalidArguments);
    }
    if ((cfg.abuse.max_clients_per_ip == 0U) || (cfg.abuse.auth_fail_window_sec == 0U) ||
        (cfg.abuse.auth_fail_max == 0U) || (cfg.abuse.auth_block_sec == 0U)) {
        std::cerr << "[error] invalid anti-abuse limits (--max-clients-per-ip / --auth-fail-*)" << std::endl;
        return static_cast<int>(ExitCode::InvalidArguments);
    }
    std::string normalized_share_dir{};
    if (!resolve_and_validate_share_dir(cfg.share_dir, normalized_share_dir)) {
        std::cerr << "[error] invalid --share-dir: '" << cfg.share_dir << "'" << std::endl;
        return static_cast<int>(ExitCode::InvalidArguments);
    }
    ServerConfig runtime_cfg = cfg;
    runtime_cfg.share_dir = normalized_share_dir;
    g_shutdown_requested = 0;
    {
        std::lock_guard<std::mutex> lock(g_ip_security_mutex);
        g_ip_security_states.clear();
    }
    install_shutdown_signal_handlers();

    const socket_t listener = create_listener(runtime_cfg.port);
    if (listener == kInvalidSocket) {
        const int err = socket_last_error();
        std::cerr << "[error] failed to bind/listen on port " << runtime_cfg.port
                  << " (errno=" << err << ")" << std::endl;
        if (socket_permission_error(err)) {
            if (runtime_cfg.port < 1024U) {
                std::cerr << "[hint] privileged port requires extra permission. "
                          << "Run: sudo setcap 'cap_net_bind_service=+ep' ./release/bin/smb_cli" << std::endl;
            }
            return static_cast<int>(ExitCode::EnvironmentRestricted);
        }
        return static_cast<int>(ExitCode::GenericError);
    }

    const auto server_guid_opt = create_server_guid();
    if (!server_guid_opt.has_value()) {
        std::cerr << "[error] failed to initialize secure random source for server GUID" << std::endl;
        close_socket(listener);
        return static_cast<int>(ExitCode::GenericError);
    }
    const std::array<std::uint8_t, 16> server_guid = server_guid_opt.value();
    const std::uint64_t start_time_filetime = now_windows_filetime_utc();
    if (runtime_cfg.verbose) {
        log_line("[info] listening on TCP port " + std::to_string(runtime_cfg.port));
        log_line("[info] share dir: " + normalized_share_dir);
        log_line("[info] hardening: read_only=" + std::string(runtime_cfg.hardening.read_only ? "true" : "false") +
                 ", allow_overwrite=" + std::string(runtime_cfg.hardening.allow_overwrite ? "true" : "false") +
                 ", deny_dot_files=" + std::string(runtime_cfg.hardening.deny_dot_files ? "true" : "false") +
                 ", allow_legacy_ntlm=" + std::string(runtime_cfg.auth.allow_legacy_ntlm ? "true" : "false") +
                 ", signing_enabled=" + std::string(runtime_cfg.auth.signing_enabled ? "true" : "false") +
                 ", signing_required=" + std::string(runtime_cfg.auth.signing_required ? "true" : "false") +
                 ", max_clients_per_ip=" + std::to_string(runtime_cfg.abuse.max_clients_per_ip) +
                 ", auth_fail_window_sec=" + std::to_string(runtime_cfg.abuse.auth_fail_window_sec) +
                 ", auth_fail_max=" + std::to_string(runtime_cfg.abuse.auth_fail_max) +
                 ", auth_block_sec=" + std::to_string(runtime_cfg.abuse.auth_block_sec));
        if (runtime_cfg.production_profile) {
            log_line("[info] production profile enabled");
        }
    }

    while (!shutdown_requested()) {
        if (!wait_for_socket_readable(listener, kServerAcceptPollMillis)) {
            continue;
        }
        sockaddr_in client_addr{};
        socket_len_t len = static_cast<socket_len_t>(sizeof(client_addr));
        const socket_t client = accept(listener, reinterpret_cast<sockaddr*>(&client_addr), &len);
        if (client == kInvalidSocket) {
            if (shutdown_requested()) {
                break;
            }
            continue;
        }

        const std::string peer_ip = client_ip_string(client_addr);
        const std::string peer = client_address_string(client_addr);
        const IpAcceptDecision ip_accept = try_acquire_ip_slot(peer_ip, runtime_cfg.abuse);
        if (ip_accept != IpAcceptDecision::Allow) {
            close_socket(client);
            if (runtime_cfg.verbose) {
                if (ip_accept == IpAcceptDecision::Blocked) {
                    log_line("[warn] connection rejected: IP temporarily blocked (" + peer_ip + ")");
                } else {
                    log_line("[warn] connection rejected: per-IP limit reached (" + peer_ip + ")");
                }
            }
            continue;
        }

        const std::size_t active_now = g_active_clients.fetch_add(1U, std::memory_order_acq_rel) + 1U;
        if (active_now > runtime_cfg.max_clients) {
            (void)g_active_clients.fetch_sub(1U, std::memory_order_acq_rel);
            release_ip_slot(peer_ip);
            close_socket(client);
            if (runtime_cfg.verbose) {
                log_line("[warn] connection rejected: max clients reached");
            }
            continue;
        }

        if (runtime_cfg.once) {
            handle_client(client, peer, peer_ip, runtime_cfg, server_guid, start_time_filetime);
            (void)g_active_clients.fetch_sub(1U, std::memory_order_acq_rel);
            release_ip_slot(peer_ip);
            break;
        }

        std::thread t([client, peer, peer_ip, runtime_cfg, server_guid, start_time_filetime]() {
            struct ActiveGuard {
                std::string ip{};
                explicit ActiveGuard(std::string peer_ip_value) : ip(std::move(peer_ip_value)) {}
                ~ActiveGuard() {
                    (void)g_active_clients.fetch_sub(1U, std::memory_order_acq_rel);
                    release_ip_slot(ip);
                }
            } guard(peer_ip);
            SMB_INVARIANT(g_active_clients.load(std::memory_order_relaxed) <= runtime_cfg.max_clients);
            handle_client(client, peer, peer_ip, runtime_cfg, server_guid, start_time_filetime);
        });
        t.detach();
    }

    if (runtime_cfg.verbose && shutdown_requested()) {
        log_line("[info] shutdown requested, stopping listener");
    }
    close_socket(listener);
    return static_cast<int>(ExitCode::Ok);
}

// -------------------------------
// Self-test + smoke client
// -------------------------------

void push_le16(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
}

void push_le32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xFFU));
}

void push_le64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    push_le32(out, static_cast<std::uint32_t>(value & 0xFFFFFFFFULL));
    push_le32(out, static_cast<std::uint32_t>((value >> 32U) & 0xFFFFFFFFULL));
}

std::uint16_t read_le16(const std::uint8_t* data) {
    return static_cast<std::uint16_t>(data[0]) | static_cast<std::uint16_t>(data[1] << 8U);
}

std::uint32_t read_le32(const std::uint8_t* data) {
    return static_cast<std::uint32_t>(data[0]) |
           (static_cast<std::uint32_t>(data[1]) << 8U) |
           (static_cast<std::uint32_t>(data[2]) << 16U) |
           (static_cast<std::uint32_t>(data[3]) << 24U);
}

std::uint64_t read_le64(const std::uint8_t* data) {
    return static_cast<std::uint64_t>(read_le32(data)) |
           (static_cast<std::uint64_t>(read_le32(data + 4U)) << 32U);
}

std::vector<std::uint8_t> make_smb2_request_header(std::uint16_t command,
                                                   std::uint64_t message_id,
                                                   std::uint64_t session_id,
                                                   std::uint32_t tree_id) {
    std::vector<std::uint8_t> out;
    out.reserve(sizeof(Smb2Header));
    push_le32(out, kProtocolSmb2);
    push_le16(out, 64U);
    push_le16(out, 0U);
    push_le32(out, 0U);
    push_le16(out, command);
    push_le16(out, 1U);
    push_le32(out, 0U);
    push_le32(out, 0U);
    push_le64(out, message_id);
    push_le32(out, 0U);
    push_le32(out, tree_id);
    push_le64(out, session_id);
    for (std::size_t i = 0U; i < 16U; ++i) {
        out.push_back(0U);
    }
    return out;
}

std::vector<std::uint8_t> make_negotiate_request_payload(std::uint64_t message_id) {
    std::vector<std::uint8_t> payload = make_smb2_request_header(static_cast<std::uint16_t>(Smb2Command::Negotiate),
                                                                 message_id,
                                                                 0U,
                                                                 0U);
    push_le16(payload, 36U);
    push_le16(payload, 1U);       // dialect_count
    push_le16(payload, 0x0001U);  // signing enabled
    push_le16(payload, 0U);
    push_le32(payload, 0U);
    for (std::size_t i = 0U; i < 16U; ++i) {
        payload.push_back(static_cast<std::uint8_t>(i + 1U));
    }
    push_le32(payload, 0U);
    push_le16(payload, 0U);
    push_le16(payload, 0U);
    push_le16(payload, 0x0311U);
    return payload;
}

std::vector<std::uint8_t> make_session_setup_request_payload_with_blob(std::uint64_t message_id,
                                                                       std::uint64_t session_id,
                                                                       const std::vector<std::uint8_t>& security_blob);

std::vector<std::uint8_t> make_session_setup_request_payload(std::uint64_t message_id,
                                                             const std::string& username,
                                                             const std::string& password,
                                                             bool include_auth_blob) {
    std::string auth_blob{};
    if (include_auth_blob) {
        auth_blob = "USER=" + username + ";PASS=" + password;
    }
    std::vector<std::uint8_t> security_blob(auth_blob.begin(), auth_blob.end());
    return make_session_setup_request_payload_with_blob(message_id, 0U, security_blob);
}

std::vector<std::uint8_t> make_session_setup_request_payload_with_blob(std::uint64_t message_id,
                                                                       std::uint64_t session_id,
                                                                       const std::vector<std::uint8_t>& security_blob) {
    std::vector<std::uint8_t> payload = make_smb2_request_header(
        static_cast<std::uint16_t>(Smb2Command::SessionSetup), message_id, session_id, 0U);
    SMB_EXPECT(security_blob.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()));
    const std::uint16_t sec_offset =
        static_cast<std::uint16_t>(sizeof(Smb2Header) + sizeof(SessionSetupRequestBody));
    const std::uint16_t sec_length = static_cast<std::uint16_t>(security_blob.size());

    push_le16(payload, 25U);
    payload.push_back(0U);
    payload.push_back(0x01U);
    push_le32(payload, 0U);
    push_le32(payload, 0U);
    push_le16(payload, sec_offset);
    push_le16(payload, sec_length);
    push_le64(payload, 0U);
    payload.insert(payload.end(), security_blob.begin(), security_blob.end());
    return payload;
}

std::vector<std::uint8_t> make_ntlm_type1_security_blob() {
    std::vector<std::uint8_t> out(40U, 0U);
    std::memcpy(out.data(), "NTLMSSP\0", 8U);
    const std::uint32_t type_le = to_le32(1U);
    const std::uint32_t flags_le = to_le32(0x00088201U);
    std::memcpy(out.data() + 8U, &type_le, sizeof(type_le));
    std::memcpy(out.data() + 12U, &flags_le, sizeof(flags_le));
    return out;
}

bool extract_session_setup_response_security_blob(const std::vector<std::uint8_t>& response,
                                                  const std::uint8_t*& blob_data,
                                                  std::size_t& blob_size) {
    blob_data = nullptr;
    blob_size = 0U;
    if (response.size() < (sizeof(Smb2Header) + sizeof(SessionSetupResponseBody))) {
        return false;
    }
    const std::uint16_t offset = read_le16(response.data() + sizeof(Smb2Header) + 4U);
    const std::uint16_t length = read_le16(response.data() + sizeof(Smb2Header) + 6U);
    if (length == 0U) {
        return true;
    }
    const std::size_t begin = static_cast<std::size_t>(offset);
    const std::size_t end = begin + static_cast<std::size_t>(length);
    if ((begin < (sizeof(Smb2Header) + sizeof(SessionSetupResponseBody))) || (end > response.size())) {
        return false;
    }
    blob_data = response.data() + begin;
    blob_size = static_cast<std::size_t>(length);
    return true;
}

bool extract_ntlm_type2_challenge(const std::uint8_t* blob_data,
                                  std::size_t blob_size,
                                  std::array<std::uint8_t, 8>& out_challenge) {
    SMB_EXPECT(blob_data != nullptr);
    const auto sig_offset = find_ntlmssp_signature(blob_data, blob_size);
    if (!sig_offset.has_value()) {
        return false;
    }
    const std::size_t base = sig_offset.value();
    const auto msg_type = extract_ntlm_message_type(blob_data, blob_size);
    if (!msg_type.has_value() || (msg_type.value() != 2U)) {
        return false;
    }
    if ((base + 32U) > blob_size) {
        return false;
    }
    std::memcpy(out_challenge.data(), blob_data + base + 24U, out_challenge.size());
    return true;
}

bool build_ntlmv2_type3_security_blob(const std::string& username,
                                      const std::string& password,
                                      const std::array<std::uint8_t, 8>& server_challenge,
                                      std::vector<std::uint8_t>& out_blob,
                                      std::array<std::uint8_t, 16>& out_session_key) {
    out_blob.clear();
    out_session_key.fill(0U);
    if (username.empty() || password.empty()) {
        return false;
    }

    std::array<std::uint8_t, 8> client_challenge{};
    if (!fill_secure_random_bytes(client_challenge.data(), client_challenge.size())) {
        return false;
    }

    const std::vector<std::uint8_t> pass_utf16 = to_utf16le_ascii(password, false);
    const std::array<std::uint8_t, 16> nt_hash = md4_hash(pass_utf16);
    std::vector<std::uint8_t> nt_hash_key(nt_hash.begin(), nt_hash.end());

    const std::string canonical_user = strip_qualified_username(username);
    const std::vector<std::uint8_t> user_utf16_upper = to_utf16le_ascii(ascii_upper_copy(canonical_user), false);
    std::vector<std::uint8_t> identity = user_utf16_upper;
    const std::array<std::uint8_t, 16> ntlm_v2_hash = hmac_md5(nt_hash_key, identity);
    std::vector<std::uint8_t> ntlm_v2_key(ntlm_v2_hash.begin(), ntlm_v2_hash.end());

    std::vector<std::uint8_t> blob_part(32U, 0U);
    blob_part[0U] = 0x01U;
    blob_part[1U] = 0x01U;
    const std::uint64_t ts_le = to_le64(now_windows_filetime_utc());
    std::memcpy(blob_part.data() + 8U, &ts_le, sizeof(ts_le));
    std::memcpy(blob_part.data() + 16U, client_challenge.data(), client_challenge.size());

    std::vector<std::uint8_t> proof_input{};
    proof_input.reserve(server_challenge.size() + blob_part.size());
    proof_input.insert(proof_input.end(), server_challenge.begin(), server_challenge.end());
    proof_input.insert(proof_input.end(), blob_part.begin(), blob_part.end());
    const std::array<std::uint8_t, 16> nt_proof = hmac_md5(ntlm_v2_key, proof_input);

    std::vector<std::uint8_t> nt_response{};
    nt_response.reserve(nt_proof.size() + blob_part.size());
    nt_response.insert(nt_response.end(), nt_proof.begin(), nt_proof.end());
    nt_response.insert(nt_response.end(), blob_part.begin(), blob_part.end());

    std::vector<std::uint8_t> nt_proof_vec(nt_proof.begin(), nt_proof.end());
    out_session_key = hmac_md5(ntlm_v2_key, nt_proof_vec);

    const std::vector<std::uint8_t> domain_utf16{};
    const std::vector<std::uint8_t> user_utf16 = to_utf16le_ascii(canonical_user, false);
    const std::vector<std::uint8_t> workstation_utf16{};
    const std::vector<std::uint8_t> lm_response{};
    const std::vector<std::uint8_t> encrypted_session_key{};

    const std::size_t base = 64U;
    const std::size_t lm_off = base;
    const std::size_t nt_off = lm_off + lm_response.size();
    const std::size_t domain_off = nt_off + nt_response.size();
    const std::size_t user_off = domain_off + domain_utf16.size();
    const std::size_t workstation_off = user_off + user_utf16.size();
    const std::size_t key_off = workstation_off + workstation_utf16.size();
    const std::size_t total = key_off + encrypted_session_key.size();
    if (total > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        return false;
    }
    out_blob.assign(total, 0U);
    std::memcpy(out_blob.data(), "NTLMSSP\0", 8U);
    const std::uint32_t type_le = to_le32(3U);
    std::memcpy(out_blob.data() + 8U, &type_le, sizeof(type_le));
    const auto write_secbuf = [&](std::size_t off, std::size_t len, std::size_t ptr_off) {
        SMB_EXPECT(len <= static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()));
        SMB_EXPECT(ptr_off <= static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()));
        const std::uint16_t len16 = to_le16(static_cast<std::uint16_t>(len));
        const std::uint32_t off32 = to_le32(static_cast<std::uint32_t>(ptr_off));
        std::memcpy(out_blob.data() + off + 0U, &len16, sizeof(len16));
        std::memcpy(out_blob.data() + off + 2U, &len16, sizeof(len16));
        std::memcpy(out_blob.data() + off + 4U, &off32, sizeof(off32));
    };
    write_secbuf(12U, lm_response.size(), lm_off);
    write_secbuf(20U, nt_response.size(), nt_off);
    write_secbuf(28U, domain_utf16.size(), domain_off);
    write_secbuf(36U, user_utf16.size(), user_off);
    write_secbuf(44U, workstation_utf16.size(), workstation_off);
    write_secbuf(52U, encrypted_session_key.size(), key_off);
    const std::uint32_t flags_le = to_le32(0x00088201U);
    std::memcpy(out_blob.data() + 60U, &flags_le, sizeof(flags_le));
    std::memcpy(out_blob.data() + nt_off, nt_response.data(), nt_response.size());
    std::memcpy(out_blob.data() + user_off, user_utf16.data(), user_utf16.size());
    return true;
}

void push_utf16le_ascii(std::vector<std::uint8_t>& out, const std::string& text) {
    for (char c : text) {
        out.push_back(static_cast<std::uint8_t>(c));
        out.push_back(0U);
    }
}

std::vector<std::uint8_t> make_tree_connect_request_payload(std::uint64_t message_id,
                                                            std::uint64_t session_id,
                                                            const std::string& path_ascii) {
    std::vector<std::uint8_t> payload =
        make_smb2_request_header(static_cast<std::uint16_t>(Smb2Command::TreeConnect), message_id, session_id, 0U);
    std::vector<std::uint8_t> path{};
    push_utf16le_ascii(path, path_ascii);
    SMB_EXPECT(path.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()));
    const std::uint16_t path_offset = static_cast<std::uint16_t>(sizeof(Smb2Header) + 8U);
    const std::uint16_t path_length = static_cast<std::uint16_t>(path.size());
    push_le16(payload, 9U);
    push_le16(payload, 0U);
    push_le16(payload, path_offset);
    push_le16(payload, path_length);
    payload.insert(payload.end(), path.begin(), path.end());
    return payload;
}

std::vector<std::uint8_t> make_create_request_payload(std::uint64_t message_id,
                                                      std::uint64_t session_id,
                                                      std::uint32_t tree_id,
                                                      const std::string& relative_path_ascii,
                                                      std::uint32_t desired_access,
                                                      std::uint32_t create_disposition,
                                                      std::uint32_t create_options = 0U) {
    std::vector<std::uint8_t> payload =
        make_smb2_request_header(static_cast<std::uint16_t>(Smb2Command::Create), message_id, session_id, tree_id);
    std::vector<std::uint8_t> name{};
    push_utf16le_ascii(name, relative_path_ascii);
    SMB_EXPECT(name.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()));
    const std::uint16_t name_offset = static_cast<std::uint16_t>(sizeof(Smb2Header) + 56U);
    const std::uint16_t name_length = static_cast<std::uint16_t>(name.size());

    push_le16(payload, 57U);
    payload.push_back(0U);
    payload.push_back(0U);
    push_le32(payload, 2U);
    push_le64(payload, 0U);
    push_le64(payload, 0U);
    push_le32(payload, desired_access);
    push_le32(payload, 0x00000080U);
    push_le32(payload, 0x00000007U);
    push_le32(payload, create_disposition);
    push_le32(payload, create_options);
    push_le16(payload, name_offset);
    push_le16(payload, name_length);
    push_le32(payload, 0U);
    push_le32(payload, 0U);
    payload.insert(payload.end(), name.begin(), name.end());
    return payload;
}

std::vector<std::uint8_t> make_write_request_payload(std::uint64_t message_id,
                                                     std::uint64_t session_id,
                                                     std::uint32_t tree_id,
                                                     const FileIdPair& file_id,
                                                     std::uint64_t offset,
                                                     const std::vector<std::uint8_t>& data) {
    std::vector<std::uint8_t> payload =
        make_smb2_request_header(static_cast<std::uint16_t>(Smb2Command::Write), message_id, session_id, tree_id);
    SMB_EXPECT(data.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()));
    const std::uint16_t data_offset = static_cast<std::uint16_t>(sizeof(Smb2Header) + 48U);
    push_le16(payload, 49U);
    push_le16(payload, data_offset);
    push_le32(payload, static_cast<std::uint32_t>(data.size()));
    push_le64(payload, offset);
    push_le64(payload, file_id.persistent_id);
    push_le64(payload, file_id.volatile_id);
    push_le32(payload, 0U);
    push_le32(payload, 0U);
    push_le16(payload, 0U);
    push_le16(payload, 0U);
    push_le32(payload, 0U);
    payload.insert(payload.end(), data.begin(), data.end());
    return payload;
}

std::vector<std::uint8_t> make_read_request_payload(std::uint64_t message_id,
                                                    std::uint64_t session_id,
                                                    std::uint32_t tree_id,
                                                    const FileIdPair& file_id,
                                                    std::uint64_t offset,
                                                    std::uint32_t length) {
    std::vector<std::uint8_t> payload =
        make_smb2_request_header(static_cast<std::uint16_t>(Smb2Command::Read), message_id, session_id, tree_id);
    push_le16(payload, 49U);
    payload.push_back(0U);
    payload.push_back(0U);
    push_le32(payload, length);
    push_le64(payload, offset);
    push_le64(payload, file_id.persistent_id);
    push_le64(payload, file_id.volatile_id);
    push_le32(payload, 0U);
    push_le32(payload, 0U);
    push_le32(payload, 0U);
    push_le16(payload, 0U);
    push_le16(payload, 0U);
    return payload;
}

std::vector<std::uint8_t> make_close_request_payload(std::uint64_t message_id,
                                                     std::uint64_t session_id,
                                                     std::uint32_t tree_id,
                                                     const FileIdPair& file_id) {
    std::vector<std::uint8_t> payload =
        make_smb2_request_header(static_cast<std::uint16_t>(Smb2Command::Close), message_id, session_id, tree_id);
    push_le16(payload, 24U);
    push_le16(payload, 0U);
    push_le32(payload, 0U);
    push_le64(payload, file_id.persistent_id);
    push_le64(payload, file_id.volatile_id);
    return payload;
}

std::vector<std::uint8_t> make_echo_request_payload(std::uint64_t message_id,
                                                    std::uint64_t session_id,
                                                    std::uint32_t tree_id) {
    std::vector<std::uint8_t> payload =
        make_smb2_request_header(static_cast<std::uint16_t>(Smb2Command::Echo), message_id, session_id, tree_id);
    push_le16(payload, 4U);
    push_le16(payload, 0U);
    return payload;
}

std::vector<std::uint8_t> make_lock_request_payload(std::uint64_t message_id,
                                                    std::uint64_t session_id,
                                                    std::uint32_t tree_id,
                                                    const FileIdPair& file_id) {
    std::vector<std::uint8_t> payload =
        make_smb2_request_header(static_cast<std::uint16_t>(Smb2Command::Lock), message_id, session_id, tree_id);
    push_le16(payload, 48U);
    push_le16(payload, 1U);
    push_le32(payload, 0U);
    push_le64(payload, file_id.persistent_id);
    push_le64(payload, file_id.volatile_id);
    push_le64(payload, 0U);
    push_le64(payload, 1U);
    push_le32(payload, 0x00000001U);  // shared lock
    push_le32(payload, 0U);
    return payload;
}

std::vector<std::uint8_t> make_ioctl_request_payload(std::uint64_t message_id,
                                                     std::uint64_t session_id,
                                                     std::uint32_t tree_id,
                                                     std::uint32_t ctl_code,
                                                     const FileIdPair& file_id,
                                                     std::uint32_t max_output_response,
                                                     std::uint32_t flags,
                                                     const std::vector<std::uint8_t>& input_data) {
    std::vector<std::uint8_t> payload =
        make_smb2_request_header(static_cast<std::uint16_t>(Smb2Command::Ioctl), message_id, session_id, tree_id);
    SMB_EXPECT(input_data.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()));
    const std::uint32_t input_count = static_cast<std::uint32_t>(input_data.size());
    const std::uint32_t input_offset = input_count == 0U ? 0U : static_cast<std::uint32_t>(sizeof(Smb2Header) + 56U);
    push_le16(payload, 57U);
    push_le16(payload, 0U);
    push_le32(payload, ctl_code);
    push_le64(payload, file_id.persistent_id);
    push_le64(payload, file_id.volatile_id);
    push_le32(payload, input_offset);
    push_le32(payload, input_count);
    push_le32(payload, 0U);
    push_le32(payload, 0U);
    push_le32(payload, 0U);
    push_le32(payload, max_output_response);
    push_le32(payload, flags);
    push_le32(payload, 0U);
    payload.insert(payload.end(), input_data.begin(), input_data.end());
    return payload;
}

std::vector<std::uint8_t> make_cancel_request_payload(std::uint64_t message_id,
                                                      std::uint64_t session_id,
                                                      std::uint32_t tree_id) {
    std::vector<std::uint8_t> payload =
        make_smb2_request_header(static_cast<std::uint16_t>(Smb2Command::Cancel), message_id, session_id, tree_id);
    push_le16(payload, 4U);
    push_le16(payload, 0U);
    return payload;
}

std::vector<std::uint8_t> make_change_notify_request_payload(std::uint64_t message_id,
                                                             std::uint64_t session_id,
                                                             std::uint32_t tree_id,
                                                             const FileIdPair& file_id,
                                                             std::uint32_t output_buffer_length,
                                                             std::uint16_t flags,
                                                             std::uint32_t completion_filter) {
    std::vector<std::uint8_t> payload = make_smb2_request_header(
        static_cast<std::uint16_t>(Smb2Command::ChangeNotify), message_id, session_id, tree_id);
    push_le16(payload, 32U);
    push_le16(payload, flags);
    push_le32(payload, output_buffer_length);
    push_le64(payload, file_id.persistent_id);
    push_le64(payload, file_id.volatile_id);
    push_le32(payload, completion_filter);
    push_le32(payload, 0U);
    return payload;
}

std::vector<std::uint8_t> make_oplock_break_request_payload(std::uint64_t message_id,
                                                            std::uint64_t session_id,
                                                            std::uint32_t tree_id,
                                                            const FileIdPair& file_id,
                                                            std::uint8_t oplock_level) {
    std::vector<std::uint8_t> payload =
        make_smb2_request_header(static_cast<std::uint16_t>(Smb2Command::OplockBreak), message_id, session_id, tree_id);
    push_le16(payload, 24U);
    payload.push_back(oplock_level);
    payload.push_back(0U);
    push_le32(payload, 0U);
    push_le64(payload, file_id.persistent_id);
    push_le64(payload, file_id.volatile_id);
    return payload;
}

std::vector<std::uint8_t> make_tree_disconnect_request_payload(std::uint64_t message_id,
                                                               std::uint64_t session_id,
                                                               std::uint32_t tree_id) {
    std::vector<std::uint8_t> payload = make_smb2_request_header(
        static_cast<std::uint16_t>(Smb2Command::TreeDisconnect), message_id, session_id, tree_id);
    push_le16(payload, 4U);
    push_le16(payload, 0U);
    return payload;
}

std::vector<std::uint8_t> make_logoff_request_payload(std::uint64_t message_id, std::uint64_t session_id) {
    std::vector<std::uint8_t> payload =
        make_smb2_request_header(static_cast<std::uint16_t>(Smb2Command::Logoff), message_id, session_id, 0U);
    push_le16(payload, 4U);
    push_le16(payload, 0U);
    return payload;
}

std::vector<std::uint8_t> make_set_info_disposition_request_payload(std::uint64_t message_id,
                                                                    std::uint64_t session_id,
                                                                    std::uint32_t tree_id,
                                                                    const FileIdPair& file_id,
                                                                    bool delete_pending,
                                                                    bool use_ex_class) {
    std::vector<std::uint8_t> payload =
        make_smb2_request_header(static_cast<std::uint16_t>(Smb2Command::SetInfo), message_id, session_id, tree_id);
    std::vector<std::uint8_t> info_data{};
    if (use_ex_class) {
        push_le32(info_data, delete_pending ? kDispositionDeleteFlag : 0U);
    } else {
        info_data.push_back(delete_pending ? 1U : 0U);
    }
    SMB_EXPECT(info_data.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()));
    const std::uint16_t buffer_offset = static_cast<std::uint16_t>(sizeof(Smb2Header) + 32U);
    push_le16(payload, 33U);
    payload.push_back(kInfoTypeFile);
    payload.push_back(use_ex_class ? kFileDispositionInformationExClass : kFileDispositionInformationClass);
    push_le32(payload, static_cast<std::uint32_t>(info_data.size()));
    push_le16(payload, buffer_offset);
    push_le16(payload, 0U);
    push_le32(payload, 0U);
    push_le64(payload, file_id.persistent_id);
    push_le64(payload, file_id.volatile_id);
    payload.insert(payload.end(), info_data.begin(), info_data.end());
    return payload;
}

bool validate_response_header(const std::vector<std::uint8_t>& payload,
                              std::uint16_t expected_command,
                              std::uint64_t expected_message_id,
                              std::uint32_t expected_status) {
    if (payload.size() < sizeof(Smb2Header)) {
        return false;
    }
    if (read_le32(payload.data()) != kProtocolSmb2) {
        return false;
    }
    if (read_le16(payload.data() + 4U) != 64U) {
        return false;
    }
    if (read_le16(payload.data() + 12U) != expected_command) {
        return false;
    }
    if (read_le32(payload.data() + 8U) != expected_status) {
        return false;
    }
    if ((read_le32(payload.data() + 16U) & kSmb2FlagResponse) == 0U) {
        return false;
    }
    if (read_le64(payload.data() + 24U) != expected_message_id) {
        return false;
    }
    return true;
}

void print_response_header_debug(const std::vector<std::uint8_t>& payload, const char* tag) {
    if (payload.size() < sizeof(Smb2Header)) {
        std::cerr << "[debug] " << tag << " short payload: " << payload.size() << std::endl;
        return;
    }
    std::cerr << "[debug] " << tag
              << " cmd=" << read_le16(payload.data() + 12U)
              << " status=0x" << std::hex << read_le32(payload.data() + 8U) << std::dec
              << " msg=" << read_le64(payload.data() + 24U)
              << " tree=" << read_le32(payload.data() + 36U)
              << " session=" << read_le64(payload.data() + 40U)
              << std::endl;
}

bool extract_tree_id_from_response(const std::vector<std::uint8_t>& payload, std::uint32_t& tree_id) {
    if (payload.size() < sizeof(Smb2Header)) {
        return false;
    }
    tree_id = read_le32(payload.data() + 36U);
    return true;
}

bool extract_create_file_id(const std::vector<std::uint8_t>& payload, FileIdPair& file_id) {
    if (payload.size() < (sizeof(Smb2Header) + 88U)) {
        return false;
    }
    file_id.persistent_id = read_le64(payload.data() + sizeof(Smb2Header) + 64U);
    file_id.volatile_id = read_le64(payload.data() + sizeof(Smb2Header) + 72U);
    return (file_id.persistent_id != 0U) || (file_id.volatile_id != 0U);
}

bool extract_write_count(const std::vector<std::uint8_t>& payload, std::uint32_t& count) {
    if (payload.size() < (sizeof(Smb2Header) + 16U)) {
        return false;
    }
    count = read_le32(payload.data() + sizeof(Smb2Header) + 4U);
    return true;
}

bool extract_read_data(const std::vector<std::uint8_t>& payload, std::vector<std::uint8_t>& out_data) {
    if (payload.size() < (sizeof(Smb2Header) + 16U)) {
        return false;
    }
    const std::uint8_t data_offset = payload[sizeof(Smb2Header) + 2U];
    const std::uint32_t data_length = read_le32(payload.data() + sizeof(Smb2Header) + 4U);
    const std::size_t offset = static_cast<std::size_t>(data_offset);
    const std::size_t end = offset + static_cast<std::size_t>(data_length);
    if ((offset < sizeof(Smb2Header)) || (end > payload.size())) {
        return false;
    }
    out_data.assign(payload.begin() + static_cast<std::ptrdiff_t>(offset),
                    payload.begin() + static_cast<std::ptrdiff_t>(end));
    return true;
}

bool build_ntlm_type3_blob_with_nt_response(const std::string& username,
                                            const std::vector<std::uint8_t>& nt_response,
                                            std::vector<std::uint8_t>& out_blob) {
    out_blob.clear();
    if (username.empty() || nt_response.empty()) {
        return false;
    }
    const std::vector<std::uint8_t> domain_utf16{};
    const std::vector<std::uint8_t> user_utf16 = to_utf16le_ascii(strip_qualified_username(username), false);
    const std::vector<std::uint8_t> workstation_utf16{};
    const std::vector<std::uint8_t> lm_response{};
    const std::vector<std::uint8_t> encrypted_session_key{};

    const std::size_t base = 64U;
    const std::size_t lm_off = base;
    const std::size_t nt_off = lm_off + lm_response.size();
    const std::size_t domain_off = nt_off + nt_response.size();
    const std::size_t user_off = domain_off + domain_utf16.size();
    const std::size_t workstation_off = user_off + user_utf16.size();
    const std::size_t key_off = workstation_off + workstation_utf16.size();
    const std::size_t total = key_off + encrypted_session_key.size();
    if (total > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        return false;
    }
    out_blob.assign(total, 0U);
    std::memcpy(out_blob.data(), "NTLMSSP\0", 8U);
    const std::uint32_t type_le = to_le32(3U);
    std::memcpy(out_blob.data() + 8U, &type_le, sizeof(type_le));
    const auto write_secbuf = [&](std::size_t off, std::size_t len, std::size_t ptr_off) {
        SMB_EXPECT(len <= static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()));
        SMB_EXPECT(ptr_off <= static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()));
        const std::uint16_t len16 = to_le16(static_cast<std::uint16_t>(len));
        const std::uint32_t off32 = to_le32(static_cast<std::uint32_t>(ptr_off));
        std::memcpy(out_blob.data() + off + 0U, &len16, sizeof(len16));
        std::memcpy(out_blob.data() + off + 2U, &len16, sizeof(len16));
        std::memcpy(out_blob.data() + off + 4U, &off32, sizeof(off32));
    };
    write_secbuf(12U, lm_response.size(), lm_off);
    write_secbuf(20U, nt_response.size(), nt_off);
    write_secbuf(28U, domain_utf16.size(), domain_off);
    write_secbuf(36U, user_utf16.size(), user_off);
    write_secbuf(44U, workstation_utf16.size(), workstation_off);
    write_secbuf(52U, encrypted_session_key.size(), key_off);
    const std::uint32_t flags_le = to_le32(0x00088201U);
    std::memcpy(out_blob.data() + 60U, &flags_le, sizeof(flags_le));
    std::memcpy(out_blob.data() + nt_off, nt_response.data(), nt_response.size());
    std::memcpy(out_blob.data() + user_off, user_utf16.data(), user_utf16.size());
    return true;
}

bool build_ntlmv1_type3_security_blob_for_test(const std::string& username,
                                                const std::string& password,
                                                const std::array<std::uint8_t, 8>& challenge,
                                                std::vector<std::uint8_t>& out_blob) {
    const std::vector<std::uint8_t> pass_utf16 = to_utf16le_ascii(password, false);
    const std::array<std::uint8_t, 16> nt_hash = md4_hash(pass_utf16);
    const std::array<std::uint8_t, 24> nt_resp = ntlm_desl_encrypt(nt_hash, challenge);
    const std::vector<std::uint8_t> nt_response(nt_resp.begin(), nt_resp.end());
    return build_ntlm_type3_blob_with_nt_response(username, nt_response, out_blob);
}

bool run_ntlmv2_session_setup_for_test(ConnectionState& state,
                                       const AuthConfig& auth,
                                       const std::string& share_dir_text,
                                       const ShareSecurityConfig& hardening,
                                       const std::array<std::uint8_t, 16>& guid,
                                       std::uint64_t start_time,
                                       std::uint64_t type1_message_id,
                                       std::uint64_t type3_message_id,
                                       const std::string& username,
                                       const std::string& password,
                                       std::uint64_t& out_session_id,
                                       std::array<std::uint8_t, 16>& out_signing_key) {
    out_session_id = 0U;
    out_signing_key.fill(0U);
    const std::vector<std::uint8_t> type1_blob = make_ntlm_type1_security_blob();
    const std::vector<std::uint8_t> type1_req =
        make_session_setup_request_payload_with_blob(type1_message_id, 0U, type1_blob);
    RequestResult type1_rsp = process_request(type1_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (type1_rsp.payload.empty() ||
        !validate_response_header(type1_rsp.payload,
                                  static_cast<std::uint16_t>(Smb2Command::SessionSetup),
                                  type1_message_id,
                                  kStatusMoreProcessingRequired)) {
        return false;
    }
    const std::uint64_t intermediate_session_id = read_le64(type1_rsp.payload.data() + 40U);
    if (intermediate_session_id == 0U) {
        return false;
    }

    const std::uint8_t* challenge_blob = nullptr;
    std::size_t challenge_blob_size = 0U;
    if (!extract_session_setup_response_security_blob(type1_rsp.payload, challenge_blob, challenge_blob_size) ||
        (challenge_blob == nullptr) || (challenge_blob_size == 0U)) {
        return false;
    }
    std::array<std::uint8_t, 8> server_challenge{};
    if (!extract_ntlm_type2_challenge(challenge_blob, challenge_blob_size, server_challenge)) {
        return false;
    }

    std::vector<std::uint8_t> type3_blob{};
    if (!build_ntlmv2_type3_security_blob(username, password, server_challenge, type3_blob, out_signing_key)) {
        return false;
    }
    const std::vector<std::uint8_t> type3_req =
        make_session_setup_request_payload_with_blob(type3_message_id, intermediate_session_id, type3_blob);
    RequestResult type3_rsp = process_request(type3_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (type3_rsp.payload.empty() ||
        !validate_response_header(type3_rsp.payload,
                                  static_cast<std::uint16_t>(Smb2Command::SessionSetup),
                                  type3_message_id,
                                  kStatusSuccess)) {
        return false;
    }
    out_session_id = read_le64(type3_rsp.payload.data() + 40U);
    return out_session_id != 0U;
}

int run_packet_self_test(bool verbose) {
    if (!des_known_vector_ok()) {
        std::cerr << "[self-test] DES primitive failed known test vector" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    {
        std::array<std::uint8_t, 16> test_sign_key{};
        for (std::size_t i = 0U; i < test_sign_key.size(); ++i) {
            test_sign_key[i] = static_cast<std::uint8_t>(i + 1U);
        }
        std::vector<std::uint8_t> signed_probe = make_negotiate_request_payload(999U);
        if (!smb2_sign_packet(signed_probe, test_sign_key) ||
            !smb2_verify_packet_signature(signed_probe, test_sign_key)) {
            std::cerr << "[self-test] SMB2 signing primitive failed" << std::endl;
            return static_cast<int>(ExitCode::GenericError);
        }
        signed_probe[kSmb2HeaderSignatureOffset] ^= 0x01U;
        if (smb2_verify_packet_signature(signed_probe, test_sign_key)) {
            std::cerr << "[self-test] SMB2 signature tamper detection failed" << std::endl;
            return static_cast<int>(ExitCode::GenericError);
        }
    }

    ConnectionState state{};
    const auto guid_opt = create_server_guid();
    if (!guid_opt.has_value()) {
        std::cerr << "[self-test] failed to generate secure server guid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    const std::array<std::uint8_t, 16> guid = guid_opt.value();
    const std::uint64_t start_time = now_windows_filetime_utc();
    const AuthConfig auth{true, false, false, false, false, "testuser", "testpass"};
    ShareSecurityConfig hardening{};
    const std::filesystem::path share_dir =
        (std::filesystem::temp_directory_path() / "smb_single_self_test_share").lexically_normal();
    std::error_code ec{};
    (void)std::filesystem::remove_all(share_dir, ec);
    ec.clear();
    if (!std::filesystem::create_directories(share_dir, ec) || ec) {
        std::cerr << "[self-test] failed to create temporary share directory" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    const std::string share_dir_text = share_dir.string();

    const std::vector<std::uint8_t> negotiate_req = make_negotiate_request_payload(1U);
    RequestResult r1 = process_request(negotiate_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (r1.payload.empty()) {
        std::cerr << "[self-test] NEGOTIATE returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(r1.payload, static_cast<std::uint16_t>(Smb2Command::Negotiate), 1U, kStatusSuccess)) {
        std::cerr << "[self-test] NEGOTIATE response header invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    std::array<std::uint8_t, 16> main_session_key{};
    std::uint64_t session_id = 0U;
    if (!run_ntlmv2_session_setup_for_test(
            state, auth, share_dir_text, hardening, guid, start_time, 200U, 2U, "testuser", "testpass", session_id, main_session_key)) {
        std::cerr << "[self-test] NTLMv2 SESSION_SETUP sequence failed" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    (void)main_session_key;

    const std::vector<std::uint8_t> tree_req =
        make_tree_connect_request_payload(3U, session_id, "//127.0.0.1/share");
    RequestResult tree_rsp =
        process_request(tree_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (tree_rsp.payload.empty()) {
        std::cerr << "[self-test] TREE_CONNECT returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(tree_rsp.payload, static_cast<std::uint16_t>(Smb2Command::TreeConnect), 3U, kStatusSuccess)) {
        std::cerr << "[self-test] TREE_CONNECT response invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    std::uint32_t tree_id = 0U;
    if (!extract_tree_id_from_response(tree_rsp.payload, tree_id) || (tree_id == 0U)) {
        std::cerr << "[self-test] TREE_CONNECT returned invalid tree id" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> create_req =
        make_create_request_payload(4U, session_id, tree_id, "upload_test.bin", 0xC0000000U, kFileOpenIf);
    RequestResult create_rsp =
        process_request(create_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (create_rsp.payload.empty()) {
        std::cerr << "[self-test] CREATE returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(create_rsp.payload, static_cast<std::uint16_t>(Smb2Command::Create), 4U, kStatusSuccess)) {
        std::cerr << "[self-test] CREATE response invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    FileIdPair file_id{};
    if (!extract_create_file_id(create_rsp.payload, file_id)) {
        std::cerr << "[self-test] CREATE returned invalid file id" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> write_data = {'T', 'E', 'S', 'T', '-', 'O', 'K'};
    const std::vector<std::uint8_t> write_req =
        make_write_request_payload(5U, session_id, tree_id, file_id, 0U, write_data);
    RequestResult write_rsp =
        process_request(write_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (write_rsp.payload.empty()) {
        std::cerr << "[self-test] WRITE returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(write_rsp.payload, static_cast<std::uint16_t>(Smb2Command::Write), 5U, kStatusSuccess)) {
        std::cerr << "[self-test] WRITE response invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    std::uint32_t written = 0U;
    if (!extract_write_count(write_rsp.payload, written) || (written != write_data.size())) {
        std::cerr << "[self-test] WRITE count mismatch" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> read_req =
        make_read_request_payload(6U, session_id, tree_id, file_id, 0U, static_cast<std::uint32_t>(write_data.size()));
    RequestResult read_rsp =
        process_request(read_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (read_rsp.payload.empty()) {
        std::cerr << "[self-test] READ returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(read_rsp.payload, static_cast<std::uint16_t>(Smb2Command::Read), 6U, kStatusSuccess)) {
        std::cerr << "[self-test] READ response invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    std::vector<std::uint8_t> read_data{};
    if (!extract_read_data(read_rsp.payload, read_data) || (read_data != write_data)) {
        std::cerr << "[self-test] READ data mismatch" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> lock_req = make_lock_request_payload(7U, session_id, tree_id, file_id);
    RequestResult lock_rsp =
        process_request(lock_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (lock_rsp.payload.empty()) {
        std::cerr << "[self-test] LOCK returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(lock_rsp.payload, static_cast<std::uint16_t>(Smb2Command::Lock), 7U, kStatusSuccess)) {
        std::cerr << "[self-test] LOCK response invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    const FileIdPair ioctl_no_file_id{std::numeric_limits<std::uint64_t>::max(), std::numeric_limits<std::uint64_t>::max()};
    const std::vector<std::uint8_t> ioctl_req = make_ioctl_request_payload(8U,
                                                                           session_id,
                                                                           tree_id,
                                                                           kFsctlValidateNegotiateInfo,
                                                                           ioctl_no_file_id,
                                                                           4096U,
                                                                           0U,
                                                                           std::vector<std::uint8_t>{});
    RequestResult ioctl_rsp =
        process_request(ioctl_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (ioctl_rsp.payload.empty()) {
        std::cerr << "[self-test] IOCTL returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(ioctl_rsp.payload, static_cast<std::uint16_t>(Smb2Command::Ioctl), 8U, kStatusSuccess)) {
        std::cerr << "[self-test] IOCTL response invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> oplock_req = make_oplock_break_request_payload(9U, session_id, tree_id, file_id, 0U);
    RequestResult oplock_rsp =
        process_request(oplock_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (oplock_rsp.payload.empty()) {
        std::cerr << "[self-test] OPLOCK_BREAK returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(
            oplock_rsp.payload, static_cast<std::uint16_t>(Smb2Command::OplockBreak), 9U, kStatusSuccess)) {
        std::cerr << "[self-test] OPLOCK_BREAK response invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> close_req = make_close_request_payload(10U, session_id, tree_id, file_id);
    RequestResult close_rsp =
        process_request(close_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (close_rsp.payload.empty()) {
        std::cerr << "[self-test] CLOSE returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(close_rsp.payload, static_cast<std::uint16_t>(Smb2Command::Close), 10U, kStatusSuccess)) {
        std::cerr << "[self-test] CLOSE response invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> dir_create_req =
        make_create_request_payload(11U, session_id, tree_id, "", 0x00000001U, kFileOpen, 0x00000001U);
    RequestResult dir_create_rsp =
        process_request(dir_create_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (dir_create_rsp.payload.empty()) {
        std::cerr << "[self-test] directory CREATE returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(
            dir_create_rsp.payload, static_cast<std::uint16_t>(Smb2Command::Create), 11U, kStatusSuccess)) {
        std::cerr << "[self-test] directory CREATE response invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    FileIdPair dir_file_id{};
    if (!extract_create_file_id(dir_create_rsp.payload, dir_file_id)) {
        std::cerr << "[self-test] directory CREATE returned invalid file id" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> notify_req =
        make_change_notify_request_payload(12U, session_id, tree_id, dir_file_id, 4096U, 0U, 0x00000017U);
    RequestResult notify_rsp =
        process_request(notify_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (notify_rsp.payload.empty()) {
        std::cerr << "[self-test] CHANGE_NOTIFY returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(
            notify_rsp.payload, static_cast<std::uint16_t>(Smb2Command::ChangeNotify), 12U, kStatusSuccess)) {
        std::cerr << "[self-test] CHANGE_NOTIFY response invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> dir_close_req = make_close_request_payload(13U, session_id, tree_id, dir_file_id);
    RequestResult dir_close_rsp =
        process_request(dir_close_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (dir_close_rsp.payload.empty()) {
        std::cerr << "[self-test] directory CLOSE returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(
            dir_close_rsp.payload, static_cast<std::uint16_t>(Smb2Command::Close), 13U, kStatusSuccess)) {
        std::cerr << "[self-test] directory CLOSE response invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> cancel_req = make_cancel_request_payload(14U, session_id, tree_id);
    RequestResult cancel_rsp =
        process_request(cancel_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (cancel_rsp.payload.empty()) {
        std::cerr << "[self-test] CANCEL returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(cancel_rsp.payload, static_cast<std::uint16_t>(Smb2Command::Cancel), 14U, kStatusSuccess)) {
        std::cerr << "[self-test] CANCEL response invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> echo_req = make_echo_request_payload(15U, session_id, tree_id);
    RequestResult echo_rsp =
        process_request(echo_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (echo_rsp.payload.empty()) {
        std::cerr << "[self-test] ECHO returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(echo_rsp.payload, static_cast<std::uint16_t>(Smb2Command::Echo), 15U, kStatusSuccess)) {
        std::cerr << "[self-test] ECHO response invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::string delete_name = "delete_me.tmp";
    const std::vector<std::uint8_t> delete_create_req =
        make_create_request_payload(16U, session_id, tree_id, delete_name, 0xC0010000U, kFileOpenIf);
    RequestResult delete_create_rsp =
        process_request(delete_create_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (delete_create_rsp.payload.empty()) {
        std::cerr << "[self-test] delete CREATE returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(
            delete_create_rsp.payload, static_cast<std::uint16_t>(Smb2Command::Create), 16U, kStatusSuccess)) {
        std::cerr << "[self-test] delete CREATE response invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    FileIdPair delete_file_id{};
    if (!extract_create_file_id(delete_create_rsp.payload, delete_file_id)) {
        std::cerr << "[self-test] delete CREATE file id invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> set_info_req =
        make_set_info_disposition_request_payload(17U, session_id, tree_id, delete_file_id, true, true);
    RequestResult set_info_rsp =
        process_request(set_info_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (set_info_rsp.payload.empty()) {
        std::cerr << "[self-test] SET_INFO returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(
            set_info_rsp.payload, static_cast<std::uint16_t>(Smb2Command::SetInfo), 17U, kStatusSuccess)) {
        std::cerr << "[self-test] SET_INFO response invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> delete_close_req = make_close_request_payload(18U, session_id, tree_id, delete_file_id);
    RequestResult delete_close_rsp =
        process_request(delete_close_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (delete_close_rsp.payload.empty()) {
        std::cerr << "[self-test] delete CLOSE returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(
            delete_close_rsp.payload, static_cast<std::uint16_t>(Smb2Command::Close), 18U, kStatusSuccess)) {
        std::cerr << "[self-test] delete CLOSE response invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    const std::filesystem::path delete_path = share_dir / delete_name;
    if (std::filesystem::exists(delete_path, ec)) {
        std::cerr << "[self-test] delete-on-close file still exists" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (ec) {
        std::cerr << "[self-test] delete-on-close existence check failed" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> tree_disconnect_req = make_tree_disconnect_request_payload(19U, session_id, tree_id);
    RequestResult tree_disconnect_rsp =
        process_request(tree_disconnect_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (tree_disconnect_rsp.payload.empty()) {
        std::cerr << "[self-test] TREE_DISCONNECT returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(
            tree_disconnect_rsp.payload, static_cast<std::uint16_t>(Smb2Command::TreeDisconnect), 19U, kStatusSuccess)) {
        std::cerr << "[self-test] TREE_DISCONNECT response invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> logoff_req = make_logoff_request_payload(20U, session_id);
    RequestResult logoff_rsp =
        process_request(logoff_req, state, auth, share_dir_text, hardening, guid, start_time);
    if (logoff_rsp.payload.empty()) {
        std::cerr << "[self-test] LOGOFF returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(logoff_rsp.payload, static_cast<std::uint16_t>(Smb2Command::Logoff), 20U, kStatusSuccess)) {
        std::cerr << "[self-test] LOGOFF response invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    const AuthConfig signing_auth{true, false, false, true, true, "testuser", "testpass"};
    std::array<std::uint8_t, 16> signing_key{};

    ConnectionState signing_state{};
    const std::vector<std::uint8_t> signing_neg_req = make_negotiate_request_payload(30U);
    RequestResult signing_neg_rsp =
        process_request(signing_neg_req, signing_state, signing_auth, share_dir_text, hardening, guid, start_time);
    if (signing_neg_rsp.payload.empty()) {
        std::cerr << "[self-test] NEGOTIATE(signing) returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(
            signing_neg_rsp.payload, static_cast<std::uint16_t>(Smb2Command::Negotiate), 30U, kStatusSuccess)) {
        std::cerr << "[self-test] NEGOTIATE(signing) response invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (signing_neg_rsp.payload.size() < (sizeof(Smb2Header) + sizeof(NegotiateResponseBody))) {
        std::cerr << "[self-test] NEGOTIATE(signing) short response body" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    const std::uint16_t signing_sec_mode = read_le16(signing_neg_rsp.payload.data() + sizeof(Smb2Header) + 2U);
    if ((signing_sec_mode & 0x0001U) == 0U || (signing_sec_mode & 0x0002U) == 0U) {
        std::cerr << "[self-test] NEGOTIATE(signing) security mode missing signing bits" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    std::uint64_t signing_session_id = 0U;
    if (!run_ntlmv2_session_setup_for_test(signing_state,
                                           signing_auth,
                                           share_dir_text,
                                           hardening,
                                           guid,
                                           start_time,
                                           131U,
                                           31U,
                                           "testuser",
                                           "testpass",
                                           signing_session_id,
                                           signing_key)) {
        std::cerr << "[self-test] SESSION_SETUP(signing) NTLMv2 sequence failed" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> unsigned_tree_req =
        make_tree_connect_request_payload(32U, signing_session_id, "//127.0.0.1/share");
    RequestResult unsigned_tree_rsp =
        process_request(unsigned_tree_req, signing_state, signing_auth, share_dir_text, hardening, guid, start_time);
    if (unsigned_tree_rsp.payload.empty()) {
        std::cerr << "[self-test] TREE_CONNECT(unsigned signing-required) returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(unsigned_tree_rsp.payload,
                                  static_cast<std::uint16_t>(Smb2Command::TreeConnect),
                                  32U,
                                  kStatusAccessDenied)) {
        std::cerr << "[self-test] TREE_CONNECT(unsigned signing-required) expected ACCESS_DENIED" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    ConnectionState signing_state_ok{};
    RequestResult signing_neg_ok_rsp =
        process_request(signing_neg_req, signing_state_ok, signing_auth, share_dir_text, hardening, guid, start_time);
    if (signing_neg_ok_rsp.payload.empty()) {
        std::cerr << "[self-test] NEGOTIATE(signing-ok path) returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    std::uint64_t signing_ok_session_id = 0U;
    if (!run_ntlmv2_session_setup_for_test(signing_state_ok,
                                           signing_auth,
                                           share_dir_text,
                                           hardening,
                                           guid,
                                           start_time,
                                           141U,
                                           41U,
                                           "testuser",
                                           "testpass",
                                           signing_ok_session_id,
                                           signing_key)) {
        std::cerr << "[self-test] SESSION_SETUP(signing-ok path) NTLMv2 sequence failed" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    std::vector<std::uint8_t> signed_tree_req =
        make_tree_connect_request_payload(42U, signing_ok_session_id, "//127.0.0.1/share");
    if (!smb2_sign_packet(signed_tree_req, signing_key)) {
        std::cerr << "[self-test] TREE_CONNECT(signed) signing failed" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    RequestResult signed_tree_rsp =
        process_request(signed_tree_req, signing_state_ok, signing_auth, share_dir_text, hardening, guid, start_time);
    if (signed_tree_rsp.payload.empty()) {
        std::cerr << "[self-test] TREE_CONNECT(signed) returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(
            signed_tree_rsp.payload, static_cast<std::uint16_t>(Smb2Command::TreeConnect), 42U, kStatusSuccess)) {
        std::cerr << "[self-test] TREE_CONNECT(signed) response invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if ((read_le32(signed_tree_rsp.payload.data() + 16U) & kSmb2FlagSigned) == 0U) {
        std::cerr << "[self-test] TREE_CONNECT(signed) response missing signed flag" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!smb2_verify_packet_signature(signed_tree_rsp.payload, signing_key)) {
        std::cerr << "[self-test] TREE_CONNECT(signed) response signature invalid" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    RequestResult replay_tree_rsp =
        process_request(signed_tree_req, signing_state_ok, signing_auth, share_dir_text, hardening, guid, start_time);
    if (replay_tree_rsp.payload.empty()) {
        std::cerr << "[self-test] TREE_CONNECT(replay) returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(
            replay_tree_rsp.payload, static_cast<std::uint16_t>(Smb2Command::TreeConnect), 42U, kStatusAccessDenied)) {
        std::cerr << "[self-test] TREE_CONNECT(replay) expected ACCESS_DENIED" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    std::vector<std::uint8_t> tampered_tree_req =
        make_tree_connect_request_payload(43U, signing_ok_session_id, "//127.0.0.1/share");
    if (!smb2_sign_packet(tampered_tree_req, signing_key)) {
        std::cerr << "[self-test] TREE_CONNECT(tampered) signing failed" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (tampered_tree_req.size() <= sizeof(Smb2Header)) {
        std::cerr << "[self-test] TREE_CONNECT(tampered) short request" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    tampered_tree_req.back() ^= 0x01U;
    RequestResult tampered_tree_rsp =
        process_request(tampered_tree_req, signing_state_ok, signing_auth, share_dir_text, hardening, guid, start_time);
    if (tampered_tree_rsp.payload.empty()) {
        std::cerr << "[self-test] TREE_CONNECT(tampered) returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(tampered_tree_rsp.payload,
                                  static_cast<std::uint16_t>(Smb2Command::TreeConnect),
                                  43U,
                                  kStatusAccessDenied)) {
        std::cerr << "[self-test] TREE_CONNECT(tampered) expected ACCESS_DENIED" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    ConnectionState auth_fail_state{};
    RequestResult auth_neg =
        process_request(negotiate_req, auth_fail_state, auth, share_dir_text, hardening, guid, start_time);
    if (auth_neg.payload.empty()) {
        std::cerr << "[self-test] NEGOTIATE(auth-fail path) returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    const std::vector<std::uint8_t> bad_setup_req =
        make_session_setup_request_payload(21U, "testuser", "testpass", true);
    RequestResult bad_setup =
        process_request(bad_setup_req, auth_fail_state, auth, share_dir_text, hardening, guid, start_time);
    if (bad_setup.payload.empty()) {
        std::cerr << "[self-test] USER/PASS SESSION_SETUP returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(
            bad_setup.payload, static_cast<std::uint16_t>(Smb2Command::SessionSetup), 21U, kStatusLogonFailure)) {
        std::cerr << "[self-test] USER/PASS SESSION_SETUP expected LOGON_FAILURE" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    ConnectionState legacy_fail_state{};
    RequestResult legacy_neg =
        process_request(negotiate_req, legacy_fail_state, auth, share_dir_text, hardening, guid, start_time);
    if (legacy_neg.payload.empty()) {
        std::cerr << "[self-test] NEGOTIATE(legacy-fail path) returned empty payload" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    const std::vector<std::uint8_t> legacy_type1_req =
        make_session_setup_request_payload_with_blob(220U, 0U, make_ntlm_type1_security_blob());
    RequestResult legacy_type1_rsp =
        process_request(legacy_type1_req, legacy_fail_state, auth, share_dir_text, hardening, guid, start_time);
    if (legacy_type1_rsp.payload.empty() ||
        !validate_response_header(legacy_type1_rsp.payload,
                                  static_cast<std::uint16_t>(Smb2Command::SessionSetup),
                                  220U,
                                  kStatusMoreProcessingRequired)) {
        std::cerr << "[self-test] NTLM type1 setup for legacy path failed" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    const std::uint8_t* legacy_challenge_blob = nullptr;
    std::size_t legacy_challenge_blob_size = 0U;
    if (!extract_session_setup_response_security_blob(
            legacy_type1_rsp.payload, legacy_challenge_blob, legacy_challenge_blob_size) ||
        (legacy_challenge_blob == nullptr) || (legacy_challenge_blob_size == 0U)) {
        std::cerr << "[self-test] NTLM legacy challenge extraction failed" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    std::array<std::uint8_t, 8> legacy_challenge{};
    if (!extract_ntlm_type2_challenge(legacy_challenge_blob, legacy_challenge_blob_size, legacy_challenge)) {
        std::cerr << "[self-test] NTLM legacy challenge parse failed" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    std::vector<std::uint8_t> legacy_type3_blob{};
    if (!build_ntlmv1_type3_security_blob_for_test("testuser", "testpass", legacy_challenge, legacy_type3_blob)) {
        std::cerr << "[self-test] failed to build NTLMv1 type3 blob" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }
    const std::uint64_t legacy_session_id = read_le64(legacy_type1_rsp.payload.data() + 40U);
    const std::vector<std::uint8_t> legacy_type3_req =
        make_session_setup_request_payload_with_blob(221U, legacy_session_id, legacy_type3_blob);
    RequestResult legacy_type3_rsp =
        process_request(legacy_type3_req, legacy_fail_state, auth, share_dir_text, hardening, guid, start_time);
    if (legacy_type3_rsp.payload.empty() ||
        !validate_response_header(legacy_type3_rsp.payload,
                                  static_cast<std::uint16_t>(Smb2Command::SessionSetup),
                                  221U,
                                  kStatusLogonFailure)) {
        std::cerr << "[self-test] NTLMv1/NTLM2-session fallback was not rejected" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    ConnectionState compound_state{};
    std::vector<std::uint8_t> compound_neg_req = make_negotiate_request_payload(230U);
    write_le32_at(compound_neg_req, 20U, 64U);
    RequestResult compound_rsp =
        process_request(compound_neg_req, compound_state, auth, share_dir_text, hardening, guid, start_time);
    if (compound_rsp.payload.empty() ||
        !validate_response_header(
            compound_rsp.payload, static_cast<std::uint16_t>(Smb2Command::Negotiate), 230U, kStatusInvalidParameter)) {
        std::cerr << "[self-test] compound request should be rejected" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    if (verbose) {
        std::cout << "[self-test] packet-level validation passed (auth + signing + tree/connect/disconnect + logoff + create/write/read/lock/ioctl/cancel/change-notify/oplock + set-info checked)"
                  << std::endl;
    }
    (void)std::filesystem::remove_all(share_dir, ec);
    return static_cast<int>(ExitCode::Ok);
}

bool recv_nbss_payload(socket_t sock, std::vector<std::uint8_t>& payload) {
    std::array<std::uint8_t, 4> nbss{};
    if (!recv_all(sock, nbss.data(), nbss.size())) {
        return false;
    }
    if (nbss[0] != 0x00U) {
        return false;
    }
    const std::uint32_t len =
        (static_cast<std::uint32_t>(nbss[1]) << 16U) |
        (static_cast<std::uint32_t>(nbss[2]) << 8U) |
        static_cast<std::uint32_t>(nbss[3]);
    if ((len < sizeof(Smb2Header)) || (len > kSmbMaxFrameBytes)) {
        return false;
    }
    payload.resize(static_cast<std::size_t>(len));
    return recv_all(sock, payload.data(), payload.size());
}

int run_smoke_client(const std::string& host,
                     std::uint16_t port,
                     bool verbose,
                     bool debug,
                     const std::string& username,
                     const std::string& password,
                     bool allow_anonymous,
                     bool disable_client_signing) {
    const socket_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == kInvalidSocket) {
        const int err = socket_last_error();
        std::cerr << "[smoke] socket() failed (errno=" << err << ")" << std::endl;
        if (socket_permission_error(err)) {
            return static_cast<int>(ExitCode::EnvironmentRestricted);
        }
        return static_cast<int>(ExitCode::GenericError);
    }
    (void)set_socket_timeouts(sock, kDefaultSocketTimeoutSeconds);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        std::cerr << "[smoke] invalid host: " << host << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::InvalidArguments);
    }
    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        std::cerr << "[smoke] connect() failed to " << host << ":" << port
                  << " (errno=" << socket_last_error() << ")" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> negotiate_wire = add_nbss_header(make_negotiate_request_payload(1U));
    if (!send_all(sock, negotiate_wire.data(), negotiate_wire.size())) {
        std::cerr << "[smoke] failed to send NEGOTIATE" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }
    std::vector<std::uint8_t> negotiate_response{};
    if (!recv_nbss_payload(sock, negotiate_response)) {
        std::cerr << "[smoke] failed to read NEGOTIATE response" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(
            negotiate_response, static_cast<std::uint16_t>(Smb2Command::Negotiate), 1U, kStatusSuccess)) {
        std::cerr << "[smoke] NEGOTIATE response invalid" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }

    std::array<std::uint8_t, 16> signing_key{};
    bool signing_active = false;
    std::uint64_t session_id = 0U;
    if (allow_anonymous) {
        const std::vector<std::uint8_t> anon_setup_wire =
            add_nbss_header(make_session_setup_request_payload_with_blob(2U, 0U, std::vector<std::uint8_t>{}));
        if (!send_all(sock, anon_setup_wire.data(), anon_setup_wire.size())) {
            std::cerr << "[smoke] failed to send SESSION_SETUP(anonymous)" << std::endl;
            close_socket(sock);
            return static_cast<int>(ExitCode::GenericError);
        }
        std::vector<std::uint8_t> anon_setup_response{};
        if (!recv_nbss_payload(sock, anon_setup_response)) {
            std::cerr << "[smoke] failed to read SESSION_SETUP(anonymous) response" << std::endl;
            close_socket(sock);
            return static_cast<int>(ExitCode::GenericError);
        }
        if (!validate_response_header(
                anon_setup_response, static_cast<std::uint16_t>(Smb2Command::SessionSetup), 2U, kStatusSuccess)) {
            std::cerr << "[smoke] SESSION_SETUP(anonymous) response invalid" << std::endl;
            close_socket(sock);
            return static_cast<int>(ExitCode::GenericError);
        }
        session_id = read_le64(anon_setup_response.data() + 40U);
        if (session_id == 0U) {
            std::cerr << "[smoke] SESSION_SETUP(anonymous) session id invalid" << std::endl;
            close_socket(sock);
            return static_cast<int>(ExitCode::GenericError);
        }
    } else {
        const std::vector<std::uint8_t> type1_wire =
            add_nbss_header(make_session_setup_request_payload_with_blob(2U, 0U, make_ntlm_type1_security_blob()));
        if (!send_all(sock, type1_wire.data(), type1_wire.size())) {
            std::cerr << "[smoke] failed to send SESSION_SETUP(type1)" << std::endl;
            close_socket(sock);
            return static_cast<int>(ExitCode::GenericError);
        }
        std::vector<std::uint8_t> type1_response{};
        if (!recv_nbss_payload(sock, type1_response)) {
            std::cerr << "[smoke] failed to read SESSION_SETUP(type1) response" << std::endl;
            close_socket(sock);
            return static_cast<int>(ExitCode::GenericError);
        }
        if (!validate_response_header(
                type1_response, static_cast<std::uint16_t>(Smb2Command::SessionSetup), 2U, kStatusMoreProcessingRequired)) {
            std::cerr << "[smoke] SESSION_SETUP(type1) response invalid" << std::endl;
            close_socket(sock);
            return static_cast<int>(ExitCode::GenericError);
        }
        const std::uint64_t intermediate_session_id = read_le64(type1_response.data() + 40U);
        if (intermediate_session_id == 0U) {
            std::cerr << "[smoke] SESSION_SETUP(type1) intermediate session id invalid" << std::endl;
            close_socket(sock);
            return static_cast<int>(ExitCode::GenericError);
        }
        const std::uint8_t* challenge_blob = nullptr;
        std::size_t challenge_blob_size = 0U;
        if (!extract_session_setup_response_security_blob(type1_response, challenge_blob, challenge_blob_size) ||
            (challenge_blob == nullptr) || (challenge_blob_size == 0U)) {
            std::cerr << "[smoke] SESSION_SETUP(type1) challenge blob missing" << std::endl;
            close_socket(sock);
            return static_cast<int>(ExitCode::GenericError);
        }
        std::array<std::uint8_t, 8> server_challenge{};
        if (!extract_ntlm_type2_challenge(challenge_blob, challenge_blob_size, server_challenge)) {
            std::cerr << "[smoke] failed to parse NTLM type2 challenge" << std::endl;
            close_socket(sock);
            return static_cast<int>(ExitCode::GenericError);
        }
        std::vector<std::uint8_t> type3_blob{};
        if (!build_ntlmv2_type3_security_blob(username, password, server_challenge, type3_blob, signing_key)) {
            std::cerr << "[smoke] failed to build NTLMv2 type3 blob" << std::endl;
            close_socket(sock);
            return static_cast<int>(ExitCode::GenericError);
        }
        const std::vector<std::uint8_t> type3_wire = add_nbss_header(
            make_session_setup_request_payload_with_blob(3U, intermediate_session_id, type3_blob));
        if (!send_all(sock, type3_wire.data(), type3_wire.size())) {
            std::cerr << "[smoke] failed to send SESSION_SETUP(type3)" << std::endl;
            close_socket(sock);
            return static_cast<int>(ExitCode::GenericError);
        }
        std::vector<std::uint8_t> type3_response{};
        if (!recv_nbss_payload(sock, type3_response)) {
            std::cerr << "[smoke] failed to read SESSION_SETUP(type3) response" << std::endl;
            close_socket(sock);
            return static_cast<int>(ExitCode::GenericError);
        }
        if (!validate_response_header(
                type3_response, static_cast<std::uint16_t>(Smb2Command::SessionSetup), 3U, kStatusSuccess)) {
            std::cerr << "[smoke] SESSION_SETUP(type3) response invalid" << std::endl;
            close_socket(sock);
            return static_cast<int>(ExitCode::GenericError);
        }
        session_id = read_le64(type3_response.data() + 40U);
        if (session_id == 0U) {
            std::cerr << "[smoke] SESSION_SETUP(type3) session id invalid" << std::endl;
            close_socket(sock);
            return static_cast<int>(ExitCode::GenericError);
        }
        signing_active = !disable_client_signing;
    }
    const auto make_wire = [&](std::vector<std::uint8_t> req) {
        if (signing_active) {
            (void)smb2_sign_packet(req, signing_key);
        }
        return add_nbss_header(req);
    };

    const std::vector<std::uint8_t> tree_wire =
        make_wire(make_tree_connect_request_payload(3U, session_id, "//127.0.0.1/share"));
    if (!send_all(sock, tree_wire.data(), tree_wire.size())) {
        std::cerr << "[smoke] failed to send TREE_CONNECT" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }
    std::vector<std::uint8_t> tree_response{};
    if (!recv_nbss_payload(sock, tree_response)) {
        std::cerr << "[smoke] failed to read TREE_CONNECT response" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(tree_response, static_cast<std::uint16_t>(Smb2Command::TreeConnect), 3U, kStatusSuccess)) {
        std::cerr << "[smoke] TREE_CONNECT response invalid" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }
    std::uint32_t tree_id = 0U;
    if (!extract_tree_id_from_response(tree_response, tree_id) || (tree_id == 0U)) {
        std::cerr << "[smoke] TREE_CONNECT tree id invalid" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> create_wire =
        make_wire(make_create_request_payload(4U, session_id, tree_id, "smoke_upload.bin", 0xC0000000U, kFileOpenIf));
    if (!send_all(sock, create_wire.data(), create_wire.size())) {
        std::cerr << "[smoke] failed to send CREATE" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }
    std::vector<std::uint8_t> create_response{};
    if (!recv_nbss_payload(sock, create_response)) {
        std::cerr << "[smoke] failed to read CREATE response" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(create_response, static_cast<std::uint16_t>(Smb2Command::Create), 4U, kStatusSuccess)) {
        std::cerr << "[smoke] CREATE response invalid" << std::endl;
        if (debug) {
            print_response_header_debug(create_response, "CREATE");
        }
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }
    FileIdPair file_id{};
    if (!extract_create_file_id(create_response, file_id)) {
        std::cerr << "[smoke] CREATE file id invalid" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> write_data = {'S', 'M', 'O', 'K', 'E', '-', 'O', 'K'};
    const std::vector<std::uint8_t> write_wire =
        make_wire(make_write_request_payload(5U, session_id, tree_id, file_id, 0U, write_data));
    if (!send_all(sock, write_wire.data(), write_wire.size())) {
        std::cerr << "[smoke] failed to send WRITE" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }
    std::vector<std::uint8_t> write_response{};
    if (!recv_nbss_payload(sock, write_response)) {
        std::cerr << "[smoke] failed to read WRITE response" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(write_response, static_cast<std::uint16_t>(Smb2Command::Write), 5U, kStatusSuccess)) {
        std::cerr << "[smoke] WRITE response invalid" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }
    std::uint32_t write_count = 0U;
    if (!extract_write_count(write_response, write_count) || (write_count != write_data.size())) {
        std::cerr << "[smoke] WRITE count mismatch" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> read_wire =
        make_wire(make_read_request_payload(6U, session_id, tree_id, file_id, 0U, static_cast<std::uint32_t>(write_data.size())));
    if (!send_all(sock, read_wire.data(), read_wire.size())) {
        std::cerr << "[smoke] failed to send READ" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }
    std::vector<std::uint8_t> read_response{};
    if (!recv_nbss_payload(sock, read_response)) {
        std::cerr << "[smoke] failed to read READ response" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(read_response, static_cast<std::uint16_t>(Smb2Command::Read), 6U, kStatusSuccess)) {
        std::cerr << "[smoke] READ response invalid" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }
    std::vector<std::uint8_t> read_data{};
    if (!extract_read_data(read_response, read_data) || (read_data != write_data)) {
        std::cerr << "[smoke] READ data mismatch" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }

    const std::vector<std::uint8_t> close_wire =
        make_wire(make_close_request_payload(7U, session_id, tree_id, file_id));
    if (!send_all(sock, close_wire.data(), close_wire.size())) {
        std::cerr << "[smoke] failed to send CLOSE" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }
    std::vector<std::uint8_t> close_response{};
    if (!recv_nbss_payload(sock, close_response)) {
        std::cerr << "[smoke] failed to read CLOSE response" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }
    if (!validate_response_header(close_response, static_cast<std::uint16_t>(Smb2Command::Close), 7U, kStatusSuccess)) {
        std::cerr << "[smoke] CLOSE response invalid" << std::endl;
        close_socket(sock);
        return static_cast<int>(ExitCode::GenericError);
    }

    close_socket(sock);
    if (verbose) {
        std::cout << "[smoke] SMB NEGOTIATE + SESSION_SETUP + TREE/CREATE/WRITE/READ/CLOSE passed" << std::endl;
    }
    return static_cast<int>(ExitCode::Ok);
}

// -------------------------------
// CLI
// -------------------------------

enum class CliMode {
    Serve,
    SmokeClient,
    SelfTest,
    Help,
    Version,
};

struct CliOptions {
    CliMode mode{CliMode::Serve};
    ServerConfig server{};
    std::string host{"127.0.0.1"};
    std::string username{};
    std::string password{};
    bool allow_anonymous{false};
    bool disable_client_signing{false};
};

void print_usage() {
    std::cout
        << kAppName << " " << kAppVersion << "\n"
        << "Usage:\n"
        << "  " << kAppName << " serve [options]\n"
        << "  " << kAppName << " smoke-client [options]\n"
        << "  " << kAppName << " self-test\n"
        << "  " << kAppName << " version\n"
        << "  " << kAppName << " help\n"
        << "\n"
        << "Serve options:\n"
        << "  --port <n>          TCP port (default 445)\n"
        << "  --once              handle one connection and exit\n"
        << "  --max-clients <n>   concurrent clients limit (default 128)\n"
        << "  --max-clients-per-ip <n> per-IP concurrent client limit (default 8)\n"
        << "  --timeout <n>       socket timeout seconds (default 10)\n"
        << "  --auth-fail-window-sec <n> auth failure counting window in seconds (default 600)\n"
        << "  --auth-fail-max <n> max auth failures in window before temporary block (default 5)\n"
        << "  --auth-block-sec <n> temporary block duration in seconds after brute force (default 1800)\n"
        << "  --share-dir <path>  local directory exposed by the server (default .)\n"
        << "  --read-only         disable WRITE and destructive CREATE dispositions\n"
        << "  --allow-overwrite   permit overwrite dispositions (supersede/overwrite)\n"
        << "  --allow-dotfiles    permit paths with dot-prefixed components\n"
        << "  --max-open-files <n> per-connection open handle limit (default 64)\n"
        << "  --max-file-size <n> max file size in bytes for reads/writes (default 67108864)\n"
        << "  --min-password-length <n> minimum password length when auth is enabled (default 8)\n"
        << "  --username <text>   required login user (serve/smoke-client)\n"
        << "  --password <text>   required login password (serve/smoke-client)\n"
        << "  --allow-anonymous   disable auth requirement (serve/smoke-client)\n"
        << "  --strict-auth-session-flags  disable guest-compat session flag for authenticated logins\n"
        << "  --disable-legacy-ntlm compatibility flag; legacy NTLM is always disabled\n"
        << "  --enable-signing    enable SMB2 packet signing for authenticated sessions\n"
        << "  --require-signing   require signed SMB2 requests after authentication\n"
        << "  --prod-profile      apply production defaults and stricter validations\n"
        << "  --debug             enable debug logs (disabled by default)\n"
        << "\n"
        << "Smoke client options:\n"
        << "  --host <ip>         target host (default 127.0.0.1)\n"
        << "  --port <n>          target port (default 445)\n"
        << "  --disable-client-signing  send unsigned requests (QCA negative test)\n"
        << "  --debug             enable debug logs on failures\n"
        << "\n"
        << "Self-test:\n"
        << "  Runs packet-level tests without network dependency.\n";
}

bool parse_cli(int argc, char** argv, CliOptions& out, std::string& error) {
    int argi = 1;
    if (argi < argc) {
        const std::string cmd(argv[argi]);
        if (cmd == "serve") {
            out.mode = CliMode::Serve;
            ++argi;
        } else if (cmd == "smoke-client") {
            out.mode = CliMode::SmokeClient;
            ++argi;
        } else if (cmd == "self-test") {
            out.mode = CliMode::SelfTest;
            ++argi;
        } else if (cmd == "help" || cmd == "--help" || cmd == "-h") {
            out.mode = CliMode::Help;
            return true;
        } else if (cmd == "version" || cmd == "--version" || cmd == "-v") {
            out.mode = CliMode::Version;
            return true;
        }
    }

    for (; argi < argc; ++argi) {
        const std::string arg(argv[argi]);

        if (arg == "--debug") {
            out.server.debug = true;
            continue;
        }

        if (arg == "--port") {
            if ((argi + 1) >= argc) {
                error = "--port requires a value";
                return false;
            }
            std::uint16_t p = 0U;
            if (!parse_u16(argv[++argi], &p) || (p == 0U)) {
                error = "invalid --port value";
                return false;
            }
            out.server.port = p;
            continue;
        }

        if (arg == "--host") {
            if ((argi + 1) >= argc) {
                error = "--host requires a value";
                return false;
            }
            out.host = argv[++argi];
            if (out.host.empty()) {
                error = "invalid --host value";
                return false;
            }
            continue;
        }

        if (arg == "--once") {
            out.server.once = true;
            continue;
        }

        if (arg == "--share-dir") {
            if ((argi + 1) >= argc) {
                error = "--share-dir requires a value";
                return false;
            }
            out.server.share_dir = argv[++argi];
            if (out.server.share_dir.empty()) {
                error = "invalid --share-dir value";
                return false;
            }
            continue;
        }

        if (arg == "--read-only") {
            out.server.hardening.read_only = true;
            continue;
        }

        if (arg == "--allow-overwrite") {
            out.server.hardening.allow_overwrite = true;
            continue;
        }

        if (arg == "--allow-dotfiles") {
            out.server.hardening.deny_dot_files = false;
            continue;
        }

        if (arg == "--max-open-files") {
            if ((argi + 1) >= argc) {
                error = "--max-open-files requires a value";
                return false;
            }
            std::uint32_t max_open_files = 0U;
            if (!parse_u32(argv[++argi], &max_open_files) || (max_open_files == 0U)) {
                error = "invalid --max-open-files value";
                return false;
            }
            out.server.hardening.max_open_files = static_cast<std::size_t>(max_open_files);
            continue;
        }

        if (arg == "--max-file-size") {
            if ((argi + 1) >= argc) {
                error = "--max-file-size requires a value";
                return false;
            }
            std::uint64_t max_file_size_bytes = 0U;
            if (!parse_u64(argv[++argi], &max_file_size_bytes) || (max_file_size_bytes == 0U)) {
                error = "invalid --max-file-size value";
                return false;
            }
            out.server.hardening.max_file_size_bytes = max_file_size_bytes;
            continue;
        }

        if (arg == "--min-password-length") {
            if ((argi + 1) >= argc) {
                error = "--min-password-length requires a value";
                return false;
            }
            std::uint32_t min_password_length = 0U;
            if (!parse_u32(argv[++argi], &min_password_length) || (min_password_length == 0U)) {
                error = "invalid --min-password-length value";
                return false;
            }
            out.server.min_password_length = static_cast<std::size_t>(min_password_length);
            continue;
        }

        if (arg == "--username") {
            if ((argi + 1) >= argc) {
                error = "--username requires a value";
                return false;
            }
            out.username = argv[++argi];
            if (out.username.empty()) {
                error = "invalid --username value";
                return false;
            }
            continue;
        }

        if (arg == "--password") {
            if ((argi + 1) >= argc) {
                error = "--password requires a value";
                return false;
            }
            out.password = argv[++argi];
            if (out.password.empty()) {
                error = "invalid --password value";
                return false;
            }
            continue;
        }

        if (arg == "--allow-anonymous") {
            out.allow_anonymous = true;
            continue;
        }

        if (arg == "--disable-client-signing") {
            out.disable_client_signing = true;
            continue;
        }

        if (arg == "--strict-auth-session-flags") {
            out.server.auth.auth_session_guest_compat = false;
            continue;
        }

        if (arg == "--disable-legacy-ntlm") {
            out.server.auth.allow_legacy_ntlm = false;
            continue;
        }

        if (arg == "--enable-signing") {
            out.server.auth.signing_enabled = true;
            continue;
        }

        if (arg == "--require-signing") {
            out.server.auth.signing_enabled = true;
            out.server.auth.signing_required = true;
            continue;
        }

        if (arg == "--prod-profile") {
            out.server.production_profile = true;
            out.allow_anonymous = false;
            out.server.timeout_seconds = 30;
            out.server.max_clients = 256U;
            out.server.abuse.max_clients_per_ip = kDefaultProductionMaxClientsPerIp;
            out.server.abuse.auth_fail_window_sec = 900U;
            out.server.abuse.auth_fail_max = 3U;
            out.server.abuse.auth_block_sec = 3600U;
            out.server.min_password_length = kMinProductionPasswordLength;
            out.server.auth.signing_enabled = true;
            out.server.hardening.allow_overwrite = false;
            out.server.hardening.deny_dot_files = true;
            out.server.hardening.max_open_files = 128U;
            out.server.hardening.max_file_size_bytes = 16ULL * 1024ULL * 1024ULL;
            continue;
        }

        if (arg == "--max-clients") {
            if ((argi + 1) >= argc) {
                error = "--max-clients requires a value";
                return false;
            }
            std::uint32_t max_clients = 0U;
            if (!parse_u32(argv[++argi], &max_clients) || (max_clients == 0U)) {
                error = "invalid --max-clients value";
                return false;
            }
            out.server.max_clients = static_cast<std::size_t>(max_clients);
            continue;
        }

        if (arg == "--max-clients-per-ip") {
            if ((argi + 1) >= argc) {
                error = "--max-clients-per-ip requires a value";
                return false;
            }
            std::uint32_t max_clients_per_ip = 0U;
            if (!parse_u32(argv[++argi], &max_clients_per_ip) || (max_clients_per_ip == 0U)) {
                error = "invalid --max-clients-per-ip value";
                return false;
            }
            out.server.abuse.max_clients_per_ip = static_cast<std::size_t>(max_clients_per_ip);
            continue;
        }

        if (arg == "--timeout") {
            if ((argi + 1) >= argc) {
                error = "--timeout requires a value";
                return false;
            }
            int timeout_seconds = 0;
            if (!parse_int(argv[++argi], &timeout_seconds) || (timeout_seconds <= 0)) {
                error = "invalid --timeout value";
                return false;
            }
            out.server.timeout_seconds = timeout_seconds;
            continue;
        }

        if (arg == "--auth-fail-window-sec") {
            if ((argi + 1) >= argc) {
                error = "--auth-fail-window-sec requires a value";
                return false;
            }
            std::uint32_t window_sec = 0U;
            if (!parse_u32(argv[++argi], &window_sec) || (window_sec == 0U)) {
                error = "invalid --auth-fail-window-sec value";
                return false;
            }
            out.server.abuse.auth_fail_window_sec = window_sec;
            continue;
        }

        if (arg == "--auth-fail-max") {
            if ((argi + 1) >= argc) {
                error = "--auth-fail-max requires a value";
                return false;
            }
            std::uint32_t fail_max = 0U;
            if (!parse_u32(argv[++argi], &fail_max) || (fail_max == 0U)) {
                error = "invalid --auth-fail-max value";
                return false;
            }
            out.server.abuse.auth_fail_max = static_cast<std::size_t>(fail_max);
            continue;
        }

        if (arg == "--auth-block-sec") {
            if ((argi + 1) >= argc) {
                error = "--auth-block-sec requires a value";
                return false;
            }
            std::uint32_t block_sec = 0U;
            if (!parse_u32(argv[++argi], &block_sec) || (block_sec == 0U)) {
                error = "invalid --auth-block-sec value";
                return false;
            }
            out.server.abuse.auth_block_sec = block_sec;
            continue;
        }

        error = "unknown argument: " + arg;
        return false;
    }

    return true;
}

int run_cli(const CliOptions& cli) {
    if (cli.mode == CliMode::Help) {
        print_usage();
        return static_cast<int>(ExitCode::Ok);
    }
    if (cli.mode == CliMode::Version) {
        std::cout << kAppName << " " << kAppVersion << std::endl;
        return static_cast<int>(ExitCode::Ok);
    }

    if (!init_sockets()) {
        std::cerr << "[error] socket stack initialization failed" << std::endl;
        return static_cast<int>(ExitCode::GenericError);
    }

    int rc = static_cast<int>(ExitCode::Ok);
    if (cli.mode == CliMode::Serve) {
        ServerConfig cfg = cli.server;
        cfg.auth.require_auth = !cli.allow_anonymous;
        cfg.auth.username = cli.username;
        cfg.auth.password = cli.password;
        cfg.auth.allow_legacy_ntlm = false;
        rc = run_server(cfg);
    } else if (cli.mode == CliMode::SmokeClient) {
        rc = run_smoke_client(
            cli.host,
            cli.server.port,
            cli.server.verbose,
            cli.server.debug,
            cli.username,
            cli.password,
            cli.allow_anonymous,
            cli.disable_client_signing);
    } else if (cli.mode == CliMode::SelfTest) {
        rc = run_packet_self_test(cli.server.verbose);
    } else {
        rc = static_cast<int>(ExitCode::InvalidArguments);
    }

    cleanup_sockets();
    return rc;
}

}  // namespace smb

int main(int argc, char** argv) {
    smb::CliOptions options{};
    std::string error{};
    if (!smb::parse_cli(argc, argv, options, error)) {
        std::cerr << "[error] " << error << std::endl;
        smb::print_usage();
        return static_cast<int>(smb::ExitCode::InvalidArguments);
    }
    return smb::run_cli(options);
}
