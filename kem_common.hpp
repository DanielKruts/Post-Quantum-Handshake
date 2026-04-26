#pragma once

/*
 * kem_common.hpp
 * Shared types and declarations for the ML-KEM-512 quantum-safe handshake.
 *
 * Requires C++17 or later.
 *
 * Dependencies:
 *   - liboqs   >= 0.10  (https://github.com/open-quantum-safe/liboqs)
 *   - OpenSSL  >= 3.0   (for HKDF-SHA256 via EVP_PKEY_CTX)
 *   - Winsock2 (Windows SDK / ws2_32.lib)
 *
 * CMake build: see CMakeLists.txt
 */

#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <oqs/oqs.h>

// -------------------------------------------------------------------------
// Protocol constants
// -------------------------------------------------------------------------

inline constexpr std::string_view DEFAULT_PORT { "54321" };
inline constexpr int              BACKLOG      { 5 };
inline constexpr std::string_view HKDF_INFO    { "ml-kem-512-handshake-v1" };

// ML-KEM-512 sizes (bytes) — verified at runtime against liboqs metadata
inline constexpr std::size_t KEM_PUBLIC_KEY_LEN  { 1568 };
inline constexpr std::size_t KEM_SECRET_KEY_LEN  { 3168 };
inline constexpr std::size_t KEM_CIPHERTEXT_LEN  { 1568 };
inline constexpr std::size_t KEM_SHARED_SEC_LEN  { 32   };
inline constexpr std::size_t SESSION_KEY_LEN     { 32   };

// -------------------------------------------------------------------------
// Handshake message types
// -------------------------------------------------------------------------

//Defines what type of message each byte is associated with
enum class MsgType : uint8_t {
    PubKey     = 0x01,   ///< Server → Client: encapsulation public key
    Ciphertext = 0x02,   ///< Client → Server: KEM ciphertext
    Finished   = 0x03,   ///< Both directions: handshake complete
    Error      = 0xFF
};

// Wire header — packed, big-endian length
#pragma pack(push, 1) //Pragma is important, stops the compiler from padding this, or the bytes sent from client to server won't match
struct MsgHeader {
    uint8_t  type;    ///< MsgType byte
    uint32_t length;  ///< Payload length in network byte order
};
#pragma pack(pop) //This then tells the compiler to continue padding as it normally does, we just didn't want to pad the messsage header

//Compiler time check, if the msgheader is any different than 5 bytes, if it is, the build will fail.
//Will only happen on the off chance of random quirks from the compiler
static_assert(sizeof(MsgHeader) == 5, "MsgHeader must be exactly 5 bytes");

// -------------------------------------------------------------------------
// Exceptions
// -------------------------------------------------------------------------

/// Base exception for all KEM handshake errors
struct KemError : std::runtime_error {
    explicit KemError(std::string_view msg) : std::runtime_error(std::string(msg)) {}
};

struct WinsockError : KemError {
    int code;
    explicit WinsockError(std::string_view msg, int wsa_code = 0)
        : KemError(std::string(msg) + " (WSA " + std::to_string(wsa_code) + ")")
        , code(wsa_code) {}
};

struct OqsError : KemError {
    explicit OqsError(std::string_view msg) : KemError(msg) {}
};

// -------------------------------------------------------------------------
// RAII: Winsock lifetime guard
// -------------------------------------------------------------------------

/// Calls WSAStartup on construction, WSACleanup on destruction.
/// Declare exactly once in main() before any socket operations.
class WinsockGuard {
public:
    WinsockGuard() {
        WSADATA wsa{};
        if (int rc = ::WSAStartup(MAKEWORD(2, 2), &wsa); rc != 0)
            throw WinsockError("WSAStartup failed", rc);
    }
    ~WinsockGuard() { ::WSACleanup(); }

    WinsockGuard(const WinsockGuard&)            = delete;
    WinsockGuard& operator=(const WinsockGuard&) = delete;
};

// -------------------------------------------------------------------------
// RAII: Socket wrapper
// -------------------------------------------------------------------------

/// Thin RAII wrapper over a Winsock SOCKET.
class Socket {
public:
    Socket() = default;

    explicit Socket(SOCKET s) : sock_(s) {}

    Socket(int family, int type, int proto)
        : sock_(::socket(family, type, proto))
    {
        if (sock_ == INVALID_SOCKET)
            throw WinsockError("socket() failed", ::WSAGetLastError());
    }

    ~Socket() { close(); }

    // Move-only
    Socket(Socket&& o) noexcept : sock_(o.release()) {}
    Socket& operator=(Socket&& o) noexcept {
        if (this != &o) { close(); sock_ = o.release(); }
        return *this;
    }
    Socket(const Socket&)            = delete;
    Socket& operator=(const Socket&) = delete;

    [[nodiscard]] SOCKET get()     const noexcept { return sock_; }
    [[nodiscard]] bool   valid()   const noexcept { return sock_ != INVALID_SOCKET; }
    explicit operator bool()       const noexcept { return valid(); }

    SOCKET release() noexcept {
        SOCKET tmp = sock_;
        sock_ = INVALID_SOCKET;
        return tmp;
    }

    void close() noexcept {
        if (valid()) { ::closesocket(sock_); sock_ = INVALID_SOCKET; }
    }

private:
    SOCKET sock_ { INVALID_SOCKET };
};

// -------------------------------------------------------------------------
// RAII: KEM context (key material + liboqs handle)
// -------------------------------------------------------------------------

/// Owns all key material for one ML-KEM-512 exchange.
/// Secret buffers are securely zeroed in the destructor.
class KemContext {
public:
    using PublicKey    = std::array<uint8_t, KEM_PUBLIC_KEY_LEN>;
    using SecretKey    = std::array<uint8_t, KEM_SECRET_KEY_LEN>;
    using Ciphertext   = std::array<uint8_t, KEM_CIPHERTEXT_LEN>;
    using SharedSecret = std::array<uint8_t, KEM_SHARED_SEC_LEN>;
    using SessionKey   = std::array<uint8_t, SESSION_KEY_LEN>;

    /// Construct and initialise the liboqs KEM handle.
    /// Throws OqsError if ML-KEM-512 is unavailable or size constants mismatch.
    KemContext();

    ~KemContext();

    // Non-copyable, movable
    KemContext(const KemContext&)            = delete;
    KemContext& operator=(const KemContext&) = delete;
    KemContext(KemContext&&)                 = default;
    KemContext& operator=(KemContext&&)      = default;

    // ------------------------------------------------------------------
    // KEM operations (throw OqsError on failure)
    // ------------------------------------------------------------------

    /// Generate a fresh ephemeral key pair (server side).
    void generateKeypair();

    /// Encapsulate against public_key; fills ciphertext + sharedSecret (client side).
    void encapsulate();

    /// Decapsulate ciphertext with secretKey; fills sharedSecret (server side).
    void decapsulate();

    /// Derive session_key from sharedSecret via HKDF-SHA256.
    /// @param salt  Optional random salt (pass empty span for none).
    /// @param info  Application-specific label.
    void deriveSessionKey(std::span<const uint8_t> salt,
                          std::string_view          info = HKDF_INFO);

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    [[nodiscard]] PublicKey&          publicKey()     noexcept { return publicKey_; }
    [[nodiscard]] const PublicKey&    publicKey()     const noexcept { return publicKey_; }
    [[nodiscard]] Ciphertext&         ciphertext()    noexcept { return ciphertext_; }
    [[nodiscard]] const Ciphertext&   ciphertext()    const noexcept { return ciphertext_; }
    [[nodiscard]] const SharedSecret& sharedSecret()  const noexcept { return sharedSecret_; }
    [[nodiscard]] const SessionKey&   sessionKey()    const noexcept { return sessionKey_; }
    [[nodiscard]] bool                complete()      const noexcept { return complete_; }

    void markComplete() noexcept { complete_ = true; }

private:
    OQS_KEM*     kem_         { nullptr };

    PublicKey    publicKey_   {};
    SecretKey    secretKey_   {};
    Ciphertext   ciphertext_  {};
    SharedSecret sharedSecret_{};
    SessionKey   sessionKey_  {};

    bool         complete_    { false };
};

// -------------------------------------------------------------------------
// Framing helpers (declared here, defined in kem_utils.cpp)
// -------------------------------------------------------------------------

/// Send a framed message over a blocking socket.
/// Throws WinsockError on failure.
void kemSendMsg(const Socket& sock,
                MsgType       type,
                std::span<const uint8_t> payload);

/// Overload for zero-payload messages (e.g. MSG_FINISHED).
inline void kemSendMsg(const Socket& sock, MsgType type) {
    kemSendMsg(sock, type, {});
}

/// Receive a framed message.  Returns {type, payload_bytes}.
/// Throws WinsockError or KemError on failure.
std::pair<MsgType, std::vector<uint8_t>>
kemRecvMsg(const Socket& sock, std::size_t max_payload = 4096);

// -------------------------------------------------------------------------
// Debug helper
// -------------------------------------------------------------------------

inline void printHex(std::string_view label, std::span<const uint8_t> buf)
{
    std::cout << label << " (" << buf.size() << " bytes):\n  ";
    for (std::size_t i = 0; i < buf.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(buf[i]);
        if ((i + 1) % 32 == 0) std::cout << "\n  ";
    }
    std::cout << std::dec << '\n';
}
