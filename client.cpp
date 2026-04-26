/*
 * client.cpp
 * ML-KEM-512 quantum-safe handshake — CLIENT side.
 *
 * Handshake flow:
 *   1. Connect to server.
 *   2. Recv  MsgType::PubKey     ← server  (800 bytes)
 *   3. Encapsulate against server's public key.
 *   4. Send  MsgType::Ciphertext → server  (768 bytes)
 *   5. Derive session key (HKDF-SHA256).
 *   6. Exchange MsgType::Finished.
 */

#include "kem_common.hpp"

inline constexpr std::string_view SERVER_HOST { "127.0.0.1" };

// -------------------------------------------------------------------------
// TcpClient — RAII outgoing connection
// -------------------------------------------------------------------------

class TcpClient {
public:
    TcpClient(std::string_view host, std::string_view port)
    {
        addrinfo hints{};
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        addrinfo* res = nullptr;
        if (::getaddrinfo(host.data(), port.data(), &hints, &res) != 0)
            throw WinsockError("getaddrinfo failed", ::WSAGetLastError());

        for (addrinfo* p = res; p; p = p->ai_next) {
            try {
                sock_ = Socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            } catch (...) { continue; }

            if (::connect(sock_.get(), p->ai_addr,
                          static_cast<int>(p->ai_addrlen)) != SOCKET_ERROR)
                break;

            sock_.close();
        }
        ::freeaddrinfo(res);

        if (!sock_)
            throw WinsockError("Could not connect to "
                               + std::string(host) + ":" + std::string(port));
    }

    [[nodiscard]] const Socket& socket() const noexcept { return sock_; }

private:
    Socket sock_;
};

// -------------------------------------------------------------------------
// Handshake logic
// -------------------------------------------------------------------------

/// Performs the full client-side handshake.
/// Returns a KemContext with complete() == true and sessionKey() ready.
KemContext clientHandshake(const Socket& sock)
{
    KemContext ctx;

    // 1 — Receive server's public key
    std::cout << "[client] Waiting for server public key...\n";
    auto [recvType, payload] = kemRecvMsg(sock, KEM_PUBLIC_KEY_LEN + 64);

    if (recvType != MsgType::PubKey || payload.size() != KEM_PUBLIC_KEY_LEN)
        throw KemError("Expected PubKey message, got type="
                       + std::to_string(static_cast<int>(recvType))
                       + " len=" + std::to_string(payload.size()));

    std::copy(payload.begin(), payload.end(), ctx.publicKey().begin());
    std::cout << "[client] Received public key (" << payload.size() << " bytes).\n";

    // TODO: authenticate the server's public key here.
    // e.g. Verify OQS_SIG signature over publicKey() using a trusted
    //      ML-DSA verification key obtained out-of-band.

    // 2 — Encapsulate
    std::cout << "[client] Encapsulating...\n";
    ctx.encapsulate();
    std::cout << "[client] Encapsulation successful.\n";
    printHex("[client] shared_secret", ctx.sharedSecret());

    // 3 — Send ciphertext
    std::cout << "[client] Sending ciphertext ("
              << KEM_CIPHERTEXT_LEN << " bytes)...\n";
    kemSendMsg(sock, MsgType::Ciphertext,
               std::span<const uint8_t>{ ctx.ciphertext() });

    // 4 — Derive session key
    //
    // TODO: Replace the empty salt with concatenated client+server nonces,
    //       and replace HKDF_INFO with a transcript hash (as on the server).
    ctx.deriveSessionKey({}, HKDF_INFO);
    printHex("[client] session_key", ctx.sessionKey());

    // 5 — Receive FINISHED from server
    auto [finType, _] = kemRecvMsg(sock, 0);
    if (finType != MsgType::Finished)
        throw KemError("Expected Finished, got type="
                       + std::to_string(static_cast<int>(finType)));

    // 6 — Send FINISHED to server
    kemSendMsg(sock, MsgType::Finished);

    ctx.markComplete();
    std::cout << "[client] Handshake complete. Session key established.\n";
    return ctx;
}

// -------------------------------------------------------------------------
// Entry point
// -------------------------------------------------------------------------

int main()
{
    try {
        WinsockGuard winsock;   // WSAStartup / WSACleanup via RAII

        TcpClient conn{ SERVER_HOST, DEFAULT_PORT };
        std::cout << "[client] Connected to server.\n";

        KemContext ctx = clientHandshake(conn.socket());

        // ----------------------------------------------------------------
        // TODO: begin encrypted application data exchange here.
        // Use ctx.sessionKey() with AES-256-GCM.
        // ----------------------------------------------------------------
        std::cout << "[client] Ready for encrypted communication.\n";

    } catch (const std::exception& ex) {
        std::cerr << "[client] Fatal error: " << ex.what() << '\n';
        return 1;
    }
    return 0;
}