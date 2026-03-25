/*
 * server.cpp
 * ML-KEM-512 quantum-safe handshake — SERVER side.
 *
 * Handshake flow:
 *   1. Generate ML-KEM-512 ephemeral key pair.
 *   2. Accept TCP connection.
 *   3. Send  MsgType::PubKey     → client  (800 bytes)
 *   4. Recv  MsgType::Ciphertext ← client  (768 bytes)
 *   5. Decapsulate → shared secret.
 *   6. Derive session key (HKDF-SHA256).
 *   7. Exchange MsgType::Finished.
 *
 * TODO before production:
 *   - Sign the public key with a long-term ML-DSA key (authenticate server).
 *   - Exchange nonces; use them as HKDF salt.
 *   - Hash the full transcript; include digest in HKDF info.
 *   - Wrap application data with AES-256-GCM using the session key.
 *   - Accept multiple clients (thread-per-connection or async I/O).
 */

#include "kem_common.hpp"
#include <stdexcept>

// -------------------------------------------------------------------------
// TcpListener — RAII listen socket
// -------------------------------------------------------------------------

class TcpListener {
public:
    explicit TcpListener(std::string_view port)
    {
        addrinfo hints{};
        hints.ai_family   = AF_INET6;   // dual-stack; change to AF_INET for IPv4-only
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags    = AI_PASSIVE;

        addrinfo* res = nullptr;
        if (::getaddrinfo(nullptr, port.data(), &hints, &res) != 0)
            throw WinsockError("getaddrinfo failed", ::WSAGetLastError());

        for (addrinfo* p = res; p; p = p->ai_next) {
            try {
                sock_ = Socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            } catch (...) { continue; }

            // Dual-stack: allow IPv4 clients on the IPv6 socket
            DWORD v6only = 0;
            ::setsockopt(sock_.get(), IPPROTO_IPV6, IPV6_V6ONLY,
                         reinterpret_cast<const char*>(&v6only), sizeof(v6only));

            // Reuse address to avoid TIME_WAIT delays during development
            BOOL reuse = TRUE;
            ::setsockopt(sock_.get(), SOL_SOCKET, SO_REUSEADDR,
                         reinterpret_cast<const char*>(&reuse), sizeof(reuse));

            if (::bind(sock_.get(), p->ai_addr, static_cast<int>(p->ai_addrlen))
                    == SOCKET_ERROR) {
                sock_.close();
                continue;
            }
            break;
        }
        ::freeaddrinfo(res);

        if (!sock_)
            throw WinsockError("Could not bind to port " + std::string(port));

        if (::listen(sock_.get(), BACKLOG) == SOCKET_ERROR)
            throw WinsockError("listen() failed", ::WSAGetLastError());
    }

    /// Block until a client connects; returns the accepted Socket.
    [[nodiscard]] Socket accept() const
    {
        sockaddr_storage addr{};
        int addrlen = sizeof(addr);
        SOCKET client = ::accept(sock_.get(),
                                 reinterpret_cast<sockaddr*>(&addr),
                                 &addrlen);
        if (client == INVALID_SOCKET)
            throw WinsockError("accept() failed", ::WSAGetLastError());
        return Socket{ client };
    }

private:
    Socket sock_;
};

// -------------------------------------------------------------------------
// Handshake logic
// -------------------------------------------------------------------------

/// Performs the full server-side handshake.
/// Returns a KemContext with complete() == true and sessionKey() ready.
KemContext serverHandshake(const Socket& clientSock)
{
    KemContext ctx;

    // 1 — Generate ephemeral key pair
    std::cout << "[server] Generating ML-KEM-512 key pair...\n";
    ctx.generateKeypair();
    std::cout << "[server] Key pair generated.\n";

    // 2 — Send public key
    std::cout << "[server] Sending public key ("
              << KEM_PUBLIC_KEY_LEN << " bytes)...\n";
    kemSendMsg(clientSock, MsgType::PubKey,
               std::span<const uint8_t>{ ctx.publicKey() });

    // 3 — Receive ciphertext
    std::cout << "[server] Waiting for ciphertext...\n";
    auto [recvType, payload] = kemRecvMsg(clientSock, KEM_CIPHERTEXT_LEN + 64);

    if (recvType != MsgType::Ciphertext || payload.size() != KEM_CIPHERTEXT_LEN)
        throw KemError("Expected Ciphertext message, got type="
                       + std::to_string(static_cast<int>(recvType))
                       + " len=" + std::to_string(payload.size()));

    std::copy(payload.begin(), payload.end(), ctx.ciphertext().begin());
    std::cout << "[server] Received ciphertext (" << payload.size() << " bytes).\n";

    // 4 — Decapsulate
    std::cout << "[server] Decapsulating...\n";
    ctx.decapsulate();
    std::cout << "[server] Decapsulation successful.\n";
    printHex("[server] shared_secret", ctx.sharedSecret());

    // 5 — Derive session key
    //
    // TODO: Replace the empty salt with concatenated client+server nonces
    //       exchanged at the start of the handshake, and replace HKDF_INFO
    //       with a SHA-256 hash of the full handshake transcript.
    ctx.deriveSessionKey({}, HKDF_INFO);
    printHex("[server] session_key", ctx.sessionKey());

    // 6 — Send FINISHED
    kemSendMsg(clientSock, MsgType::Finished);

    // 7 — Receive FINISHED
    auto [finType, _] = kemRecvMsg(clientSock, 0);
    if (finType != MsgType::Finished)
        throw KemError("Expected Finished, got type="
                       + std::to_string(static_cast<int>(finType)));

    ctx.markComplete();
    std::cout << "[server] Handshake complete. Session key established.\n";
    return ctx;
}

// -------------------------------------------------------------------------
// Entry point
// -------------------------------------------------------------------------

int main()
{
    try {
        WinsockGuard winsock;   // WSAStartup / WSACleanup via RAII

        TcpListener listener{ DEFAULT_PORT };
        std::cout << "[server] Listening on port " << DEFAULT_PORT << "...\n";

        // Accept a single client.
        // TODO: for multiple clients, move the block below into a
        //       std::thread (or use async I/O) and loop here.
        Socket clientSock = listener.accept();
        std::cout << "[server] Client connected.\n";

        KemContext ctx = serverHandshake(clientSock);

        // ----------------------------------------------------------------
        // TODO: begin encrypted application data exchange here.
        // Use ctx.sessionKey() with AES-256-GCM
        // (OpenSSL EVP_aead_aes_256_gcm or EVP_EncryptInit_ex).
        // ----------------------------------------------------------------
        std::cout << "[server] Ready for encrypted communication.\n";

    } catch (const std::exception& ex) {
        std::cerr << "[server] Fatal error: " << ex.what() << '\n';
        return 1;
    }
    return 0;
}
