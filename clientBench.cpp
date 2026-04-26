/*
 * client.cpp
 * -----------------------------------------------------------------------
 * The client side of the ML-KEM-512 quantum-safe handshake.
 *
 * In benchmark mode (BENCH_RUNS > 1) the client reconnects BENCH_RUNS
 * times, times each full handshake with RDTSC, and prints averaged
 * clock-cycle statistics at the end.
 *
 * The server must be started first and built with the same BENCH_RUNS
 * value so both sides loop the same number of times.
 * -----------------------------------------------------------------------
 */

#include "kem_common.hpp"

#include <algorithm>  
#include <limits>     
#include <vector>     

static constexpr int BENCH_RUNS = 1000; // must match server.cpp

using namespace std;

inline constexpr string_view SERVER_HOST { "127.0.0.1" };

// -----------------------------------------------------------------------
// RDTSC — reads the CPU hardware cycle counter.
// -----------------------------------------------------------------------
static inline uint64_t rdtsc()
{
    __asm__ volatile("" ::: "memory");
    uint64_t t = __builtin_ia32_rdtsc();
    __asm__ volatile("" ::: "memory");
    return t;
}

// -----------------------------------------------------------------------
// TcpClient — unchanged from original.
// In benchmark mode we construct a fresh TcpClient each loop iteration
// so each run uses a clean TCP connection, matching what the server does.
// -----------------------------------------------------------------------
class TcpClient {
public:
    TcpClient(string_view host, string_view port)
    {
        addrinfo hints{};
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        addrinfo* res = nullptr;
        if (::getaddrinfo(host.data(), port.data(), &hints, &res) != 0)
            throw KemError("getaddrinfo failed, WSA code: "
                                 + to_string(::WSAGetLastError()));

        for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
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
            throw KemError("Could not connect to "
                                 + string(host) + ":" + string(port));
    }

    [[nodiscard]] const Socket& socket() const noexcept { return sock_; }

private:
    Socket sock_;
};

KemContext clientHandshake(const Socket& sock, bool silent = false)
{
    KemContext ctx;

    // Step 1: Receive server's public key
    if (!silent) cout << "[client] Waiting for server's public key...\n";
    auto [msgType, payload] = kemRecvMsg(sock, KEM_PUBLIC_KEY_LEN + 64);

    if (msgType != MsgType::PubKey || payload.size() != KEM_PUBLIC_KEY_LEN)
        throw KemError("Expected a PubKey message but received something else");

    copy(payload.begin(), payload.end(), ctx.publicKey().begin());
    if (!silent) cout << "[client] Received public key (" << payload.size() << " bytes).\n";

    // Step 2: Encapsulate
    if (!silent) cout << "[client] Encapsulating against server's public key...\n";
    ctx.encapsulate();
    if (!silent) cout << "[client] Encapsulation successful.\n";
    if (!silent) printHex("[client] shared_secret", ctx.sharedSecret());

    // Step 3: Send ciphertext
    if (!silent) cout << "[client] Sending ciphertext to server...\n";
    kemSendMsg(sock,
               MsgType::Ciphertext,
               span<const uint8_t>{ ctx.ciphertext() });
    if (!silent) cout << "[client] Ciphertext sent (" << KEM_CIPHERTEXT_LEN << " bytes).\n";

    // Step 4: Derive session key
    if (!silent) cout << "[client] Deriving session key...\n";
    ctx.deriveSessionKey({}, HKDF_INFO);
    if (!silent) printHex("[client] session_key", ctx.sessionKey());

    // Step 5: Receive Finished
    auto [finType, ignored] = kemRecvMsg(sock, 0);
    if (finType != MsgType::Finished)
        throw KemError("Expected Finished from server but received something else");
    if (!silent) cout << "[client] Received Finished from server.\n";

    // Step 6: Send Finished
    kemSendMsg(sock, MsgType::Finished);
    if (!silent) cout << "[client] Sent Finished.\n";

    ctx.markComplete();
    if (!silent) cout << "[client] Handshake complete. Session key is ready.\n";
    return ctx;
}

void printBenchResults(const vector<uint64_t>& timings)
{
    uint64_t total   = 0;
    uint64_t min_val = numeric_limits<uint64_t>::max();
    uint64_t max_val = 0;

    for (uint64_t t : timings) {
        total   += t;
        min_val  = min(min_val, t);
        max_val  = max(max_val, t);
    }

    uint64_t avg = total / timings.size();

    cout << "\n";
    cout << "┌──────────────────────────────────────────────────────┐\n";
    cout << "│  CLIENT — Full Handshake Benchmark Results           │\n";
    cout << "│  Includes: recv pubkey, encaps, send CT,            │\n";
    cout << "│            HKDF, Finished exchange                  │\n";
    cout << "├──────────────────────┬───────────────────────────────┤\n";
    cout << "│  Runs completed      │ " << left  << setw(29)
              << timings.size()                            << " │\n";
    cout << "│  Average (K cycles)  │ " << left  << setw(29)
              << fixed << setprecision(1) << avg / 1000.0  << " │\n";
    cout << "│  Min     (K cycles)  │ " << left  << setw(29)
              << min_val / 1000.0                         << " │\n";
    cout << "│  Max     (K cycles)  │ " << left  << setw(29)
              << max_val / 1000.0                         << " │\n";
    cout << "└──────────────────────┴───────────────────────────────┘\n";
    cout << "\nNOTE: These timings include real TCP socket I/O over\n";
    cout << "      loopback — not just the KEM crypto operations.\n";
}

int main()
{
    try {
        WinsockGuard winsock;

        if (BENCH_RUNS > 1) {
            cout << "[client] Benchmark mode: " << BENCH_RUNS
                      << " runs.\n";
            cout << "[client] Run 1 will print verbose output to confirm "
                         "correctness.\n";
            cout << "[client] Remaining runs will be silent for accurate "
                         "timing.\n\n";
        }

        vector<uint64_t> timings;
        timings.reserve(BENCH_RUNS);

        for (int run = 0; run < BENCH_RUNS; ++run) {

            TcpClient conn{ SERVER_HOST, DEFAULT_PORT };

            bool silent = (run > 0);

            if (!silent)
                cout << "[client] Connected (run "
                          << run + 1 << "/" << BENCH_RUNS << ").\n";
            else
                cout << "[client] Run " << run + 1
                          << "/" << BENCH_RUNS << "...\r" << flush;

            uint64_t start = rdtsc();
            KemContext ctx = clientHandshake(conn.socket(), silent);
            uint64_t end   = rdtsc();
            // ─────────────────────────────────────────────────────────────

            timings.push_back(end - start);

            if (run < BENCH_RUNS - 1)
                Sleep(10);
        }

        cout << "\n";
        printBenchResults(timings);

    } catch (const exception& ex) {
        cerr << "[client] Error: " << ex.what() << '\n';
        return 1;
    }

    return 0;
}