/*
 * server.cpp
 * -----------------------------------------------------------------------
 * The server side of the ML-KEM-512 quantum-safe handshake.
 *
 * In benchmark mode (BENCH_RUNS > 1) the server accepts BENCH_RUNS
 * connections in a loop, times each full handshake with RDTSC, and
 * prints averaged clock-cycle statistics at the end.
 *
 * The client must be started after the server and must also be built
 * with the same BENCH_RUNS value so both sides loop the same number
 * of times.
 * -----------------------------------------------------------------------
 */

#include "kem_common.hpp"

#include <algorithm>  
#include <limits>     
#include <vector>     

static constexpr int BENCH_RUNS = 1000; //Number of times the benchmark will be ran

using namespace std;

// -----------------------------------------------------------------------
// RDTSC — reads the CPU hardware cycle counter.
// The compiler memory fences prevent instruction reordering across the
// measurement boundary, which would corrupt the timing reading.
// -----------------------------------------------------------------------
static inline uint64_t rdtsc()
{
    __asm__ volatile("" ::: "memory");
    uint64_t t = __builtin_ia32_rdtsc();
    __asm__ volatile("" ::: "memory");
    return t;
}

// -----------------------------------------------------------------------
// TcpListener — unchanged from original
// -----------------------------------------------------------------------
class TcpListener {
public:
    explicit TcpListener(string_view port)
    {
        addrinfo hints{};
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags    = AI_PASSIVE;

        addrinfo* res = nullptr;
        if (::getaddrinfo(nullptr, port.data(), &hints, &res) != 0)
            throw KemError("getaddrinfo failed, WSA code: "
                                 + to_string(::WSAGetLastError()));

        for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
            try {
                sock_ = Socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            } catch (...) { continue; }

            BOOL reuse = TRUE;
            ::setsockopt(sock_.get(), SOL_SOCKET, SO_REUSEADDR,
                         reinterpret_cast<const char*>(&reuse), sizeof(reuse));

            if (::bind(sock_.get(), p->ai_addr,
                       static_cast<int>(p->ai_addrlen)) == SOCKET_ERROR) {
                sock_.close();
                continue;
            }
            break;
        }
        ::freeaddrinfo(res);

        if (!sock_)
            throw KemError("Could not bind to port " + string(port));

        if (::listen(sock_.get(), BACKLOG) == SOCKET_ERROR)
            throw KemError("listen() failed, WSA code: "
                                 + to_string(::WSAGetLastError()));
    }

    [[nodiscard]] Socket accept() const
    {
        sockaddr_storage clientAddr{};
        int addrLen = sizeof(clientAddr);
        SOCKET clientSock = ::accept(sock_.get(),
                                     reinterpret_cast<sockaddr*>(&clientAddr),
                                     &addrLen);
        if (clientSock == INVALID_SOCKET)
            throw KemError("accept() failed, WSA code: "
                                 + to_string(::WSAGetLastError()));
        return Socket{ clientSock };
    }

private:
    Socket sock_;
};

KemContext serverHandshake(const Socket& clientSock, bool silent = false)
{
    KemContext ctx;

    // Step 1: Generate key pair
    if (!silent) cout << "[server] Generating ML-KEM-512 key pair...\n";
    ctx.generateKeypair();
    if (!silent) cout << "[server] Key pair generated.\n";

    // Step 2: Send public key
    if (!silent) cout << "[server] Sending public key to client...\n";
    kemSendMsg(clientSock,
               MsgType::PubKey,
               span<const uint8_t>{ ctx.publicKey() });
    if (!silent) cout << "[server] Public key sent.\n";

    // Step 3: Receive ciphertext
    if (!silent) cout << "[server] Waiting for ciphertext from client...\n";
    auto [msgType, payload] = kemRecvMsg(clientSock, KEM_CIPHERTEXT_LEN + 64);

    if (msgType != MsgType::Ciphertext || payload.size() != KEM_CIPHERTEXT_LEN)
        throw KemError("Expected a Ciphertext message but received something else");

    copy(payload.begin(), payload.end(), ctx.ciphertext().begin());
    if (!silent) cout << "[server] Received ciphertext (" << payload.size() << " bytes).\n";

    // Step 4: Decapsulate
    if (!silent) cout << "[server] Decapsulating ciphertext...\n";
    ctx.decapsulate();
    if (!silent) cout << "[server] Decapsulation successful.\n";
    if (!silent) printHex("[server] shared_secret", ctx.sharedSecret());

    // Step 5: Derive session key
    if (!silent) cout << "[server] Deriving session key...\n";
    ctx.deriveSessionKey({}, HKDF_INFO);
    if (!silent) printHex("[server] session_key", ctx.sessionKey());

    // Step 6: Send Finished
    kemSendMsg(clientSock, MsgType::Finished);
    if (!silent) cout << "[server] Sent Finished.\n";

    // Step 7: Receive Finished
    auto [finType, ignored] = kemRecvMsg(clientSock, 0);
    if (finType != MsgType::Finished)
        throw KemError("Expected Finished from client but received something else");
    if (!silent) cout << "[server] Received Finished from client.\n";

    ctx.markComplete();
    if (!silent) cout << "[server] Handshake complete. Session key is ready.\n";
    return ctx;
}

// -----------------------------------------------------------------------
// printBenchResults — prints a formatted summary table
// -----------------------------------------------------------------------
void printBenchResults(const vector<uint64_t>& timings)
{
    uint64_t total     = 0;
    uint64_t min_val   = numeric_limits<uint64_t>::max();
    uint64_t max_val   = 0;

    for (uint64_t t : timings) {
        total   += t;
        min_val  = min(min_val, t);
        max_val  = max(max_val, t);
    }

    uint64_t avg = total / timings.size();

    cout << "\n";
    cout << "┌──────────────────────────────────────────────────────┐\n";
    cout << "│  SERVER — Full Handshake Benchmark Results           │\n";
    cout << "│  Includes: keygen, send pubkey, recv CT,            │\n";
    cout << "│            decaps, HKDF, Finished exchange          │\n";
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

// -----------------------------------------------------------------------
// main
// -----------------------------------------------------------------------
int main()
{
    try {
        WinsockGuard winsock;

        TcpListener listener{ DEFAULT_PORT };
        cout << "[server] Listening on port " << DEFAULT_PORT << "...\n";

        if (BENCH_RUNS > 1) {
            cout << "[server] Benchmark mode: " << BENCH_RUNS
                      << " runs. Start client now.\n";
            cout << "[server] Run 1 will print verbose output to confirm "
                         "correctness.\n";
            cout << "[server] Remaining runs will be silent for accurate "
                         "timing.\n\n";
        }

        vector<uint64_t> timings;
        timings.reserve(BENCH_RUNS);

        for (int run = 0; run < BENCH_RUNS; ++run) {

            // Each run gets a fresh TCP connection from the client
            Socket clientSock = listener.accept();

            // Only print verbose output on the first run to confirm correctness
            bool silent = (run > 0);

            if (!silent)
                cout << "[server] Client connected (run "
                          << run + 1 << "/" << BENCH_RUNS << ").\n";
            else
                cout << "[server] Run " << run + 1
                          << "/" << BENCH_RUNS << "...\r" << flush;

            uint64_t start = rdtsc();
            KemContext ctx = serverHandshake(clientSock, silent);
            uint64_t end   = rdtsc();
            // ─────────────────────────────────────────────────────────────

            timings.push_back(end - start);
        }

        cout << "\n";
        printBenchResults(timings);

    } catch (const exception& ex) {
        cerr << "[server] Error: " << ex.what() << '\n';
        return 1;
    }

    return 0;
}