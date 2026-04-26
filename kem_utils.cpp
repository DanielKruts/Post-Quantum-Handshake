/*
 * kem_utils.cpp
 * Implementations for KemContext and framing helpers.
 *
 * 
 */

#include "kem_common.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <algorithm>
#include <cassert>
#include <cstring>
#include <vector>

// =========================================================================
// KemContext — constructor / destructor
// =========================================================================

KemContext::KemContext()
{
    kem_ = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem_)
        throw OqsError("OQS_KEM_new failed — is ML-KEM-512 enabled in your liboqs build?");

    // Runtime sanity-check: make sure our compile-time constants are correct
    if (kem_->length_public_key   != KEM_PUBLIC_KEY_LEN  ||
        kem_->length_secret_key   != KEM_SECRET_KEY_LEN  ||
        kem_->length_ciphertext   != KEM_CIPHERTEXT_LEN  ||
        kem_->length_shared_secret != KEM_SHARED_SEC_LEN)
    {
        OQS_KEM_free(kem_);
        throw OqsError("KEM size mismatch — update the *_LEN constants in kem_common.hpp");
    }
}

KemContext::~KemContext()
{
    // Securely zero all secret material before releasing memory
    OQS_MEM_cleanse(secretKey_.data(),    secretKey_.size());
    OQS_MEM_cleanse(sharedSecret_.data(), sharedSecret_.size());
    OQS_MEM_cleanse(sessionKey_.data(),   sessionKey_.size());

    if (kem_) OQS_KEM_free(kem_);
}

// =========================================================================
// KEM operations
// =========================================================================

void KemContext::generateKeypair()
{
    assert(kem_);
    OQS_STATUS rc = OQS_KEM_keypair(kem_, publicKey_.data(), secretKey_.data());
    if (rc != OQS_SUCCESS)
        throw OqsError("OQS_KEM_keypair failed");
}

void KemContext::encapsulate()
{
    assert(kem_);
    OQS_STATUS rc = OQS_KEM_encaps(kem_,
                                    ciphertext_.data(),
                                    sharedSecret_.data(),
                                    publicKey_.data());
    if (rc != OQS_SUCCESS)
        throw OqsError("OQS_KEM_encaps failed");
}

void KemContext::decapsulate()
{
    assert(kem_);
    OQS_STATUS rc = OQS_KEM_decaps(kem_,
                                    sharedSecret_.data(),
                                    ciphertext_.data(),
                                    secretKey_.data());
    if (rc != OQS_SUCCESS)
        throw OqsError("OQS_KEM_decaps failed");
}

// =========================================================================
// Session key derivation — HKDF-SHA256 via OpenSSL EVP_PKEY_CTX
// =========================================================================

void KemContext::deriveSessionKey(std::span<const uint8_t> salt,
                                   std::string_view          info)
{
    // Unique_ptr with custom deleter for EVP_PKEY_CTX
    auto ctx_del = [](EVP_PKEY_CTX* p) { EVP_PKEY_CTX_free(p); };
    std::unique_ptr<EVP_PKEY_CTX, decltype(ctx_del)>
        pctx { EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), ctx_del };

    if (!pctx)
        throw KemError("EVP_PKEY_CTX_new_id failed");

    auto chk = [](int rc, std::string_view step) {
        if (rc <= 0) throw KemError(std::string("HKDF step failed: ") + std::string(step));
    };

    chk(EVP_PKEY_derive_init(pctx.get()),                                 "derive_init");
    chk(EVP_PKEY_CTX_set_hkdf_md(pctx.get(), EVP_sha256()),              "set_md");
    chk(EVP_PKEY_CTX_set1_hkdf_key(pctx.get(),
            sharedSecret_.data(),
            static_cast<int>(sharedSecret_.size())),                      "set_key");

    if (!salt.empty()) {
        chk(EVP_PKEY_CTX_set1_hkdf_salt(pctx.get(),
                salt.data(), static_cast<int>(salt.size())),              "set_salt");
    }

    if (!info.empty()) {
        chk(EVP_PKEY_CTX_add1_hkdf_info(pctx.get(),
                reinterpret_cast<const unsigned char*>(info.data()),
                static_cast<int>(info.size())),                           "set_info");
    }

    std::size_t keylen = SESSION_KEY_LEN;
    chk(EVP_PKEY_derive(pctx.get(), sessionKey_.data(), &keylen),        "derive");

    if (keylen != SESSION_KEY_LEN)
        throw KemError("HKDF produced wrong key length");
}

// =========================================================================
// Internal framing helpers
// =========================================================================

namespace {

/// Send every byte in [buf, buf+len) — handles partial writes.
void sendAll(const Socket& sock, const uint8_t* buf, int len)
{
    int sent = 0;
    while (sent < len) {
        int n = ::send(sock.get(),
                       reinterpret_cast<const char*>(buf + sent),
                       len - sent, 0);
        if (n == SOCKET_ERROR)
            throw WinsockError("send() failed", ::WSAGetLastError());
        sent += n;
    }
}

/// Receive exactly len bytes — handles partial reads.
void recvAll(const Socket& sock, uint8_t* buf, int len)
{
    int got = 0;
    while (got < len) {
        int n = ::recv(sock.get(),
                       reinterpret_cast<char*>(buf + got),
                       len - got, 0);
        if (n == 0)
            throw WinsockError("Connection closed by peer");
        if (n == SOCKET_ERROR)
            throw WinsockError("recv() failed", ::WSAGetLastError());
        got += n;
    }
}

}

// =========================================================================
// Public framing API
// =========================================================================

void kemSendMsg(const Socket& sock,
                MsgType       type,
                std::span<const uint8_t> payload)
{
    MsgHeader hdr{};
    hdr.type   = static_cast<uint8_t>(type);
    hdr.length = ::htonl(static_cast<uint32_t>(payload.size()));

    sendAll(sock, reinterpret_cast<const uint8_t*>(&hdr), sizeof(hdr));
    if (!payload.empty())
        sendAll(sock, payload.data(), static_cast<int>(payload.size()));
}

std::pair<MsgType, std::vector<uint8_t>>
kemRecvMsg(const Socket& sock, std::size_t max_payload)
{
    MsgHeader hdr{};
    recvAll(sock, reinterpret_cast<uint8_t*>(&hdr), sizeof(hdr));

    const uint32_t plen = ::ntohl(hdr.length);
    if (plen > max_payload)
        throw KemError("Incoming payload " + std::to_string(plen) +
                       " exceeds max " + std::to_string(max_payload));

    std::vector<uint8_t> payload(plen);
    if (plen > 0)
        recvAll(sock, payload.data(), static_cast<int>(plen));

    return { static_cast<MsgType>(hdr.type), std::move(payload) };
}
