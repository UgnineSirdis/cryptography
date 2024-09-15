#pragma once
#include <memory>

#include <openssl_wrapper/error.h>

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>

namespace NOpenSsl {

class TOpenSslObjectFree {
public:
    TOpenSslObjectFree() = default;
    TOpenSslObjectFree(const TOpenSslObjectFree&) = default;
    TOpenSslObjectFree(TOpenSslObjectFree&&) = default;

    void operator()(EVP_CIPHER_CTX* ctx) const {
        EVP_CIPHER_CTX_free(ctx);
    }

    void operator()(BIO* bio) const {
        BIO_free(bio);
    }
};

using TCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, TOpenSslObjectFree>;
using TBioPtr = std::unique_ptr<BIO, TOpenSslObjectFree>;

inline void OpensslCheckErrorAndThrow(int callResult, const char* action) {
    if (callResult <= 0) {
        throw NOpenSsl::TOpenSslLastError(callResult, action);
    }
}

} // namespace NOpenSsl
