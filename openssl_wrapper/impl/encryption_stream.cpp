#include "helpers.h"

#include <openssl_wrapper/encryption_stream.h>

#include <openssl/evp.h>

namespace NOpenSsl {

class TAES256GCMEncryptionStream : public IEncryptionStream {
public:
    TAES256GCMEncryptionStream(std::vector<unsigned char>* dst)
        : Ctx(EVP_CIPHER_CTX_new())
        , Dst(dst)
    {
        if (!Ctx) {
            throw NOpenSsl::TOpenSslLastError(0);
        }

        // Init without parameters
        OpensslCheckErrorAndThrow(EVP_EncryptInit_ex(Ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr), "EVP_EncryptInit_ex");
    }

    void EnsureInit() {
        if (Inited) {
            return;
        }

        Inited = true;
        unsigned char* key = nullptr;
        unsigned char* iv = nullptr;
        if (!Key.empty()) {
            key = &Key[0];
        }
        if (!IV.empty()) {
            iv = &IV[0];
        }
        OpensslCheckErrorAndThrow(EVP_EncryptInit_ex(Ctx.get(), nullptr, nullptr, key, iv), "EVP_EncryptInit_ex");
    }

    size_t GetKeySize() const override {
        return EVP_CIPHER_CTX_key_length(Ctx.get());
    }

    void SetKey(const std::vector<unsigned char>& key) override {
        Key = key;
    }

    size_t GetIVSize() const override {
        return EVP_CIPHER_CTX_iv_length(Ctx.get());
    }

    void SetIV(const std::vector<unsigned char>& iv) override {
        IV = iv;
    }

    void Update(unsigned char* data, size_t size) override {
        EnsureInit();

        int outLen = 0;
        OpensslCheckErrorAndThrow(EVP_EncryptUpdate(Ctx.get(), &(*Dst)[DstSize], &outLen, data, size), "EVP_EncryptUpdate");
        DstSize += size_t(outLen);
    }

    void Finalize() override {
        EnsureInit();

        int outLen = 0;
        OpensslCheckErrorAndThrow(EVP_EncryptFinal_ex(Ctx.get(), &(*Dst)[DstSize], &outLen), "EVP_EncryptFinal_ex");
        DstSize += size_t(outLen);
    }

    std::vector<unsigned char> GetTag() override {
        std::vector<unsigned char> result;
#if __OPENSSL_VERSION__ == 1
        int len = 16;
#elif __OPENSSL_VERSION__ == 3
        int len = EVP_CIPHER_CTX_get_tag_length(Ctx.get());
#endif
        result.resize(len);
        OpensslCheckErrorAndThrow(EVP_CIPHER_CTX_ctrl(Ctx.get(), EVP_CTRL_GCM_GET_TAG, len, &result[0]), "EVP_CIPHER_CTX_ctrl");
        return result;
    }

    size_t GetBytesWritten() const override {
        return DstSize;
    }

    std::vector<unsigned char> Key;
    std::vector<unsigned char> IV;
    TCipherCtxPtr Ctx;
    int BlockSize = 0;
    std::vector<unsigned char>* Dst;
    size_t DstSize = 0;
    bool Inited = false;
};

class TAES256GCMDecryptionStream : public NOpenSsl::IDecryptionStream {
public:
    TAES256GCMDecryptionStream(std::vector<unsigned char>* dst)
        : Ctx(EVP_CIPHER_CTX_new())
        , Dst(dst)
    {
        if (!Ctx) {
            throw NOpenSsl::TOpenSslLastError(0);
        }

        OpensslCheckErrorAndThrow(EVP_DecryptInit_ex(Ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr), "EVP_DecryptInit_ex");

        BlockSize = EVP_CIPHER_CTX_block_size(Ctx.get());
    }

    void EnsureInit() {
        if (Inited) {
            return;
        }

        Inited = true;
        unsigned char* key = nullptr;
        unsigned char* iv = nullptr;
        if (!Key.empty()) {
            key = &Key[0];
        }
        if (!IV.empty()) {
            iv = &IV[0];
        }
        OpensslCheckErrorAndThrow(EVP_DecryptInit_ex(Ctx.get(), nullptr, nullptr, key, iv), "EVP_DecryptInit_ex");
    }

    size_t GetKeySize() const override {
        return EVP_CIPHER_CTX_key_length(Ctx.get());
    }

    void SetKey(const std::vector<unsigned char>& key) override {
        Key = key;
    }

    size_t GetIVSize() const override {
        return EVP_CIPHER_CTX_iv_length(Ctx.get());
    }

    void SetIV(const std::vector<unsigned char>& iv) override {
        IV = iv;
    }

    size_t GetTagSize() const override {
#if __OPENSSL_VERSION__ == 1
        return 16;
#elif __OPENSSL_VERSION__ == 3
        return EVP_CIPHER_CTX_get_tag_length(Ctx.get());
#endif
    }

    void SetTag(const std::vector<unsigned char>& tag) override {
        Tag = tag;
    }

    void Update(unsigned char* data, size_t size) override {
        EnsureInit();

        int outLen = 0;
        OpensslCheckErrorAndThrow(EVP_DecryptUpdate(Ctx.get(), &(*Dst)[DstSize], &outLen, data, size), "EVP_DecryptUpdate");
        DstSize += size_t(outLen);
    }

    void Finalize() override {
        EnsureInit();

        // Set expected tag
        OpensslCheckErrorAndThrow(EVP_CIPHER_CTX_ctrl(Ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, &Tag[0]), "EVP_CIPHER_CTX_ctrl");

        // Finalize
        int outLen = 0;
        OpensslCheckErrorAndThrow(EVP_DecryptFinal_ex(Ctx.get(), &(*Dst)[DstSize], &outLen), "EVP_DecryptFinal_ex");
        DstSize += size_t(outLen);
    }

    size_t GetBytesWritten() const override {
        return DstSize;
    }

    std::vector<unsigned char> Key;
    std::vector<unsigned char> IV;
    std::vector<unsigned char> Tag;
    TCipherCtxPtr Ctx;
    int BlockSize = 0;
    std::vector<unsigned char>* Dst;
    size_t DstSize = 0;
    bool Inited = false;
};

std::shared_ptr<IEncryptionStream> CreateEncryptionStream(std::vector<unsigned char>* dst) {
    return std::make_shared<TAES256GCMEncryptionStream>(dst);
}

std::shared_ptr<IDecryptionStream> CreateDecryptionStream(std::vector<unsigned char>* dst) {
    return std::make_shared<TAES256GCMDecryptionStream>(dst);
}

} // namespace NOpenSsl
