#include "helpers.h"

#include <openssl_wrapper/encryption_stream.h>

#include <openssl/evp.h>

#if __OPENSSL_VERSION__ == 3
#include <openssl/core_names.h>
#include <openssl/params.h>
#endif

#include <iostream>
#include <sstream>

namespace NOpenSsl {

const EVP_CIPHER* GetCipherByName(const std::string& cipherName) {
    const EVP_CIPHER* cipher = EVP_get_cipherbyname(cipherName.c_str());
    if (!cipher) {
        std::stringstream ss;
        ss << "Failed to get cipher \"" << cipherName << "\" by name";
        throw TOpenSslError(ss.str());
    }
    return cipher;
}

class TEvpEncryptionStream : public IEncryptionStream {
public:
    TEvpEncryptionStream(const std::string& cipherName, std::vector<unsigned char>* dst)
        : Ctx(EVP_CIPHER_CTX_new())
        , Dst(dst)
    {
        if (!Ctx) {
            throw TOpenSslLastError(0);
        }

        // Init without parameters
        OpensslCheckErrorAndThrow(EVP_EncryptInit_ex(Ctx.get(), GetCipherByName(cipherName), nullptr, nullptr, nullptr), "EVP_EncryptInit_ex");
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

#if __OPENSSL_VERSION__ == 1
    std::vector<unsigned char> GetTag() override {
        std::vector<unsigned char> result;
        int len = 16;
        result.resize(len);
        OpensslCheckErrorAndThrow(EVP_CIPHER_CTX_ctrl(Ctx.get(), EVP_CTRL_AEAD_GET_TAG, len, &result[0]), "EVP_CIPHER_CTX_ctrl(EVP_CTRL_AEAD_GET_TAG)");
        return result;
    }
#endif

#if __OPENSSL_VERSION__ == 3
    std::vector<unsigned char> GetTag() override {
        //unsigned int tagLen = EVP_CIPHER_CTX_get_tag_length(Ctx.get()); // does not work for chacha20-poly1305

        /*  // does not work for chacha20-poly1305
        OSSL_PARAM tagLengthParam[] = {
            OSSL_PARAM_uint(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &tagLen),
            OSSL_PARAM_END,
        };
        OpensslCheckErrorAndThrow(EVP_CIPHER_CTX_get_params(Ctx.get(), tagLengthParam), "EVP_CIPHER_CTX_get_params");
        std::cerr << "Tag len: " << tagLen << std::endl;
        */

        unsigned int tagLen = 16;

        std::vector<unsigned char> result;
        result.resize(tagLen);

        OSSL_PARAM tagParam[] = {
            OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, &result[0], result.size()),
            OSSL_PARAM_END,
        };
        OpensslCheckErrorAndThrow(EVP_CIPHER_CTX_get_params(Ctx.get(), tagParam), "EVP_CIPHER_CTX_get_params");

        return result;
    }
#endif

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

class TEvpDecryptionStream : public IDecryptionStream {
public:
    TEvpDecryptionStream(const std::string& cipherName, std::vector<unsigned char>* dst)
        : Ctx(EVP_CIPHER_CTX_new())
        , Dst(dst)
    {
        if (!Ctx) {
            throw TOpenSslLastError(0);
        }

        OpensslCheckErrorAndThrow(EVP_DecryptInit_ex(Ctx.get(), GetCipherByName(cipherName), nullptr, nullptr, nullptr), "EVP_DecryptInit_ex");

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
        EnsureInit();
        Tag = tag;

        // Set expected tag
        OpensslCheckErrorAndThrow(EVP_CIPHER_CTX_ctrl(Ctx.get(), EVP_CTRL_AEAD_SET_TAG, Tag.size(), &Tag[0]), "EVP_CIPHER_CTX_ctrl");
    }

    void Update(unsigned char* data, size_t size) override {
        EnsureInit();

        int outLen = 0;
        OpensslCheckErrorAndThrow(EVP_DecryptUpdate(Ctx.get(), &(*Dst)[DstSize], &outLen, data, size), "EVP_DecryptUpdate");
        DstSize += size_t(outLen);
    }

    void Finalize() override {
        EnsureInit();

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

std::shared_ptr<IEncryptionStream> CreateEncryptionStream(const std::string& cipherName, std::vector<unsigned char>* dst) {
    return std::make_shared<TEvpEncryptionStream>(cipherName, dst);
}

std::shared_ptr<IDecryptionStream> CreateDecryptionStream(const std::string& cipherName, std::vector<unsigned char>* dst) {
    return std::make_shared<TEvpDecryptionStream>(cipherName, dst);
}

} // namespace NOpenSsl
