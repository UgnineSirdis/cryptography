#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <memory>
#include <vector>

#include <openssl_wrapper/error.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

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

std::string GetLastOpenSslError() {
    TBioPtr bio(BIO_new(BIO_s_mem()));
    ERR_print_errors(bio.get());
    char* buf;
    size_t len = BIO_get_mem_data(bio.get(), &buf);
    std::string ret(buf, len);
    return ret;
}

struct TOpenSslLastError : public TOpenSslError {
    TOpenSslLastError(int errorCode, const char* action = nullptr)
        : TOpenSslError(GetErrorText(errorCode, action))
    {}

    static std::string GetErrorText(int errorCode, const char* action) {
        std::stringstream result;
        if (action) {
            result << action << ". ";
        }
        result << "Code " << errorCode << ": " << GetLastOpenSslError();
        return result.str();
    }
};

void OpensslCheckErrorAndThrow(int callResult, const char* action) {
    if (callResult <= 0) {
        throw TOpenSslLastError(callResult, action);
    }
}

struct TRandomGeneratedBytes {
    TRandomGeneratedBytes(size_t size)
        : Size(size)
    {
        Value.resize(Size);
        OpensslCheckErrorAndThrow(RAND_bytes(&Value[0], Size), "RAND_bytes");
    }

    TRandomGeneratedBytes(const TRandomGeneratedBytes&) = default;

    operator const unsigned char* () const {
        return &Value[0];
    }

    size_t Size;
    std::vector<unsigned char> Value;
};

// Stream for encryption or decryption
struct IEncryptionStream {
    virtual ~IEncryptionStream() = default;

    virtual void Update(unsigned char* data, size_t size) = 0;
    virtual void Finalize() = 0;
    virtual std::vector<unsigned char> GetTag() = 0;
    virtual size_t GetBytesWritten() const = 0;
};

class TAES256GCMEncryptionStream : public IEncryptionStream {
public:
    TAES256GCMEncryptionStream(const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, std::vector<unsigned char>* dst)
        : Key(key)
        , IV(iv)
        , Ctx(EVP_CIPHER_CTX_new())
        , Dst(dst)
    {
        if (!Ctx) {
            throw TOpenSslLastError(0);
        }

        OpensslCheckErrorAndThrow(EVP_EncryptInit_ex(Ctx.get(), EVP_aes_256_gcm(), nullptr, &Key[0], &IV[0]), "EVP_EncryptInit_ex");

        BlockSize = EVP_CIPHER_CTX_get_block_size(Ctx.get());
    }

    void Update(unsigned char* data, size_t size) override {
        int outLen = 0;
        OpensslCheckErrorAndThrow(EVP_EncryptUpdate(Ctx.get(), &(*Dst)[DstSize], &outLen, data, size), "EVP_EncryptUpdate");
        DstSize += size_t(outLen);
    }

    void Finalize() override {
        int outLen = 0;
        OpensslCheckErrorAndThrow(EVP_EncryptFinal_ex(Ctx.get(), &(*Dst)[DstSize], &outLen), "EVP_EncryptFinal_ex");
        DstSize += size_t(outLen);
    }

    std::vector<unsigned char> GetTag() override {
        std::vector<unsigned char> result;
        int len = EVP_CIPHER_CTX_get_tag_length(Ctx.get());
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
    const int EncryptStepSize = 1024 * 1024;
};

class TAES256GCMDecryptionStream : public IEncryptionStream {
public:
    TAES256GCMDecryptionStream(const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& tag, std::vector<unsigned char>* dst)
        : Key(key)
        , IV(iv)
        , Tag(tag)
        , Ctx(EVP_CIPHER_CTX_new())
        , Dst(dst)
    {
        if (!Ctx) {
            throw TOpenSslLastError(0);
        }

        OpensslCheckErrorAndThrow(EVP_DecryptInit_ex(Ctx.get(), EVP_aes_256_gcm(), nullptr, &Key[0], &IV[0]), "EVP_DecryptInit_ex");

        BlockSize = EVP_CIPHER_CTX_get_block_size(Ctx.get());
    }

    void Update(unsigned char* data, size_t size) override {
        int outLen = 0;
        OpensslCheckErrorAndThrow(EVP_DecryptUpdate(Ctx.get(), &(*Dst)[DstSize], &outLen, data, size), "EVP_DecryptUpdate");
        DstSize += size_t(outLen);
    }

    void Finalize() override {
        // Set expected tag
        OpensslCheckErrorAndThrow(EVP_CIPHER_CTX_ctrl(Ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, &Tag[0]), "EVP_CIPHER_CTX_ctrl");

        // Finalize
        int outLen = 0;
        OpensslCheckErrorAndThrow(EVP_DecryptFinal_ex(Ctx.get(), &(*Dst)[DstSize], &outLen), "EVP_DecryptFinal_ex");
        DstSize += size_t(outLen);
    }

    std::vector<unsigned char> GetTag() override {
        return Tag;
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
    const int EncryptStepSize = 1024 * 1024;
};

class TTimeMeasurer {
public:
    TTimeMeasurer(const std::string& name)
        : Name(name)
    {
        Start();
    }

    void Start() {
        Begin = std::chrono::system_clock::now();
    }

    void Stop(size_t bytes) {
        End = std::chrono::system_clock::now();

        auto d = GetDuration();
        std::cerr << std::endl << Name << ":" << std::endl;
        std::cerr << "Time (us): " << d.count() << std::endl;
        std::cerr << "Speed (MB/s): " << (double(bytes) / d.count()) << std::endl;
    }

    std::chrono::microseconds GetDuration() const {
        return std::chrono::duration_cast<std::chrono::microseconds>(End - Begin);
    }

private:
    std::string Name;
    std::chrono::time_point<std::chrono::system_clock> Begin;
    std::chrono::time_point<std::chrono::system_clock> End;
};

int main(int argc, const char** argv) {
    try {
        std::cerr << "cipher speed test program" << std::endl;

        TRandomGeneratedBytes key(32);
        TRandomGeneratedBytes iv(12);

        size_t gigabyte = 1024 * 1024 * 1024;
        TRandomGeneratedBytes data(gigabyte);
        std::vector<unsigned char> encryptedData(gigabyte + 1024);
        std::vector<unsigned char> decryptedData(gigabyte + 1024);

        // Encryption
        TTimeMeasurer encMeasurer("Encryption");
        TAES256GCMEncryptionStream enc(key.Value, iv.Value, &encryptedData);
        enc.Update(&data.Value[0], data.Value.size());
        enc.Finalize();
        auto tag = enc.GetTag();
        encMeasurer.Stop(gigabyte);
        std::cerr << "Bytes written: " << enc.GetBytesWritten() << std::endl;

        // Decryption
        TTimeMeasurer decMeasurer("Decryption");
        TAES256GCMDecryptionStream dec(key.Value, iv.Value, tag, &decryptedData);
        dec.Update(&encryptedData[0], enc.GetBytesWritten());
        dec.Finalize();
        decMeasurer.Stop(gigabyte);
        std::cerr << "Bytes written: " << dec.GetBytesWritten() << std::endl;

        // Compare
        bool compareProblem = false;
        if (dec.GetBytesWritten() != data.Value.size()) {
            std::cerr << "Decrypted size is not equal to source data size" << std::endl;
            compareProblem = true;
        }
        for (size_t i = 0; i < data.Value.size(); ++i) {
            if (data.Value[i] != decryptedData[i]) {
                std::cerr << "Decrypted data is not equal to source data. Byte " << i << std::endl;
                compareProblem = true;
            }
        }

        std::cerr << std::endl;
        if (compareProblem) {
            std::cerr << "Results don't match" << std::endl;
        } else {
            std::cerr << "Results match" << std::endl;
        }

        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }
}
