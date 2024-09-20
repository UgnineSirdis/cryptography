#pragma once
#include <memory>
#include <vector>

namespace NOpenSsl {

// Stream for encryption or decryption
struct IEncryptionStreamBase {
    virtual ~IEncryptionStreamBase() = default;

    // Set key
    virtual size_t GetKeySize() const = 0;
    virtual void SetKey(const std::vector<unsigned char>& key) = 0;

    // Set IV
    virtual size_t GetIVSize() const = 0;
    virtual void SetIV(const std::vector<unsigned char>& iv) = 0;

    // Encryption
    virtual void Update(unsigned char* data, size_t size) = 0;
    virtual void Finalize() = 0;

    // How many bytes encrypted/decrypted
    virtual size_t GetBytesWritten() const = 0;
};

struct IEncryptionStream : public IEncryptionStreamBase {
    // Get tag after encryption
    virtual std::vector<unsigned char> GetTag() = 0;
};

struct IDecryptionStream : public IEncryptionStreamBase {
    // Set tag to check
    // For decryption streams
    virtual size_t GetTagSize() const = 0;
    virtual void SetTag(const std::vector<unsigned char>& tag) = 0;
};

std::shared_ptr<IEncryptionStream> CreateEncryptionStream(const std::string& cipherName, std::vector<unsigned char>* dst);
std::shared_ptr<IDecryptionStream> CreateDecryptionStream(const std::string& cipherName, std::vector<unsigned char>* dst);

} // namespace NOpenSsl
