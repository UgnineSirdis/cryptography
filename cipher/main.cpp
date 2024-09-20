#include <chrono>
#include <cstddef>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl_wrapper/encryption_stream.h>
#include <openssl_wrapper/error.h>
#include <openssl_wrapper/random.h>

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

struct TParams {
    TParams(int argc, const char** argv) {
        if (argc >= 2) {
            CipherName = argv[1];
        }

        std::cerr << "CipherName: \"" << CipherName << "\"" << std::endl;
    }

    std::string CipherName = "AES-128-GCM";
};

int main(int argc, const char** argv) {
    std::cerr << "Cipher speed test program" << std::endl;
    try {
        TParams opts(argc, argv);
        size_t gigabyte = 1024 * 1024 * 1024;
        TTimeMeasurer genMeasurer("Data generation");
        NOpenSsl::TRandomGeneratedBytes data(gigabyte);
        genMeasurer.Stop(gigabyte);
        std::vector<unsigned char> encryptedData(gigabyte + 1024);
        std::vector<unsigned char> decryptedData(gigabyte + 1024);

        auto enc = NOpenSsl::CreateEncryptionStream(opts.CipherName, &encryptedData);
        auto dec = NOpenSsl::CreateDecryptionStream(opts.CipherName, &decryptedData);

        NOpenSsl::TRandomGeneratedBytes key(enc->GetKeySize());
        enc->SetKey(key.Value);
        dec->SetKey(key.Value);

        NOpenSsl::TRandomGeneratedBytes iv(enc->GetIVSize());
        enc->SetIV(iv.Value);
        dec->SetIV(iv.Value);

        std::cerr << std::endl;
        std::cerr << "Key length: " << key.Size << std::endl;
        std::cerr << "IV length: " << iv.Size << std::endl;

        // Encryption
        TTimeMeasurer encMeasurer("Encryption");
        enc->Update(&data.Value[0], data.Value.size());
        enc->Finalize();
        auto tag = enc->GetTag();
        std::cerr << "Tag length: " << tag.size() << std::endl;
        encMeasurer.Stop(gigabyte);
        std::cerr << "Bytes written: " << enc->GetBytesWritten() << std::endl;

        // Decryption
        TTimeMeasurer decMeasurer("Decryption");
        dec->Update(&encryptedData[0], enc->GetBytesWritten());
        dec->SetTag(tag);
        dec->Finalize();
        decMeasurer.Stop(gigabyte);
        std::cerr << "Bytes written: " << dec->GetBytesWritten() << std::endl;

        // Compare
        bool compareProblem = false;
        if (dec->GetBytesWritten() != data.Value.size()) {
            throw std::runtime_error("Decrypted size is not equal to source data size");
        }

        // Compare uint64_t pieces
        const size_t countInts = data.Value.size() / sizeof(uint64_t);
        const uint64_t* srcValueUint64 = reinterpret_cast<uint64_t*>(&data.Value[0]);
        const uint64_t* decValueUint64 = reinterpret_cast<uint64_t*>(&decryptedData[0]);
        for (size_t i = 0; i < countInts; ++i) {
            if (srcValueUint64[i] != decValueUint64[i]) {
                std::cerr << "Decrypted data is not equal to source data. ui64 " << i << std::endl;
                compareProblem = true;
            }
        }

        for (size_t i = 0; i < data.Value.size() % sizeof(uint64_t); ++i) {
            size_t index = i + countInts * sizeof(uint64_t);
            if (data.Value[index] != decryptedData[index]) {
                std::cerr << "Decrypted data is not equal to source data. byte " << index << std::endl;
                compareProblem = true;
            }
        }

        std::cerr << std::endl;
        if (compareProblem) {
            throw std::runtime_error("Results don't match");
        } else {
            std::cerr << "Results match" << std::endl;
        }

        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }
}
