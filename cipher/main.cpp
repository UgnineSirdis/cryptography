#include <chrono>
#include <iostream>
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

int main(int argc, const char** argv) {
    try {
        std::cerr << "cipher speed test program" << std::endl;

        size_t gigabyte = 1024 * 1024 * 1024;
        NOpenSsl::TRandomGeneratedBytes data(gigabyte);
        std::vector<unsigned char> encryptedData(gigabyte + 1024);
        std::vector<unsigned char> decryptedData(gigabyte + 1024);

        auto enc = NOpenSsl::CreateEncryptionStream(&encryptedData);
        auto dec = NOpenSsl::CreateDecryptionStream(&decryptedData);

        NOpenSsl::TRandomGeneratedBytes key(enc->GetKeySize());
        enc->SetKey(key.Value);
        dec->SetKey(key.Value);

        NOpenSsl::TRandomGeneratedBytes iv(enc->GetIVSize());
        enc->SetIV(iv.Value);
        dec->SetIV(iv.Value);

        // Encryption
        TTimeMeasurer encMeasurer("Encryption");
        enc->Update(&data.Value[0], data.Value.size());
        enc->Finalize();
        auto tag = enc->GetTag();
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
