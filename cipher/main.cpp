#include <chrono>
#include <cstddef>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <random>

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
            for (int i = 1; i < argc;) {
                i = ProcessOption(i, argc, argv);
                if (DisplayHelpAndExit) {
                    break;
                }
            }
        } else {
            ApplyDefaultOptions();
        }
    }

    int ProcessOption(int i, int argc, const char** argv) {
        std::string opt(argv[i]);
        if (opt.size() > 2 && opt[0] == '-') {
            if (opt == "--no-authenticated-encryption") {
                AuthenticatedEncryption = false;
                return ++i;
            } else if (opt == "-h" || opt == "--help") {
                DisplayHelpAndExit = true;
                return ++i;
            } else {
                std::stringstream ss;
                ss << "Failed to parse option \"" << opt << "\"";
                throw std::runtime_error(ss.str());
            }
        } else {
            CipherNames.push_back(opt);
            return ++i;
        }
    }

    void ApplyDefaultOptions() {
        CipherNames.push_back("AES-128-GCM");
        CipherNames.push_back("AES-256-GCM");
        CipherNames.push_back("ChaCha20-Poly1305");
    }

    void ShowHelp() {
        std::cerr << "cipher <cipher-1> <cipher-2> ..." << std::endl;
        std::cerr << std::endl;
        std::cerr << "Options:" << std::endl;
        std::cerr << "--no-authenticated-encryption: don't set and verify tag (for nonauthenticated encryption ciphers)" << std::endl;
    }

    std::vector<std::string> CipherNames;
    bool AuthenticatedEncryption = true;
    bool DisplayHelpAndExit = false;
};

void GenerateRandomData(std::vector<unsigned char>& data, size_t size) {
    NOpenSsl::TRandomGeneratedBytes r(size);
    data.swap(r.Value);
}

void TestCipher(const TParams& opts, const std::string& cipherName, const std::vector<unsigned char>& data) {
    try {
        std::cerr << std::endl << "CipherName: \"" << cipherName << "\"" << std::endl;

        const size_t dataSize = data.size();
        std::vector<unsigned char> encryptedData(dataSize + 1024);
        std::vector<unsigned char> decryptedData(dataSize + 1024);

        auto enc = NOpenSsl::CreateEncryptionStream(cipherName, &encryptedData);
        auto dec = NOpenSsl::CreateDecryptionStream(cipherName, &decryptedData);

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
        enc->Update(&data[0], data.size());
        enc->Finalize();
        std::vector<unsigned char> tag;
        if (opts.AuthenticatedEncryption) {
            tag = enc->GetTag();
            std::cerr << "Tag length: " << tag.size() << std::endl;
        }
        encMeasurer.Stop(dataSize);
        std::cerr << "Bytes written: " << enc->GetBytesWritten() << std::endl;

        // Decryption
        TTimeMeasurer decMeasurer("Decryption");
        dec->Update(&encryptedData[0], enc->GetBytesWritten());
        if (opts.AuthenticatedEncryption) {
            dec->SetTag(tag);
        }
        dec->Finalize();
        decMeasurer.Stop(dataSize);
        std::cerr << "Bytes written: " << dec->GetBytesWritten() << std::endl;

        // Compare
        bool compareProblem = false;
        if (dec->GetBytesWritten() != data.size()) {
            throw std::runtime_error("Decrypted size is not equal to source data size");
        }

        // Compare uint64_t pieces
        const size_t countInts = data.size() / sizeof(uint64_t);
        const uint64_t* srcValueUint64 = reinterpret_cast<const uint64_t*>(&data[0]);
        const uint64_t* decValueUint64 = reinterpret_cast<const uint64_t*>(&decryptedData[0]);
        for (size_t i = 0; i < countInts; ++i) {
            if (srcValueUint64[i] != decValueUint64[i]) {
                std::cerr << "Decrypted data is not equal to source data. ui64 " << i << std::endl;
                compareProblem = true;
            }
        }

        for (size_t i = 0; i < data.size() % sizeof(uint64_t); ++i) {
            size_t index = i + countInts * sizeof(uint64_t);
            if (data[index] != decryptedData[index]) {
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
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }
}

int main(int argc, const char** argv) {
    std::cerr << "Cipher speed test program" << std::endl;
    try {
        TParams opts(argc, argv);
        if (opts.DisplayHelpAndExit) {
            opts.ShowHelp();
            return 0;
        }
        size_t gigabyte = 1024 * 1024 * 1024;
        std::vector<unsigned char> data;
        TTimeMeasurer genMeasurer("Data generation");
        GenerateRandomData(data, gigabyte);
        genMeasurer.Stop(gigabyte);

        for (const std::string& cipherName : opts.CipherNames) {
            TestCipher(opts, cipherName, data);
        }

        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }
}
