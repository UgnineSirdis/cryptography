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

    void Stop(size_t bytes, bool silent = false) {
        End = std::chrono::system_clock::now();

        if (!silent) {
            auto d = GetDuration();
            std::cerr << std::endl << Name << ":" << std::endl;
            std::cerr << "Time (us): " << d.count() << std::endl;
            std::cerr << "Speed (MB/s): " << (double(bytes) / d.count()) << std::endl;
        }
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

struct TCipherTime {
    TCipherTime(std::chrono::microseconds enc, std::chrono::microseconds dec, size_t bytes)
        : EncryptionTime(enc)
        , EncryptionSpeedMbs(double(bytes) / enc.count())
        , DecryptionTime(dec)
        , DecryptionSpeedMbs(double(bytes) / dec.count())
    {}

    std::chrono::microseconds EncryptionTime;
    double EncryptionSpeedMbs;
    std::chrono::microseconds DecryptionTime;
    double DecryptionSpeedMbs;
};

struct TCipherStats {
    std::string CipherName;
    std::vector<TCipherTime> Times;

    TCipherStats(const std::string& cipherName)
        : CipherName(cipherName)
    {}

    template <class T>
    T Min(T TCipherTime::* member) const {
        T t = Times[0].*member;
        for (const TCipherTime& time : Times) {
            T current = time.*member;
            if (current < t) {
                t = current;
            }
        }
        return t;
    }

    template <class T>
    T Max(T TCipherTime::* member) const {
        T t = Times[0].*member;
        for (const TCipherTime& time : Times) {
            T current = time.*member;
            if (current > t) {
                t = current;
            }
        }
        return t;
    }

    template <class T>
    T Sum(T TCipherTime::* member) const {
        T t = T();
        for (const TCipherTime& time : Times) {
            t += time.*member;
        }
        return t;
    }

    template <class T>
    T Average(T TCipherTime::* member) const {
        return Sum(member) / Times.size();
    }

    static double GetDouble(double d) {
        return d;
    }

    static double GetDouble(std::chrono::microseconds d) {
        return d.count();
    }

    template <class T>
    double StdDev(T TCipherTime::* member) const {
        auto avg = GetDouble(Average(member));
        double sum = 0.0;
        for (const TCipherTime& time : Times) {
            auto t = time.*member;
            double d = GetDouble(t) - avg;
            sum += d * d;
        }
        return sqrt(sum / Times.size());
    }

    static std::string GetMeasurementUnit(double) {
        return "MB/s";
    }

    static std::string GetMeasurementUnit(std::chrono::microseconds) {
        return "us";
    }

    static double OutputValue(double d) {
        return d;
    }

    static long OutputValue(std::chrono::microseconds d) {
        return d.count();
    }

    template <class T>
    void OutputStat(const std::string& name, T TCipherTime::* member) const {
        {
            auto min = Min(member);
            std::cerr << name << " min (" << GetMeasurementUnit(min) << "): " << OutputValue(min) << std::endl;
        }
        {
            auto max = Max(member);
            std::cerr << name << " max (" << GetMeasurementUnit(max) << "): " << OutputValue(max) << std::endl;
        }

        {
            auto avg = Average(member);
            std::cerr << name << " average (" << GetMeasurementUnit(avg) << "): " << OutputValue(avg) << std::endl;
        }

        {
            double stddev = StdDev(member);
            std::cerr << name << " stddev: " << stddev << std::endl;
        }

        std::cerr << std::endl;
    }

    void OutputStats() const {
        std::cerr << std::endl;
        std::cerr << "Cipher " << CipherName << " (" << Times.size() << " times)" << std::endl;
        OutputStat("Encryption time", &TCipherTime::EncryptionTime);
        OutputStat("Encryption speed", &TCipherTime::EncryptionSpeedMbs);
        OutputStat("Decryption time", &TCipherTime::DecryptionTime);
        OutputStat("Decryption speed", &TCipherTime::DecryptionSpeedMbs);
    }
};

TCipherTime TestCipherImpl(const TParams& opts, const std::string& cipherName, const std::vector<unsigned char>& data) {
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
        }

        return TCipherTime(encMeasurer.GetDuration(), decMeasurer.GetDuration(), dataSize);
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        throw;
    }
}

TCipherStats TestCipher(const TParams& opts, const std::string& cipherName, const std::vector<unsigned char>& data) {
    // First time for warm up:
    TestCipherImpl(opts, cipherName, data);

    size_t count = 10;
    TCipherStats stats(cipherName);
    for (size_t i = 0; i < count; ++i) {
        stats.Times.emplace_back(TestCipherImpl(opts, cipherName, data));
    }
    return stats;
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

        std::vector<TCipherStats> stats;
        for (const std::string& cipherName : opts.CipherNames) {
            stats.emplace_back(TestCipher(opts, cipherName, data));
        }

        for (const TCipherStats& stat : stats) {
            stat.OutputStats();
        }

        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }
}
