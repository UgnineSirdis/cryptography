#pragma once
#include <string>
#include <stdexcept>

namespace NOpenSsl {

std::string GetLastOpenSslError();

struct TOpenSslError : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct TOpenSslLastError : public NOpenSsl::TOpenSslError {
    TOpenSslLastError(int errorCode, const char* action = nullptr)
        : TOpenSslError(GetErrorText(errorCode, action))
    {}

    static std::string GetErrorText(int errorCode, const char* action);
};

} // namespace NOpenSsl
