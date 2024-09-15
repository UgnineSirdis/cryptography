#pragma once
#include <stdexcept>

struct TOpenSslError : public std::runtime_error {
    using std::runtime_error::runtime_error;
};
