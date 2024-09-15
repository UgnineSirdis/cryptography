#pragma once
#include <vector>

namespace NOpenSsl {

struct TRandomGeneratedBytes {
    TRandomGeneratedBytes(size_t size);
    TRandomGeneratedBytes(const TRandomGeneratedBytes&) = default;

    operator const unsigned char* () const;

    size_t Size;
    std::vector<unsigned char> Value;
};

} // namespace NOpenSsl
