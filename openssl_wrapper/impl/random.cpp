#include "helpers.h"

#include <openssl_wrapper/random.h>

#include <openssl/rand.h>

namespace NOpenSsl {

TRandomGeneratedBytes::TRandomGeneratedBytes(size_t size)
    : Size(size)
{
    Value.resize(Size);
    OpensslCheckErrorAndThrow(RAND_bytes(&Value[0], Size), "RAND_bytes");
}

TRandomGeneratedBytes::operator const unsigned char* () const {
    return &Value[0];
}

} // namespace NOpenSsl
