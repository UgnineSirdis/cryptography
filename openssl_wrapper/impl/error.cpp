#include <string>
#include <sstream>

#include <openssl/err.h>

#include <openssl_wrapper/error.h>

#include "helpers.h"

namespace NOpenSsl {

std::string GetLastOpenSslError() {
    TBioPtr bio(BIO_new(BIO_s_mem()));
    ERR_print_errors(bio.get());
    char* buf;
    size_t len = BIO_get_mem_data(bio.get(), &buf);
    std::string ret(buf, len);
    return ret;
}

std::string TOpenSslLastError::GetErrorText(int errorCode, const char* action) {
    std::stringstream result;
    if (action) {
        result << action << ". ";
    }
    result << "Code " << errorCode << ": " << NOpenSsl::GetLastOpenSslError();
    return result.str();
}

} // namespace NOpenSsl
