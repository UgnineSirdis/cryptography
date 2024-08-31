#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include <openssl/sha.h>

// From https://stackoverflow.com/a/2262447/7768383
bool simpleSHA256(const void* input, unsigned long length, unsigned char* md)
{
    SHA256_CTX context;
    if (!SHA256_Init(&context))
        return false;

    if (!SHA256_Update(&context, (unsigned char*)input, length))
        return false;

    if (!SHA256_Final(md, &context))
        return false;

    return true;
}

// Convert an byte array into a string
std::string fromByteArray(const unsigned char* data, unsigned long length)
{
    std::stringstream shastr;
    shastr << std::hex << std::setfill('0');
    for (unsigned long i = 0; i < length; ++i)
    {
        shastr << std::setw(2) << static_cast<int>(data[i]);
    }

    return shastr.str();
}

std::string MESSAGE = "hello world";

int main(int argc, const char** argv) {
    std::cerr << "cipher program" << std::endl;

    unsigned char md[SHA256_DIGEST_LENGTH] = {};

    if (!simpleSHA256(static_cast<const void*>(MESSAGE.data()), MESSAGE.size(), md)) {
        std::cerr << "simpleSHA256 failed" << std::endl;
    }
    std::string hash = fromByteArray(md, SHA256_DIGEST_LENGTH);

    std::cerr << "SHA256(" << MESSAGE << ") = " << hash << std::endl;

    return 0;
}
