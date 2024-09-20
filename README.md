# Cryptography
Examples of code related to cryptography.

Builds for two versions of openssl: `1.1.1t` and `3.3.1`.

## How to build and run

```shell
cd cryptography

# Build (for two versions of openssl)
$ bazel build //cipher:cipher-1.1.1t //cipher:cipher-3.3.1

# Run
# Default cipher test
$ ./bazel-bin/cipher/cipher-1.1.1t
$ ./bazel-bin/cipher/cipher-3.3.1

# Concrete cipher test
$ ./bazel-bin/cipher/cipher-1.1.1t chacha20-poly1305
$ ./bazel-bin/cipher/cipher-3.3.1 chacha20-poly1305

$ ./bazel-bin/cipher/cipher-1.1.1t aes-128-gcm
$ ./bazel-bin/cipher/cipher-3.3.1 aes-128-gcm
```

[Cipher names in openssl code](https://github.com/openssl/openssl/blob/master/crypto/objects/obj_dat.h#L1740)
