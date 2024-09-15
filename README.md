# Cryptography
Examples of code related to cryptography.

Builds for two versions of openssl: `1.1.1t` and `3.3.1`.

## How to build and run

```shell
cd cryptography

# Build (for two versions of openssl)
$ bazel build //cipher:cipher-1.1.1t //cipher:cipher-3.3.1

# Run
$ ./bazel-bin/cipher/cipher-1.1.1t
$ ./bazel-bin/cipher/cipher-3.3.1
```
