"""A module defining the third party dependency OpenSSL"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def openssl_repositories():
    # old version
    maybe(
        http_archive,
        name = "openssl-1.1.1t",
        build_file = Label("//openssl:BUILD.openssl-1.1.1t.bazel"),
        sha256 = "b1270f044e36452e15d1f2e18b702691a240b0445080282f2c7daaea8704ec5e",
        strip_prefix = "openssl-OpenSSL_1_1_1t",
        urls = [
            "https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_1_1t.tar.gz",
        ],
    )

    # current version
    maybe(
        http_archive,
        name = "openssl-3.3.1",
        build_file = Label("//openssl:BUILD.openssl-3.3.1.bazel"),
        sha256 = "777cd596284c883375a2a7a11bf5d2786fc5413255efab20c50d6ffe6d020b7e",
        strip_prefix = "openssl-3.3.1",
        urls = [
            "https://github.com/openssl/openssl/releases/download/openssl-3.3.1/openssl-3.3.1.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "nasm",
        build_file = Label("//openssl:BUILD.nasm.bazel"),
        sha256 = "f5c93c146f52b4f1664fa3ce6579f961a910e869ab0dae431bd871bdd2584ef2",
        strip_prefix = "nasm-2.15.05",
        urls = [
            "https://mirror.bazel.build/www.nasm.us/pub/nasm/releasebuilds/2.15.05/win64/nasm-2.15.05-win64.zip",
            "https://www.nasm.us/pub/nasm/releasebuilds/2.15.05/win64/nasm-2.15.05-win64.zip",
        ],
    )

    maybe(
        http_archive,
        name = "rules_perl",
        sha256 = "5cefadbf2a49bf3421ede009f2c5a2c9836abae792620ed2ff99184133755325",
        strip_prefix = "rules_perl-0.1.0",
        urls = [
            "https://github.com/bazelbuild/rules_perl/archive/refs/tags/0.1.0.tar.gz",
        ],
    )
