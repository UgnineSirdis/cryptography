# Header only lib.
# Implementation can use different versions of openssl.
cc_library(
    name = "include",
    hdrs = [
        "include/openssl_wrapper/encryption_stream.h",
        "include/openssl_wrapper/error.h",
        "include/openssl_wrapper/random.h",
    ],
    strip_include_prefix = "include",
    visibility = ["//visibility:public"],
)

SOURCES = [
    "impl/encryption_stream.cpp",
    "impl/error.cpp",
    "impl/helpers.h",
    "impl/random.cpp",
]

cc_library(
    name = "impl-1.1.1t",
    srcs = SOURCES,
    local_defines = [
        "__OPENSSL_VERSION__=1",
    ],
    deps = [
        "@openssl-1.1.1t//:openssl",
        ":include",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "impl-3.3.1",
    srcs = SOURCES,
    local_defines = [
        "__OPENSSL_VERSION__=3",
    ],
    deps = [
        "@openssl-3.3.1//:openssl",
        ":include",
    ],
    visibility = ["//visibility:public"],
)
