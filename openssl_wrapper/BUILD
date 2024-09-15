# Header only lib.
# Implementation can use different versions of openssl.
cc_library(
    name = "include",
    hdrs = [
        "include/openssl_wrapper/error.h"
    ],
    strip_include_prefix = "include",
    visibility = ["//visibility:public"],
)

cc_library(
    name = "impl",
    srcs = [
        "impl/error.cpp",
        "impl/helpers.h"
    ],
    deps = [
        "@openssl//:openssl",
        ":include",
    ],
    visibility = ["//visibility:public"],
)
