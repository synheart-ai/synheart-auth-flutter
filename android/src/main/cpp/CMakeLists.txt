cmake_minimum_required(VERSION 3.18)
project(synheart_native_crypto)

add_library(synheart_native_crypto SHARED synheart_native_bridge.cpp)

# Required for Google Play (Nov 2025): produce 16 KB-aligned ELF segments
# so the .so loads on Android 15+ devices using 16 KB memory pages.
# Harmless on NDK r28+ (where this is already the default).
target_link_options(synheart_native_crypto PRIVATE
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,common-page-size=16384"
)

target_link_libraries(synheart_native_crypto log)
