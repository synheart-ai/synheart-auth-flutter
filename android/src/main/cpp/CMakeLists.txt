cmake_minimum_required(VERSION 3.18)
project(synheart_native_crypto)

add_library(synheart_native_crypto SHARED synheart_native_bridge.cpp)

target_link_libraries(synheart_native_crypto log)
