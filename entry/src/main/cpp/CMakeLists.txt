cmake_minimum_required(VERSION 3.13)
project(biu)

set(CMAKE_CXX_STANDARD 17)

add_library(biu SHARED
    napi_init.cpp
    tun_reader.cpp
    dns_handler.cpp
    ip_prober.cpp
)

target_link_libraries(biu PUBLIC
    libace_napi.z.so
    libhilog_ndk.z.so
)