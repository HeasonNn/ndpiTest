cmake_minimum_required(VERSION 3.10)

project(test VERSION 1.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

include_directories(
    src/lib
)

add_library(ndpi_common STATIC
    src/lib/ndpi_common.c
)

add_executable(test src/main.c)

target_link_libraries(test
    ndpi_common
    ndpi
    pcap
    event
)
