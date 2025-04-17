cmake_minimum_required(VERSION 3.15)

project(Cryptix VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include("${CMAKE_CURRENT_BINARY_DIR}/generators/conan_toolchain.cmake")

find_package(OpenSSL REQUIRED)
find_package(fmt REQUIRED)

add_subdirectory(src)
# only add when tests are enabled
add_subdirectory(test)