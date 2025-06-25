cmake_minimum_required(VERSION 3.15)

project(Cryptix VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include("${CMAKE_CURRENT_BINARY_DIR}/generators/conan_toolchain.cmake")

find_package(OpenSSL REQUIRED)
find_package(fmt REQUIRED)
find_package(cpputils REQUIRED) # install from here using conan: https://github.com/quinnwencn/cpputils.git

add_subdirectory(src)

add_library(cryptix SHARED
    $<TARGET_OBJECTS:crypto>
)
target_link_libraries(cryptix PUBLIC
    ${OpenSSL_LIBRARIES}
    ${fmt_LIBRARIES}
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    cpputils::cpputils
)

install(TARGETS cryptix
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/cryptix DESTINATION include FILES_MATCHING PATTERN "*.h")
