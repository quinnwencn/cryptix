cmake_minimum_required(VERSION 3.15)

project(Cryptix VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include("${CMAKE_CURRENT_BINARY_DIR}/generators/conan_toolchain.cmake")

find_package(OpenSSL REQUIRED)
find_package(fmt REQUIRED)

add_subdirectory(src)

add_library(cryptix SHARED
    $<TARGET_OBJECTS:cert>
)
target_link_libraries(cryptix PUBLIC
    ${OpenSSL_LIBRARIES}
    ${fmt_LIBRARIES}
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

install(TARGETS cryptix
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include DESTINATION include FILES_MATCHING PATTERN "*.h")
