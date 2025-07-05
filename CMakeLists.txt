cmake_minimum_required(VERSION 3.15)

project(cryptix VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(OpenSSL REQUIRED)
find_package(fmt REQUIRED)
find_package(cpputils REQUIRED) # install from here using conan: https://github.com/quinnwencn/cpputils.git
find_package(Threads REQUIRED)

add_subdirectory(src)

add_library(${PROJECT_NAME} SHARED
    $<TARGET_OBJECTS:crypto>
)
target_link_libraries(${PROJECT_NAME} PUBLIC
    ${OpenSSL_LIBRARIES}
    ${fmt_LIBRARIES}
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    cpputils::cpputils
    Threads::Threads
)

install(TARGETS ${PROJECT_NAME}
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/cryptix DESTINATION include FILES_MATCHING PATTERN "*.h")
