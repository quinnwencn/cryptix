cmake_minimum_required(VERSION 3.15)
project(cryptix_test LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE TEST_SOURCES CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc"
    "${CMAKE_CURRENT_SOURCE_DsIR}/src/*.h"
)

find_package(GTest REQUIRED)
find_package(cryptix REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(cryptix_test ${TEST_SOURCES})
target_include_directories(cryptix_test PRIVATE 
    "${CMAKE_SOURCE_DIR}/include"
    ${GTest_INCLUDE_DIRS}
    ${cryptix_INCLUDE_DIRS})
target_link_libraries(cryptix_test PRIVATE
    ${GTest_LIBRARIES}
    ${OpenSSL_LIBRARIES}
    cryptix::cryptix
)

# prepare test sources
execute_process(COMMAND mkdir -p mock
                WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

if (NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/mock/rsa_root.key)
    # generate a self-signed certificate
    execute_process(COMMAND openssl genpkey -algorithm RSA -out rsa_root.key -pkeyopt rsa_keygen_bits:2048
                    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/mock"
                    OUTPUT_VARIABLE RSA_PRIVATE_KEY
                    OUTPUT_QUIET
    )
endif()

if (NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/mock/rsa_root_pub.key)
    execute_process(COMMAND openssl pkey -in rsa_root.key -pubout -out rsa_root_pub.key
                    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/mock"
                    OUTPUT_VARIABLE RSA_PRIVATE_KEY
                    OUTPUT_QUIET
    )
endif()

if (NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/mock/root.pem)
    execute_process(COMMAND openssl req -new -x509 -key rsa_root.key -out root.pem -days 365 -subj "/C=CN/ST=Shanghai/L=Shanghai Jiading/O=My Company/CN=www.example.com"
                    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/mock/"
                    OUTPUT_VARIABLE ROOT_CERT
                    OUTPUT_QUIET
    )
endif()

target_compile_definitions(cryptix_test PRIVATE
    ROOT_PEM="${CMAKE_CURRENT_SOURCE_DIR}/mock/root.pem"
    ROOT_DER="${CMAKE_CURRENT_SOURCE_DIR}/mock/root.der"
    ROOT_PRIV_KEY="${CMAKE_CURRENT_SOURCE_DIR}/mock/rsa_root.key"
    ROOT_PUB_KEY="${CMAKE_CURRENT_SOURCE_DIR}/mock/rsa_root_pub.key"
)

enable_testing()
add_test(NAME cryptix_test COMMAND cryptix_test)