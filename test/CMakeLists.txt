file(GLOB_RECURSE TEST_SOURCES CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc"
    "${CMAKE_CURRENT_SOURCE_DsIR}/src/*.h"
)

find_package(gtest REQUIRED)

add_executable(cryptix_test ${TEST_SOURCES})
target_include_directories(cryptix_test PRIVATE 
    "${CMAKE_SOURCE_DIR}/include"
    ${GTest_INCLUDE_DIRS})
target_link_libraries(cryptix_test PRIVATE
    ${GTest_LIBRARIES}
    cryptix
)

# prepare test sources
execute_process(COMMAND mkdir -p mock
                WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

# generate a self-signed certificate
execute_process(COMMAND openssl genpkey -algorithm RSA -out mock/rsa_root.key -pkeyopt rsa_keygen_bits:2048
                WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
                OUTPUT_VARIABLE RSA_PRIVATE_KEY
                OUTPUT_QUIET
)

execute_process(COMMAND openssl req -new -x509 -key mock/rsa_root.key -out mock/root.pem -days 365 -subj "/C=CN/ST=Shanghai/L=Shanghai Jiading/O=My Company/CN=www.example.com"
                WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
                OUTPUT_VARIABLE ROOT_CERT
                OUTPUT_QUIET
)

target_compile_definitions(cryptix_test PRIVATE
    ROOT_PEM="${ROOT_CERT}"
    ROOT_DER="${CMAKE_CURRENT_SOURCE_DIR}/mock/root.der"
)