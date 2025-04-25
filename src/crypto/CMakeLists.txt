file(GLOB_RECURSE CRYPTO_SRCS CMAKE_CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cc)
add_library(crypto OBJECT ${CRYPTO_SRCS})
target_include_directories(crypto PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${OpenSSL_INCLUDE_DIRS}
    ${fmt_INCLUDE_DIRS}
)
set_target_properties(crypto PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)