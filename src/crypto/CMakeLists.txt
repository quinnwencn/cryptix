file(GLOB_RECURSE CERT_SRCS CMAKE_CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cc)
add_library(crypto OBJECT ${CERT_SRCS})
target_include_directories(crypto PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${OpenSSL_INCLUDE_DIRS}
    ${fmt_INCLUDE_DIRS}
)
set_target_properties(crypto PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)