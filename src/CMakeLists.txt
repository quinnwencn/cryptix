add_subdirectory(cert)

add_library(cryptix SHARED
    $<TARGET_OBJECTS:cert>
)
target_link_libraries(cryptix PUBLIC
    ${OpenSSL_LIBRARIES}
    ${fmt_LIBRARIES}
)