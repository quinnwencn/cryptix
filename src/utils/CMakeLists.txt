file(GLOB_RECURSE UTILS_SRCS CMAKE_CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cc)
add_library(utils OBJECT ${UTILS_SRCS})
target_include_directories(utils PUBLIC ${CMAKE_SOURCE_DIR}/include)

set_target_properties(utils PROPERTIES POSITION_INDEPENDENT_CODE ON)