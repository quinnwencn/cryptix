file(GLOB_RECURSE RANDOM_SRCS CMAKE_CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cc)
add_library(random OBJECT ${RANDOM_SRCS})
target_include_directories(random PUBLIC ${CMAKE_SOURCE_DIR}/include)

set_target_properties(random PROPERTIES POSITION_INDEPENDENT_CODE ON)