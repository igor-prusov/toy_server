project (SERVER)
add_executable (final main.cpp)
set (CMAKE_CXX_FLAGS "--std=gnu++11 ${CMAKE_CXX_FLAGS}")

TARGET_LINK_LIBRARIES(final pthread)
