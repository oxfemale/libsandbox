cmake_minimum_required(VERSION 3.12)
project(sbox C)

set(CMAKE_C_STANDARD 11)

set(LIBRARY_OUTPUT_PATH  "../bin")


add_library(sbox SHARED library.c library.h utils_general.c utils_general.h ntdll.c ntdll.h hooks.c hooks.h hfs.c hfs.h utils_fs.c utils_fs.h utils_str.c utils_str.h hashmap.c hashmap.h)


# Test 32/64 bits
if("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
    message(STATUS "Target is 64 bits")
    if (WIN32)
        set(WINXXBITS Win64)
        set_target_properties(sbox PROPERTIES OUTPUT_NAME "sbox64")
    endif(WIN32)
else("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
    message(STATUS "Target is 32 bits")
    if (WIN32)
        set(WINXXBITS Win32)
        set_target_properties(sbox PROPERTIES OUTPUT_NAME "sbox32")
        set (CMAKE_CXX_FLAGS "-m32")
    endif(WIN32)
endif("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")

target_link_libraries(sbox Userenv.lib)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static ")