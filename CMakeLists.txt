cmake_minimum_required(VERSION 3.12)
project(ByteHunter)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

find_package(PkgConfig REQUIRED)

set(IDA_SDK_PATH "${CMAKE_SOURCE_DIR}/../SDK" CACHE PATH "IDA SDK path")

file(GLOB_RECURSE SOURCES "src/*.c")

add_library(ByteHunter SHARED ${SOURCES})

target_include_directories(ByteHunter PRIVATE 
    include 
    ${IDA_SDK_PATH}/include
)

target_compile_options(ByteHunter PRIVATE 
    -mavx2 
    -O2 
    -Wall 
    -Wextra
)

target_link_libraries(ByteHunter ${IDA_SDK_PATH}/lib/ida.lib)

set_target_properties(ByteHunter PROPERTIES
    SUFFIX ".dll"
    PREFIX ""
)
