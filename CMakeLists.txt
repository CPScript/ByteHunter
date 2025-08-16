cmake_minimum_required(VERSION 3.12)
project(ByteHunter LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

# IDA SDK path
set(IDA_SDK_PATH "${CMAKE_SOURCE_DIR}/../SDK" CACHE PATH "IDA SDK path")

# Detect IDA version based on available SDK
if(EXISTS "${IDA_SDK_PATH}/8")
    set(IDA_VERSION "8" CACHE STRING "IDA version")
elseif(EXISTS "${IDA_SDK_PATH}/9")
    set(IDA_VERSION "9" CACHE STRING "IDA version")
elseif(EXISTS "${IDA_SDK_PATH}/9beta")
    set(IDA_VERSION "9beta" CACHE STRING "IDA version")
else()
    message(FATAL_ERROR "No valid IDA SDK found in ${IDA_SDK_PATH}")
endif()

message(STATUS "Building for IDA ${IDA_VERSION}")

# Source files
file(GLOB_RECURSE C_SOURCES "src/*.c")
file(GLOB_RECURSE CXX_SOURCES "src/*.cpp")

# Create the plugin library
add_library(ByteHunter SHARED ${C_SOURCES} ${CXX_SOURCES})

# Include directories
target_include_directories(ByteHunter PRIVATE 
    include 
    ${IDA_SDK_PATH}/${IDA_VERSION}/include
)

# Compiler flags
target_compile_options(ByteHunter PRIVATE 
    $<$<COMPILE_LANGUAGE:C>:-std=c11>
    $<$<COMPILE_LANGUAGE:CXX>:-std=c++17>
    -O2 
    -Wall 
    -Wextra
    -fPIC
)

# Enable AVX2 if supported
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag(-mavx2 COMPILER_SUPPORTS_AVX2)
if(COMPILER_SUPPORTS_AVX2)
    target_compile_options(ByteHunter PRIVATE -mavx2)
    target_compile_definitions(ByteHunter PRIVATE __AVX2__)
endif()

# Platform-specific settings
if(WIN32)
    set_target_properties(ByteHunter PROPERTIES SUFFIX ".dll")
    target_link_libraries(ByteHunter ${IDA_SDK_PATH}/${IDA_VERSION}/lib/x64_win_vc_64/ida.lib)
elseif(APPLE)
    set_target_properties(ByteHunter PROPERTIES SUFFIX ".dylib")
    target_link_libraries(ByteHunter ${IDA_SDK_PATH}/${IDA_VERSION}/lib/x64_mac_clang_64/ida.dylib)
else()
    set_target_properties(ByteHunter PROPERTIES SUFFIX ".so")
    target_link_libraries(ByteHunter ${IDA_SDK_PATH}/${IDA_VERSION}/lib/x64_linux_gcc_64/ida.so)
endif()

# Plugin naming
set_target_properties(ByteHunter PROPERTIES PREFIX "")

# Install target
install(TARGETS ByteHunter 
    DESTINATION ${CMAKE_INSTALL_PREFIX}
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)
