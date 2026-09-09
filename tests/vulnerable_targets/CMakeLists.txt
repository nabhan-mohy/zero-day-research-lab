"""CMakeLists for test target."""

cmake_minimum_required(VERSION 3.10)
project(VulnerableParser)

set(CMAKE_C_STANDARD 11)

# Allow sanitizers via environment variables
if(DEFINED ENV{CFLAGS})
    set(CMAKE_C_FLAGS "$ENV{CFLAGS}")
else()
    set(CMAKE_C_FLAGS "-O2 -g")
endif()

if(DEFINED ENV{LDFLAGS})
    set(CMAKE_EXE_LINKER_FLAGS "$ENV{LDFLAGS}")
endif()

add_executable(parser parser.c)
