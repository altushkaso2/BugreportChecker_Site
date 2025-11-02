cmake_minimum_required(VERSION 3.16)

project(DebugReportChecker VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_definitions(-D_WIN32)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
endif()

include_directories(include)

file(GLOB_RECURSE SOURCES "src/*.cpp" "src/*/*.cpp")

add_executable(BugReportChecker ${SOURCES})

if (UNIX AND NOT APPLE)
    target_link_libraries(BugReportChecker pthread)
endif()

if(WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /ENTRY:mainCRTStartup")
endif()
