cmake_minimum_required(VERSION 3.20)

#############################################
# Base Config
#############################################
project(PQC CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_BUILD_TYPE Release)
############################################
# Complex compiler
############################################
# Targeted operating system.
#set(CMAKE_SYSTEM_NAME Windows)
## Use mingw 64-bit compilers.
#set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc-posix)
#set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-c++-posix)
#set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32/)
#
## Adjust the default behavior of the find commands:
## search headers and libraries in the target environment
#set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
############################################

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

include_directories(./include)
#aux_source_directory(./src/pybind DIR_PYBIND)
#add_executable(${PROJECT_NAME} main.cpp ${DIR_PYBIND})
add_executable(${PROJECT_NAME} main.cpp)

#############################################
# Compile Config
#############################################
# BENCHMARK
option(BENCHMARK "Benchmark Module" OFF)
message("BENCHMARK_ENABLE Value: ${BENCHMARK}")
# FSANITIZE
option(FSANITIZE "Fsanitize Module" OFF)
message("FSANITIZE_ENABLE Value: ${FSANITIZE}")
# PYBIND11
option(PYBIND11 "Pybind11 Module" OFF)
message("PYBIND11_ENABLE Value: ${PYBIND11}")
# JNI
option(JNI "JNI Module" ON)
message("JNI_ENABLE Value: ${JNI}")
# GTEST
option(GTEST "GTEST Module" OFF)
message("GTEST_ENABLE Value: ${GTEST}")

if (BENCHMARK)
    find_package(benchmark REQUIRED)
    target_link_libraries(${PROJECT_NAME} benchmark::benchmark)
    add_subdirectory(benchmark)
endif (BENCHMARK)
if (FSANITIZE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address ")
endif (FSANITIZE)
if (PYBIND11)
    find_package(PythonLibs REQUIRED)
    include_directories(${PYTHON_INCLUDE_DIRS})
    add_subdirectory(pybind11)
    target_link_libraries(${PROJECT_NAME} ${PYTHON_LIBRARIES})
    pybind11_add_module(PQC_PYTHON src/pybind/py_interface.cpp)
    target_compile_definitions(PQC_PYTHON PRIVATE VERSION_INFO=${EXAMPLE_VERSION_INFO})
endif (PYBIND11)

if (JNI)
#    SET(Java_JAR_EXECUTABLE "/usr/local/jdk1.8.0_202/bin/java")
#    SET(Java_JAVAC_EXECUTABLE "/usr/local/jdk1.8.0_202/bin/javac")
#    SET(Java_JAVAH_EXECUTABLE "/usr/local/jdk1.8.0_202/bin/javah")
#    SET(Java_JAVADOC_EXECUTABLE "/usr/local/jdk1.8.0_202/bin/javadoc")
    find_package(Java REQUIRED)
    find_package(JNI REQUIRED)
    include(UseJava)
    include_directories(${JNI_INCLUDE_DIRS})
    add_jar(PQCJNI
            VERSION 0.0.1
            ENTRY_POINT com.example.pqc.MLKEMJNI
            GENERATE_NATIVE_HEADERS PQCJNI-native
            SOURCES src/java/com/example/pqc/MLKEMJNI.java)
    add_library(PQCJNI-cpp SHARED src/cpp/MLKEMJNI-cpp.cpp)
    target_include_directories(PQCJNI-cpp PRIVATE ${JNI_INCLUDE_DIRS})
    target_link_libraries(PQCJNI-cpp PRIVATE PQCJNI-native ${JNI_LIBRARIES})
endif (JNI)
if (GTEST)
    find_package(GTest CONFIG REQUIRED)
    set(link_lib glog pthread gtest)
    target_include_directories(${PROJECT_NAME} PUBLIC ${GTEST_INCLUDE_DIRS})
    target_link_libraries(${PROJECT_NAME} ${link_lib})
    enable_testing()
    add_subdirectory(test)
endif (GTEST)