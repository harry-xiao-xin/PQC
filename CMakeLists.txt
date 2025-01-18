cmake_minimum_required(VERSION 3.24)
project(PQC CXX)
set(CMAKE_CXX_STANDARD 20)
#############################################
# Base Config
#############################################
find_package(GTest CONFIG REQUIRED)
set(link_lib glog pthread gtest)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

include_directories(./include)
aux_source_directory(./src/pybind DIR_PYBIND)
add_executable(${PROJECT_NAME} main.cpp ${DIR_PYBIND})

#############################################
# Compile Config
#############################################
# BENCHMARK
option(BENCHMARK "Benchmark Module" ON)
message("BENCHMARK_ENABLE Value: ${BENCHMARK}")
# FSANITIZE
option(FSANITIZE "Fsanitize Module" OFF)
message("FSANITIZE_ENABLE Value: ${FSANITIZE}")
# PYBIND11
option(PYBIND11 "Pybind11 Module" ON)
message("PYBIND11_ENABLE Value: ${PYBIND11}")

if (BENCHMARK)
    find_package(benchmark REQUIRED)
    target_link_libraries(${PROJECT_NAME} benchmark::benchmark)
    add_subdirectory(benchmark)
endif (BENCHMARK)
if (FSANITIZE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address ")
endif (FSANITIZE)
if (PYBIND11)
#    set(pybind11_INCLUDE_DIRS  /root/miniconda3/lib/python3.9/site-packages/pybind11/share/cmake/pybind11)
#    find_package(pybind11 REQUIRED)
    find_package(PythonLibs REQUIRED)
    add_subdirectory(pybind11)
    pybind11_add_module(PQC_PYTHON src/pybind/py_interface.cpp)
    target_compile_definitions(PQC_PYTHON PRIVATE VERSION_INFO=${EXAMPLE_VERSION_INFO})
endif (PYBIND11)


target_include_directories(${PROJECT_NAME} PUBLIC ${GTEST_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} ${link_lib})
enable_testing()
add_subdirectory(test)