find_package(GTest REQUIRED)
find_package(benchmark REQUIRED)
aux_source_directory(../benchmark DIR_BENCHMARK)


set(link_lib glog gtest pthread)
add_executable(BENCHMARK_PQC ${DIR_BENCHMARK})
link_directories(/usr/local/lib/)
target_link_libraries(BENCHMARK_PQC  ${link_lib} benchmark::benchmark)