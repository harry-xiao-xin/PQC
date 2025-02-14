find_package(GTest REQUIRED)

set(link_lib glog pthread gtest)
set(CTEST_PARALLEL_LEVEL 8)

aux_source_directory(../test DIR_TEST)
aux_source_directory(../test/test_ml_kem DIR_TEST_ML_KEM)
aux_source_directory(../test/test_sha3 DIR_TEST_SHA3)
aux_source_directory(../test/test_subtle DIR_TEST_SUBTLE)
aux_source_directory(../test/test_utils DIR_TEST_UTILS)


add_executable(TEST_PQC ${DIR_TEST} ${DIR_TEST_ML_KEM} ${DIR_TEST_SHA3} ${DIR_TEST_SUBTLE} ${DIR_TEST_ML_DSA} ${DIR_TEST_UTILS})
link_directories(/usr/local/lib/)
target_link_libraries(TEST_PQC ${link_lib})