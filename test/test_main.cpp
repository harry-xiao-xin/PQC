//
// Created by zpx on 2025/01/13.
//
#include <gtest/gtest.h>
#include <glog/logging.h>
#include <iostream>

int main(int argc, char *argv[]) {
    testing::InitGoogleTest(&argc, argv);
    google::InitGoogleLogging("QP");
    FLAGS_log_dir = "./log";
    FLAGS_alsologtostderr = true;
    LOG(INFO) << "Start test...\n";
    return RUN_ALL_TESTS();
}