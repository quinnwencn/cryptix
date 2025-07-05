//
// Created by quinn on 7/5/2025.
// Copyright (c) 2025 All rights reserved.
//

#include "cryptix/error.h"

#include <thread>
#include <fmt/core.h>
#include <gtest/gtest.h>
#include <cpputils/fileops.h>


TEST(ErrorContextTest, SetAndGetLastError) {
    Cryptix::ErrorContext::SetLastError(Cpputils::ExtractFileName(__FILE__), 42, "Something went wrong!");
    auto err = Cryptix::ErrorContext::LastError();

    EXPECT_NE(err.find(fmt::format("{}:42", Cpputils::ExtractFileName(__FILE__))), std::string::npos);
    EXPECT_NE(err.find("Something went wrong!"), std::string::npos);
}

TEST(ErrorContextTest, MacroSetsCorrectLocation) {
    CRYPTX_ERROR("Macro triggered");

    auto err = Cryptix::ErrorContext::LastError();
    EXPECT_NE(err.find("Macro triggered"), std::string::npos);
    EXPECT_NE(err.find(Cpputils::ExtractFileName(__FILE__)), std::string::npos);
}

TEST(ErrorContextTest, ThreadLocalIsolation) {
    Cryptix::ErrorContext::SetLastError("main", 1, "main thread");

    std::string thread_err;
    std::thread t([&]() {
        Cryptix::ErrorContext::SetLastError("thread", 2, "worker thread");
        thread_err = Cryptix::ErrorContext::LastError();
    });

    t.join();

    std::string main_err = Cryptix::ErrorContext::LastError();

    EXPECT_NE(thread_err.find("worker thread"), std::string::npos);
    EXPECT_NE(main_err.find("main thread"), std::string::npos);
    EXPECT_EQ(main_err.find("worker thread"), std::string::npos);  // main thread 不应包含子线程错误
}
