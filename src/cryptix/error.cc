//
// Created by quinn on 7/4/2025.
// Copyright (c) 2025 All rights reserved.
//

#include <fmt/core.h>
#include <cpputils/fileops.h>

#include "cryptix/error.h"

namespace Cryptix {

thread_local std::string ErrorContext::lastError_;

void ErrorContext::SetLastError(const char* file, int line, const std::string& msg) {
    lastError_ = fmt::format("[{}:{}] {}", Cpputils::ExtractFileName(file), line, msg);
}

void ErrorContext::SetLastError(const std::string& file, int line, const std::string& msg) {
    SetLastError(file.c_str(), line, msg);
}

void ErrorContext::SetLastError(const char* file, int line, std::string&& msg) {
    lastError_ = fmt::format("[{}:{}] {}", Cpputils::ExtractFileName(file), line, std::move(msg));
}

void ErrorContext::SetLastError(const std::string& file, int line, std::string&& msg) {
    SetLastError(file.c_str(), line, std::move(msg));
}

}