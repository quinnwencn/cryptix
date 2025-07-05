//
// Created by quinn on 7/4/2025.
// Copyright (c) 2025 All rights reserved.
//

#ifndef ERROR_H
#define ERROR_H

#include <string>

namespace Cryptix {

class ErrorContext {
public:
    static std::string LastError() {
        return lastError_;
    }

    static void SetLastError(const char* file, int line, const std::string& msg);
    static void SetLastError(const std::string& file, int line, const std::string& msg);
    static void SetLastError(const char* file, int line, std::string&& msg);
    static void SetLastError(const std::string& file, int line, std::string&& msg);

private:
    static thread_local std::string lastError_;
};

#define CRYPTX_ERROR(msg) Cryptix::ErrorContext::SetLastError(__FILE__, __LINE__, msg)

}

#endif //ERROR_H
