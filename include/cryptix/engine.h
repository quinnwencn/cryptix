#ifndef ENGINE_H
#define ENGINE_H

#include <string_view>

#include <openssl/engine.h>
#include <openssl/err.h>

namespace cryptix {

class P11Ctx;
class P11slot;

class Engine {
public:
    // all blank to use no engine
    Engine(std::string_view engineType, std::string_view engineId, std::string_view enginePath, std::string_view modulePath);
    ~Engine();
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
    Engine(Engine&&) = delete;
    Engine& operator=(Engine&&) = delete;

    ENGINE* Get() const {
        return engine_;
    }

private:
    ENGINE* engine_ = nullptr;
};

}


#endif // ENGINE_H
