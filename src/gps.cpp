#include "paths.h"

#include <atomic>
#include <errno.h>

namespace fixpre
{

namespace
{

constexpr int kApplied = (1 << 31);
std::atomic<int> _options{0};

} // anonymous

std::string Path(enum fixpre_known_path, const std::string& suffix);

std::string UserProfile();

}

extern "C"
{

int fixpre_configure(enum fixpre_config_options options) {
    bool success;
    do {
        int last_opt = _options;
        if(_last_opt & kApplied) {
            return errno = EBUSY, -1;
        }
        success = _options.compare_exchange_weak(last_opt, options, std::memory_order_relaxed);
    }
    while(!success);
    return 0;

}

const char* fixpre_path(enum fixpre_known_path, const char* suffix) {
    //
}

const char* fixpre_userprofile() {
    //
}

} // extern "C"