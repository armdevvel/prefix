#include "paths.h"

/* cache, containers and concurrency */
#include <atomic>
#include <mutex>
#include <map>
#include <string>
#include <utility>
#include <functional>

/* error handling */
#include <exception>
#include <stdexcept>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include "dbg.h"

namespace fixpre {
namespace detail {

/* don't want a header for this method alone */
__attribute__((visibility("hidden")))
extern std::string OSPathLookup(
    enum fixpre_known_path path_kind,
    enum fixpre_config_options options,
    std::function<const std::string&(enum fixpre_known_path)> get_dep);

} // namespace detail
} // namespace fixpre

namespace
{
constexpr int kApplied = fixpre_config_options__reserved_upper_bit;
std::atomic<int> _options{0};

void ensure_trailing(std::string& str, char chr) {
    if(str.size() && str.back() != chr) {
        str.push_back(chr);
    }
}

void transliterate(std::string& str, char old, char sub) {
    for(char& chr : str) {
        if(chr == old) {
            chr = sub;
        }
    }
}

enum fixpre_config_options take_options() {
    int taken, applied;
    do taken = _options, applied = kApplied | taken;
    while(!_options.compare_exchange_weak(taken, applied, std::memory_order_relaxed));
    return static_cast<enum fixpre_config_options>(taken);
}

using DoWith = std::function<void(int)>;

DoWith with_or_without(int flag, DoWith action) {
    return [flag, action](int flags) {
        action(flags);
        action(flags | flag);
    };
}

struct PathCache;

struct PathQuery
{
    PathQuery(enum fixpre_known_path path_kind, std::string path_suffix, bool cache_output)
        : kind(path_kind), suffix(path_suffix), _cache_output(cache_output),
            err(0), out{}, cached(nullptr) {}

    /* at this moment, we are under cache instance lock */
    void setCached(const std::string& cache_hit) {
        if(_cache_output) {
            cached = cache_hit.c_str(); // C API
        } else {
            out = cache_hit; // C++ API
        }
    }

    /* under cache instance lock, and the cache needs to be updated */
    void setResult(int error_code, const std::string& path_or_msg, PathCache& cache);

    const enum fixpre_known_path kind;
    const std::string suffix;
    const bool _cache_output;
    int err;
    std::string out;  // C++
    const char* cached; // C
};

using namespace fixpre::detail;

struct PathCache {
    using Key = std::pair<int, std::string>;

    PathCache() : options(take_options()) {

        // 1. (0xf0 << 24) modifiers change the path substantially. Therefore, do the full lookup.
        // Note - not all flags affect all families, but we do all out of an abundance of caution.
        // 2. (0x0f << 24) modifiers only transliterate the path. Transliterate results on demand.
        // 3. iterate family groups until EINVAL at position fam+0
        // 4. iterate within family groups until EINVAL at position fam+n (n>0)

        with_or_without(fixpre_path_modifiers__profile_dir, //1
            with_or_without(fixpre_path_modifiers__cfgfile_dir, //1
                [this](int mods) {
                    int fam = 0;
                    while(resolve_path(mods + fam)) { //3
                        int knp = 1;
                        while(resolve_path(mods + fam + knp)) { //4
                            knp++;
                        }
                        fam += (1 << _PREFIX_PATH_MEMBER_BITS);
                    }
                }
            )
        )(0);
    }

    /* always under singleton lock and within constructor */
    bool resolve_path(int path_kind) {
        auto kind = static_cast<enum fixpre_known_path>(path_kind);
        auto out = OSPathLookup(kind, options,
            [this](enum fixpre_known_path dependency) { return must_exist(dependency); });
        return out.size() ? static_cast<bool>(set_base(kind, out)) : false;
    }

    /* always under singleton lock and within constructor */
    const std::string& must_exist(enum fixpre_known_path path_kind) const {
        return _impl.at({path_kind, {}}); // assertion within
    }

    /* always under lock */
    const char* set_base(enum fixpre_known_path path_kind, const std::string& val) {
        return set_full(path_kind, {}, val);
    }

    /* always under lock */
    const char* set_full(enum fixpre_known_path path_kind, const std::string& suffix, const std::string& val) {
        auto inserted = _impl.emplace(Key{path_kind, suffix}, val);
        assert(inserted.second);
        return inserted.first->second.c_str();
    }

    void lookup(PathQuery& pq) {
        std::unique_lock<std::mutex> guard(_guard);
        lookup_locked(pq);
    }

private:
    void lookup_locked(PathQuery& pq) {

        // When we request a path, there are the following scenarios in play:
        // A) cache hit as is, return cached value;
        // B) cache hit (base path) and no cache_output, return concatenated;
        // C) cache hit (base path) but cache_output=on, concatenate & cache;
        // D) cache miss (complete) but available under alternative sepflags;
        // E) cache miss (complete) > EINVAL

        auto itr = _impl.find({pq.kind, pq.suffix}); // A?
        if(_impl.end() != itr) { // A!
            pq.setCached(itr->second);
        } else {
            itr = _impl.find({pq.kind, {}}); // B|C?
            if(_impl.end() != itr) { // B|C
                pq.setResult(0, itr->second, *this);
            } else { // D|E
                int canflags = pq.kind & ~_PREFIX_PATH_FORMAT_MASK;
                if(canflags != pq.kind) { // ...maybe D?
                    PathQuery cs{static_cast<enum fixpre_known_path>(canflags),
                            pq.suffix, pq._cache_output};
                    lookup_locked(cs);
                    if(!(pq.err = cs.err)) { // D
                        if(pq.kind & fixpre_path_modifiers__native_dsep) {
                            transliterate(cs.out, '/', '\\');
                        }
                        if(pq.kind & fixpre_path_modifiers__native_psep) {
                            transliterate(cs.out, ':', ';');
                        }
                        pq.setResult(cs.err, cs.out, *this);
                    }
                } else { // E
                    pq.err = EINVAL; // sorry folks, out of coffee today
                }
            }
        }
    }

    mutable std::mutex _guard;
    const enum fixpre_config_options options;
    std::map<Key, std::string> _impl;
};

PathCache& path_cache() {
    static PathCache cache;
    return cache;
}

void PathQuery::setResult(int error_code, const std::string& path_or_msg, PathCache& cache) {
    out = path_or_msg;
    if(!(err = error_code)) {
        if(_PREFIX_PATH_IS_PATHLIST(kind)) {
            ensure_trailing(out, (kind & fixpre_path_modifiers__native_psep) ? ';' : ':');
        }
        out.append(suffix);
    } else if(out.empty()) {
        out = strerror(err);
    }
    if(_cache_output) {
        cached = cache.set_full(kind, suffix, out);
    }
}

} // anonymous

namespace fixpre
{

std::string Path(enum fixpre_known_path path_kind, const std::string& suffix)
{
    PathQuery pq(path_kind, suffix, false);
    path_cache().lookup(pq);
#ifdef _PREFIX_NOEXCEPT
    if(pq.err) {
        _PREFIX_LOG("_PATH[0x%x]/%s -> errno=%d/%s", path_kind, suffix, pq.err, pq.out);
        return errno = pq.err, {};
    }
    return pq.out;
#else
    switch(pq.err) {
    case 0:
        return pq.out;
    case EINVAL:
        throw std::invalid_argument(pq.out);
    default:
        throw std::runtime_error(pq.out);
    }
#endif
}

} // namespace fixpre

extern "C"
{

int fixpre_configure(enum fixpre_config_options options) {
    int last_opt;
    do if((last_opt = _options) & kApplied) return errno = EBUSY, -1;
    while(!_options.compare_exchange_weak(last_opt, options, std::memory_order_relaxed));
    return 0;
}

const char* fixpre_path(enum fixpre_known_path path_kind, const char* suffix) {
    PathQuery pq(path_kind, suffix, true);
    path_cache().lookup(pq);
    if(pq.err) {
        _PREFIX_LOG("_PATH[0x%x]/%s -> errno=%d/%s", path_kind, suffix, pq.err, pq.cached);
        errno = pq.err;
        return nullptr;
    }
    return pq.cached;
}

} // extern "C"