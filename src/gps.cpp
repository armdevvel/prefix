#include "paths.h"

/* cache, containers and concurrency */
#include <atomic>
#include <mutex>
#include <map>
#include <utility>

/* error handling */
#include <exception>
#include <stdexcept>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include <sys/stat.h>

#include "def.h"
#include "dbg.h"

namespace
{
constexpr int kApplied = fixpre_config_options__reserved_upper_bit;
std::atomic<int> _options{0};
const std::string kUndefined;

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
    do (taken = _options), (applied = kApplied | taken);
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
    PathQuery(int path_kind, std::string path_suffix, bool cache_output)
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

    const int kind;
    const std::string suffix;
    const bool _cache_output;
    int err;
    std::string out;  // C++
    const char* cached; // C
};

using namespace fixpre;
using namespace detail;

struct PathCache {
    using Key = std::pair<int, std::string>;
    using Map = std::map<Key, std::string>;

    PathCache() : options(take_options()) {

        _PREFIX_LOG("Constructing path cache with options %08x", options);

        // 1. (0xf0 << 24) modifiers change the path substantially. Therefore, do the full lookup.
        // Note - not all flags affect all families, but we do all out of an abundance of caution.
        // 2. (0x0f << 24) modifiers only transliterate the path. Transliterate results on demand.
        // 3. iterate family groups until EINVAL at position fam+0
        // 4. iterate within family groups until EINVAL at position fam+n (n>0)

        with_or_without(fixpre_path_modifiers__cfgfile_dir, //1
            with_or_without(fixpre_path_modifiers__profile_dir, //1
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

        if(!(fixpre_config_options__tuning_noninvasive & options)) {
            SweetHome(mbexisting(fixpre_known_path__homedir | fixpre_path_modifiers__profile_dir));
        }
    }

    /* always under singleton lock and within constructor */
    bool resolve_path(int path_kind) {
        auto out = OSPathLookup(path_kind, options, [this](int dep) { return mbexisting(dep); });
        auto kind = _PREFIX_ENUM_KNOWN_PATH(path_kind);
        transliterate(out, ';', ':');
        transliterate(out, '\\', '/');
        if(fixpre_file_type(path_kind) == S_IFDIR) {
            ensure_trailing(out, '/'); // MOREINFO doesn't work w/TEMP?
        }
        if(kind == fixpre_known_path__etcroot) {
            if(fixpre_config_options__profile_as_etchome & options) {
                out.push_back('.'); // produces e.g. "$HOME/.ssh"
            } else {
                //_PREFIX_LOG("Append etc/ to: %s", out.c_str());
                out.append(_SUFFIX_PATH_ETC); // "$PREFIX/etc/ssh"
            }
        }
        return out.size() && set_base(path_kind, out) || fixpre_explain(kind);
    }

    /* always under singleton lock and within constructor */
    const std::string& must_exist(int path_kind) const {
        //_PREFIX_LOG("must exist: %08x", path_kind);
        return _impl.at({path_kind, {}}); // assertion within
    }

    /* always under singleton lock and within constructor */
    const std::string& mbexisting(int path_kind) const {
        //_PREFIX_LOG("need exist: %08x", path_kind);
        auto itr = _impl.find({path_kind, {}});
        return (itr != _impl.end()) ? itr->second : kUndefined;
    }

    /* always under lock */
    const char* set_base(int path_kind, const std::string& val) {
        return set_full(path_kind, {}, val);
    }

    /* always under lock */
    const char* set_full(int path_kind, const std::string& suffix, const std::string& val) {
        auto inserted = _impl.emplace(Key{path_kind, suffix}, val);
        assert(inserted.second);
        return inserted.first->second.c_str();
    }

    void lookup(PathQuery& pq) {
        std::unique_lock<std::mutex> guard(_guard);
        lookup_locked(pq);
    }

    bool peek(int path_kind, OnKnownPath okp) const {
        typename Map::const_iterator itr;
        {
            std::unique_lock<std::mutex> guard(_guard);
            itr = _impl.find(Key{path_kind, {}});
        }
        return (itr == _impl.end()) ? false :
                (okp(Known(path_kind), itr->second), true);
    }

    void iterate(OnCachedPath ocp) const {
        Map impl_copy;
        {
            std::unique_lock<std::mutex> guard(_guard);
            impl_copy = _impl;
        }
        for(const auto& known : impl_copy) {
            ocp(Known(known.first.first),
                known.first.second, known.second);
        }
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
                    PathQuery cs{canflags, pq.suffix, pq._cache_output};
                    lookup_locked(cs);
                    if(!(pq.err = cs.err)) { // D
                        if(pq.kind & fixpre_path_modifiers__native_dsep) {
                            transliterate(cs.out, '/', '\\');
                        }
                        if(fixpre_path_families__binpath == (pq.kind & _PREFIX_PATH_FAMILY_MASK)) {
                            transliterate(cs.out, '\1', (pq.kind & fixpre_path_modifiers__native_psep) ? ';' : ':');
                        }
                        pq.setResult(cs.err, cs.out, *this);
                    }
                } else { // E
                    pq.err = EINVAL; // sorry folks, out of coffee today
                }
            }
        }
    }

    const enum fixpre_config_options options;
    mutable std::mutex _guard;
    Map _impl;
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

std::string Path(int path_kind, const std::string& suffix)
{
    PathQuery pq(path_kind, suffix, false);
    path_cache().lookup(pq);
#ifdef _PREFIX_NOEXCEPT
    if(pq.err) {
        _PREFIX_LOG("_PATH[0x%x]/%s -> errno=%d/%s", path_kind, suffix.c_str(), pq.err, pq.out.c_str());
        errno = pq.err;
        return {};
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

void EnumerateKnownBasePaths(OnKnownPath callback) {
    const auto& cache = path_cache();
    // TODO: extract idiom (see also ctor of PathCache)
    int fam = 0;
    while(fixpre_explain(fam)) {
        int knp = fam;
        do cache.peek(knp, callback);
        while(fixpre_explain(++knp));
        fam += (1 << _PREFIX_PATH_MEMBER_BITS);
    }
}

void EnumerateCachedPaths(OnCachedPath callback) {
    const auto& cache = path_cache();
    cache.iterate(callback);
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

void fixpre_enumerate_known_base_paths(void(*callback)(enum fixpre_known_path, const char* value)) {
    EnumerateKnownBasePaths([callback](enum fixpre_known_path path_kind, const std::string& value) {
        callback(path_kind, value.c_str());
    });
}

void fixpre_enumerate_cached_paths(void(*callback)(enum fixpre_known_path, const char* suffix, const char* value)) {
    EnumerateCachedPaths([callback](enum fixpre_known_path kind, const std::string& suffix, const std::string& value) {
        callback(kind, suffix.c_str(), value.c_str());
    });
}

const char* fixpre_path(int path_kind, const char* suffix) {
    PathQuery pq(Known(path_kind), suffix, true);
    path_cache().lookup(pq);
    if(pq.err) {
        _PREFIX_LOG("_PATH[0x%x]/%s -> errno=%d/%s", path_kind, suffix, pq.err, pq.cached);
        errno = pq.err;
        return nullptr;
    }
    return pq.cached;
}

} // extern "C"