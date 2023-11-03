#include "paths.h"

#include <windows.h>

#include <string>

namespace fixpre {
namespace detail {

/**
 * TODO describe preconditions
 */
__attribute__((visibility("hidden"))) std::string OSPathLookup(
    enum fixpre_known_path path_kind,
    enum fixpre_config_options options,
    std::function<const std::string&(enum fixpre_known_path)> get_dep)
{
    // TODO implement
}

} // namespace detail
} // namespace fixpre
