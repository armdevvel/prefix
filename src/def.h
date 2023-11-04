#ifndef _SRC_DEF_H_
#define _SRC_DEF_H_

#include "paths.h"

#include <functional>
#include <string>

#define Known(x) static_cast<enum fixpre_known_path>(x)

namespace fixpre {
namespace detail {

/**
 * "GetDependencyPath". The other reading is valid, too:
 *  -- macroeconomic regulation is a path to dependency.
 */
using GDP = std::function<const std::string&(int)>;

__attribute__((visibility("hidden")))
extern std::string OSPathLookup(int path_kind, enum fixpre_config_options options, GDP get_dep);

__attribute__((visibility("hidden")))
extern void SweetHome(const std::string& home);

} // namespace detail
} // namespace fixpre

#endif /* _SRC_DEF_H_ */