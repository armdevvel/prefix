# What is it?

Common prefix (simulated root) and "well-known directory" location logic. Provides [paths.h](include/paths.h) on platforms
that never heard of it. Most of the logic is outlined in the comments and macro definitions within the include file itself.

The standard `_PATH_*` macros, usually implemented as string literals, resolve instead as calls to `libprefix` public API.
The most common case is as follows: wherever the main application is installed, `libprefix` itself is expected to be found
under the system root, typically in "bin" or a subfolder of "bin" (the exact name is softcoded and configurable). If that's
the case, the base path of "bin" (the parent of its outermost path component) becomes the detected simroot.

Fallbacks and overrides are possible; particularly, application configuration directories ("etc") receive special handling,
as application configuration is more likely to diverge between users (and needs to be easier to edit) than executable code.

## Implementation notes

TODO write up a TL;DR

### Limitations

No Unicode support. Paths are ASCII. Related:
* https://github.com/treeswift/libfatctl/issues/4

Context:
* https://github.com/treeswift/toybox-mingw
* https://github.com/armdevvel/openssh-portable

## Design notes

### Relationship with [libmoregw](https://github.com/treeswift/libmoregw)

While functionally being an essential path of the `libmoregw` meta-package, `libprefix` aims at being disconnected from its
dependency graph. Particularly, its lower-level components should resist the temptation to use `paths.h` and generally stay
file system layout agnostic, while `libprefix` itself should resist the temptation to expose API that's usable to such path
agnostic components. Distro-wide infrastructure (such as an implementation of `procfs` or a port of `dbus`) should probably
comprise another meta-package, most naturally called `libdistro`; in this case, `libprefix` becomes the perfect section to
separate `libmoregw` (libc-like API provider) from `libdistro` (provider of facilities not encapsulated naturally in libc).

# Legal

`libprefix` is released into the public domain with a no-strings-attached [Unlicense license](LICENSE).

