#ifndef _PATHS_H_
#define	_PATHS_H_

/**
 * Why the whimsical "fixpre"? Unfortunately, "prefix" is too common a word,
 * and while macros only affect specific translation units, symbols must be
 * unique within a linked binary (shared library or executable).
 * 
 * Also, it's an acronym for "fix prefix", which is what libprefix is written to do.
 */

/* BEGIN_DECLS */
#ifdef __cplusplus
#include <string>
#include <functional>
extern "C" {
#endif

/**
 * Special path request flags. The list may be expanded over time, but
 * there will always be enough free bits to accommodate the path family.
 */
enum fixpre_path_modifiers {
    /**
     * All four combinations of profile_dir and cfgfile_dir are possible:
     * <pro: 0, cfg: 0>  => global installation folder; known OS location
     * <pro: 0, cfg: 1>  => global configuration folder ("/etc/ssh")
     * <pro: 1, cfg: 0>  => per-user installation or data
     * <pro: 1, cfg: 1>  => per-user configuration folder ("~/.ssh")
     */
    fixpre_path_modifiers__profile_dir = (1 << 31), /* per-user; flips sign */
    fixpre_path_modifiers__cfgfile_dir = (1 << 30),
    /* ...a couple of reserved bits to indicate custom path semantic */

    fixpre_path_modifiers__native_dsep = (1 << 27), /* '\\' instead of '/' */
    /* ...a couple of reserved bits to indicate custom path format */
};

/**
 * A bitwise 'or' of the modifiers above, with a generous reservation.
 */
#define _PREFIX_PATH_USRCFG_MASK (0xf0 << 24)
#define _PREFIX_PATH_FORMAT_MASK (0x0f << 24)
#define _PREFIX_PATH_TUNING_MASK (_PREFIX_PATH_USRCFG_MASK | _PREFIX_PATH_FORMAT_MASK)

#define _PREFIX_PATH_MEMBER_BITS 12
#define _PREFIX_PATH_MEMBER_MASK ((1 << _PREFIX_PATH_MEMBER_BITS) - 1)
#define _PREFIX_PATH_FAMILY_MASK (~(_PREFIX_PATH_MEMBER_MASK | _PREFIX_PATH_TUNING_MASK))

#define _PREFIX_ENUM_KNOWN_PATH(x) ((enum fixpre_known_path)(x & ~_PREFIX_PATH_TUNING_MASK))

enum fixpre_path_families {
    /* Known Windows filesystem paths (Windows, default shell) */
    fixpre_path_families__windows = 0,

    /* Known directories within simulated *nix sysroot. */
    fixpre_path_families__sysroot = 1 << _PREFIX_PATH_MEMBER_BITS,

    /* Executable and dynamic library lookup paths, i.e. PATH. */
    fixpre_path_families__binpath = 2 << _PREFIX_PATH_MEMBER_BITS,

    /* Known Windows OS devices and kernel-driven filesystems. */
    fixpre_path_families__devices = 3 << _PREFIX_PATH_MEMBER_BITS,

    /* Pipe name prefices of simulated /sys, /proc, etc. */
    fixpre_path_families__proc_fs = 4 << _PREFIX_PATH_MEMBER_BITS,
};

#define _PREFIX_PATH_IS_PATHLIST(req) \
    ((req & _PREFIX_PATH_FAMILY_MASK) == fixpre_path_families__binpath)

/**
 * Well-known paths within (real or simulated) sysroot. RELATIVE.
 * Obvious #ifndef..#endif spaghetti for user-injected overrides.
 * 
 * The Windows convention (the one MXE respects) is that loadable
 * images, whether *.exe or *.dll, are placed in "bin", and "lib"
 * only contains static and/or import libraries consumed at build
 * time. This saves a lot of space (in case of static libraries),
 * and also simplifies the composition of %PATH%.
 */
#ifndef _SUFFIX_PATH_BIN
#define _SUFFIX_PATH_BIN        "bin/"
#endif
#ifndef _SUFFIX_PATH_CRT
#define _SUFFIX_PATH_CRT        _SUFFIX_PATH_BIN "crt/"
#endif
#ifndef _SUFFIX_PATH_ETC
#define _SUFFIX_PATH_ETC        "etc/"
#endif
/* ... lesser, less often used implementation details ... */
#ifndef _SUFFIX_PATH_LIBEXEC
#define _SUFFIX_PATH_LIBEXEC    "libexec/"
#endif
#ifndef _SUFFIX_PATH_SHARE
#define _SUFFIX_PATH_SHARE      "share/"
#endif
#ifndef _SUFFIX_PATH_SBIN
#define _SUFFIX_PATH_SBIN       "bin/"
#endif
#ifndef _SUFFIX_PATH_VAR
#define _SUFFIX_PATH_VAR        "var/"
#endif
/* ... documentation ... */
#ifndef _SUFFIX_PATH_DOC
#define _SUFFIX_PATH_DOC        "doc/"
#endif
#ifndef _SUFFIX_PATH_MAN
#define _SUFFIX_PATH_MAN        "man/"
#endif
/* ... package manager / installation script metadata ... */
#ifndef _SUFFIX_PATH_INSTALLED
#define _SUFFIX_PATH_INSTALLED  "installed/"
#endif
/* ... build-time dependencies for self-hosted builds ... */
#ifndef _SUFFIX_PATH_INCLUDE
#define _SUFFIX_PATH_INCLUDE    "include/"
#endif
#ifndef _SUFFIX_PATH_LIB
#define _SUFFIX_PATH_LIB        "lib/"
#endif

/**
 * Prefix to configuration directory names placed in user profile (%HOME%) root.
 * No "hidden" semandic on Windows, but many ported programs expect it that way.
 *      Applied in the following modes (enabled in the following scopes):
 *  `fixpre_config_options__profile_as_etchome` (app startup time)
 *  `fixpre_path_modifiers__profile_dir`        (individual path request)
 */
#ifndef _PREFIX_HOME_CONFIG
#define _PREFIX_HOME_CONFIG "."
#endif

/**
 * Well-known utility names.
*/
#ifndef _SUFFIX_PATH_SH
#define _SUFFIX_PATH_SH             "sh"
#endif
#ifndef _SUFFIX_PATH_BSHELL
#define _SUFFIX_PATH_BSHELL _SUFFIX_PATH_BIN _SUFFIX_PATH_SH
#endif

/**
 * Distro name. Our fifteen minutes of fame. Feel free to alter in your own mod;
 * just make sure it is 4-character, starts with a capital and ends with an "a".
 * "Dina", "Gina", "Nina", "Lima", "Xena", "Mona" and "Lisa" are all good names.
 * 
 * ...kidding, of course. This file is public domain. Modify as you wish.
 * This will become the "application name" used within AppLocal and ProgramData.
 * If set to an empty string, no "best Windows practices" will ever be followed.
 */
#ifndef _PREFIX_DISTRO_NAME
#define _PREFIX_DISTRO_NAME "Rita"
#endif

/**
 * Installation path of `libprefix` within the simulated root.
 * You typically don't need to change that.
 */
#ifndef _SUFFIX_PATH_PRE
#define _SUFFIX_PATH_PRE _SUFFIX_PATH_BIN
#endif

/**
 * Now the zoo. Options that differ from each other only by a fixed suffix
 * or modifier flags NEED NOT BE SPECIFIED. Only custom runtime logic that
 * cannot be expressed with modifier flags matters.
 * (Reading of known environment variables, however, _is_ custom logic and
 * the implementation must be given the freedom to replace it silently.)
 * 
 * The "known" paths are loaded in enumeration order;
 *  for all the above, per-profile after non-profile;
 *  for all the above, config (etc) after non-config.
 * This is a hint at out logic, not a hard guarantee.
 */
enum fixpre_known_path {
    fixpre_known_path__windows = fixpre_path_families__windows,
    fixpre_known_path__sys_dir,
    fixpre_known_path__c_shell,  /* %ComSpec% */
    fixpre_known_path__dot_net,
    fixpre_known_path__homedir,  /* profile ? %USERPROFILE% : %PUBLIC% */
    fixpre_known_path__datadir,  /* AppData\Local or ProgramData */
    fixpre_known_path__roaming,  /* AppData\Roaming folder, i.e. %APPDATA% */
    fixpre_known_path__tmp_dir,

    fixpre_known_path__sysroot = fixpre_path_families__sysroot,
    fixpre_known_path__etcroot,

    fixpre_known_path__defpath = fixpre_path_families__binpath,
    fixpre_known_path__stdpath,

    fixpre_known_path__devnull = fixpre_path_families__devices,
    fixpre_known_path__tty,

    fixpre_known_path__pipe_fs = fixpre_path_families__proc_fs,
};

/**
 * Initial sysroot location options. Normal (package-managed, production)
 * application code should't need any of them, but they may be useful for
 * standalone/self-contained installation, confinement within the current
 * user profile or disambiguation between multiple sysroots ("production"
 * where most packages are installed vs. "debug" where the AUT is staged).
 * 
 * Despite bit separation, flags below represent complete, self-contained
 * policies representing distinct use cases. (Exceptions are documented.)
 */
enum fixpre_config_options {
    /**
     * Default mode: libprefix uses its own symbols to identify the canary
     * binary (DLL or EXE) image it is linked into, locates the image file
     * within the file system, checks whether it is placed under the "bin"
     * (more precisely, _SUFFIX_PATH_PRE) directory, and if it is, assumes
     * the base directory of the _SUFFIX_PATH_PRE relative path to be the
     * simulated root. (The difference from simply choosing the parent dir
     * is that if _SUFFIX_PATH_PRE contains multiple path elements -- e.g.
     * "my/bin/" -- the parent of "my", rather than that of "bin", becomes
     * the assumed sysroot.)
     * 
     * _SUFFIX_PATH_PRE can be different from _SUFFIX_PATH_BIN. This is to
     * support a scenario in which `libprefix` is placed outside the "bin"
     * directory, but _PATH_BIN should still return the stock "bin". As a
     * distro maintainer, you probably don't need it, but who knows.
     * 
     * If the canary binary logic fails but there is a logged-in user with
     * a valid profile (%USERPROFILE% or %HOMEDRIVE%HOMEPATH%), the user's
     * profile is used in `profile_as_etcroot` mode  -- i.e. configuration
     * in AppData\Local and everything else under the directory the *main*
     * *application* *file* is located in (as under `app_dir_as_sysroot`).
     * 
     * If the profile cannot be located, the mode is `app_dir_as_sysroot`.
     * 
     * Significance: only to have some reasonable, human-readable place to
     * post the above explanation -- so that you could find it.
     */
    fixpre_config_options__completely_vanilla = 0,

    /**
     * The app image directory is considered the sysroot.
     * Significance: the application is self-contained.
     */
    fixpre_config_options__app_dir_as_sysroot = (1 << 0),

    /**
     * The sysroot is confined within the user profile.
     * Best Windows practices are followed (read: AppData\Local).
     * Significance: the application is only exists for a single user,
     * without any administrative permissions or systemwide footprint.
     */
    fixpre_config_options__profile_as_sysroot = (1 << 1),

    /**
     * The /etc directory is confined within the user profile.
     * Best Windows practices are followed (read: AppData\Local).
     * Significance: the application is installed systemwide,
     * but user-specific configurations are respected.
     */
    fixpre_config_options__profile_as_etcroot = (1 << 2),

    /**
     * The /etc directory is ASSUMED TO BE the user profile.
     * Leading '.' (_PREFIX_HOME_CONFIG) is added to leading directory names.
     * Significance: compatibility mode with stupid ported stuff that assumes
     * %HOME% to be a place exactly like $HOME. There is no place like $HOME!
     */
    fixpre_config_options__profile_as_etchome = (1 << 3),

    /**
     * The canary binary is the main program rather than the binary image
     * (e.g. "libprefix.dll") that `libprefix` is linked into.
     * Significance: either `libprefix` from a stable sysroot used with an
     * application build installed in a staging sysroot, or developing and
     * debugging `libprefix` itself.
     */
    fixpre_config_options__app_dir_as_lib_dir = (1 << 4),

    /**
     * If the value of _PREFIX_DISTRO_NAME is nonempty and an envvar under that
     * name exists and points to a valid directory, assume this directory to be
     * the sysroot without any second thoughts and further inquiries.
     * Significance: quick sysroot switching. Don't use in production.
     */
    fixpre_config_options__env_var_as_sysroot = (1 << 5),

    /**
     * The temporary directory (however determined) is used as sysroot.
     * Significance: either extremely transient staging mode or trying the distro
     * without installation.
     */
    fixpre_config_options__tmp_dir_as_sysroot = (1 << 6),

    /* Modifier ("tuning") flags. Can be combined with the options above. */

    /**
     * Don't set the %HOME% environment variable during initialization.
     * By default, it is done for convenience, and only of %HOME% isn't already
     * set. The value is not exported, i.e. only affects the running process and
     * its children and does not persist in the parent process (e.g. the shell).
     */
    fixpre_config_options__tuning_noninvasive = (1 << 30),

    /* reserved */
    fixpre_config_options__reserved_upper_bit = (1 << 31),
};

/**
 * Custom path resolution options. Call before any call to fixpre_path(), or never.
 * If called multiple times, only the argument passed to the last call applies.
 * If the value has already been put to use, returns -1 and sets `errno` to EBUSY.
 */
int fixpre_configure(enum fixpre_config_options options);

/**
 * Type of the file represented by a known base path.
 * If the file type is unknown, returns S_IFDIR.
 * 
 */
int fixpre_file_type(int path_kind);

/**
 * Describes the known path kind. No actual lookup is made.
 * The result is not affected by modifiers.
 * The result is nullptr if the base path kind is unknown
 *      (can be used to test the validity of `path_kind`).
 * The returned C-string is read-only and need not be freed.
 */
const char* fixpre_explain(int path_kind);

/**
 * Actual path resolution function. `_PATH_*` macros contain calls to it internally.
 * It is NOT the caller's responsibility to free returned memory; designing otherwise
 * would destroy compatibility with macros normally expected to be literal strings.
 */
const char* fixpre_path(int path_kind_with_optional_modifiers, const char* suffix);

/**
 * Shortcut for `fixpre_path(path_kind_with_optional_modifiers, "")`
 */
const char* fixpre_base_path(int path_kind_with_optional_modifiers);

/**
 * Toybox uses: _PATH_DEFPATH (all around), _PATH_UTMP (getty); hardcodes _PATH_KLOG.
 * _PATH_STDPATH stays unused. Our policy is to query per-user path from the registry
 *   or environment and then vet (whitelist) components that gets into _PATH_DEFPATH.
 * 
 * From Linux, we can adopt: _PATH_DEVNULL (nul), _PATH_TTY (con).
 * Once `toysh` is stable, it will be harmless to add: _PATH_BSHELL
 * Adding `cmd.exe` as _PATH_CSHELL will probably make a nice joke.
 * 
 * The most important idea of _PATH_{DEF,STD}PATH is that they are prescriptive, not
 * informative/"approximative". You, as the distro maintainer, want them to be "such
 * and such". We can then introduce the following notation:
 * 
 * 0. `_PREFIX_DISTRO_DEFPATH` and `_PREFIX_DISTRO_STDPATH` are used as templates of
 *      actual `_PATH_DEFPATH` and `_PATH_STDPATH`.
 * 
 * 1. `_PREFIX_DISTRO_COMSEP` specifies the template component separator.
 *      It's ':' by default to align with the *nix convention but can be overridden.
 *      (To use absolute paths with drive letters, it has to be, but we do not want
 *      to encourage absolute paths in macros as a first-class use case.)
 * 
 * 2. `_PREFIX_DISTRO_VARTAG` specifies the "brace" character or substring that both
 *      begins and ends a variable name within the path component -- similar to "%"s
 *      that mark an environment variable name within a substituted string.
 * 
 * 3. A variable may appear anywhere in the path template component but the trailing
 *      part of the component MAY be interpreted in variable-specific way, rendering
 *      the variable effectively a function. The default interpretation, however, is
 *      simply that the trailing suffix will be appended literally.
 * 
 *      Template variable scanning occurs right-to-left, i.s. $A$tomato$B$potato is,
 *      effectively, A(tomato + B(potato)).
 * 
 * 4. The parser expands environment variables after it splits the path template into
 *      components and recognizes template variables. If template variable processing
 *      leads to a registry read, REG_EXPAND_SZ values are expanded using the current
 *      environment block, but are not subject to any further parsing; in other words
 *     (this is another gentle nudge of ours), there's no reason to use path template
 *      variables in values stored in the registry.
 * 
 * 5. The following template variables are defined:
 * 
 *      $HKCU$path/within/the/current/user/hive/ending/with/value/name
 *      $HKDU$path/within/the/default/user/hive/ending/with/value/name
 *      $HKLM$path/within/the/local/machine/hive/ending/with/value/name
 *          (No other registry hives are explicitly supported.)
 * 
 *      $HKCUENV$envvar         same as $HKCU$Environment/envvar
 *      $HKDUENV$envvar         same as $HKDU$Environment/envvar
 *      $HKLMENV$envvar         system environment variable (%envvar%)
 *       (there is no similarly beautiful $HKLM$ equivalent, but you got the point)
 *                          
 *      $HKLMPATH$              system %PATH% value (suffix ignored)
 *      $HKCUPATH$              current user %PATH% value (-"-)
 *      $HKDUPATH$              default user %PATH% value (-"-)
 *          Path component splitting occurs after envvar expansion.
 *          The line preceding the variable is processed separately.
 * 
 *      $WINDIR$sub/di/rectory  same as %windir%sub/di/rectory
 *      $SYSDIR$subdi/rector/y  same as above but relative to system dir (System32)
 *      $PREFIX$subdir/ecto/ry  ...but relative to the distro root
 *      $HOME$su/b/directory    ...to the current user profile
 *      $KNOWN${Music|Pictures|Downloads|...}/subdir
 *          ...to a known profile folder speficied by the first suffix component.
 *          In other words, if your locale is Spanish and Downloads is Descargas,
 *          $KNOWN$Downloads/EGElephantSDK becomes $HOME$Descargas/EGElephantSDK.
 *          The trailing suffix components are not localized. 
 *          The download name used in this example is fictional.
 * 
 *      The variable names are case-sensitive and must be in all capitals.
 *      (Replace the '$' character above with the effective `_PREFIX_DISTRO_VARTAG`.)
 * 
 * 6. Fully expanded path components that aren't absolute paths (don't start with any
 *      drive letter or a double [back]slash) are relative to distro prefix (sysroot).
 * 
 * 7. Second, third etc. case- and dirsep-insensitively identical occurrences of path
 *      components in the eventual path MAY be eliminated by the implementation.
 */

#ifndef _PREFIX_DISTRO_COMSEP
#define _PREFIX_DISTRO_COMSEP ":"
#endif

#ifndef _PREFIX_DISTRO_VARTAG
#define _PREFIX_DISTRO_VARTAG "$"
#endif

#ifndef _PREFIX_DISTRO_DEFPATH
#define _PREFIX_DISTRO_DEFPATH _SUFFIX_PATH_BIN ":" _SUFFIX_PATH_CRT ":$HKCUPATH$:$HKLMPATH$"
#endif

#ifndef _PREFIX_DISTRO_STDPATH
#define _PREFIX_DISTRO_STDPATH _SUFFIX_PATH_BIN ":" _SUFFIX_PATH_CRT ":$HKDUPATH$:$HKLMPATH$"
#endif

#define _PATH_DEFPATH   fixpre_base_path(fixpre_known_path__defpath | fixpre_path_modifiers__native_dsep | fixpre_path_modifiers__profile_dir)
#define _PATH_STDPATH   fixpre_base_path(fixpre_known_path__stdpath | fixpre_path_modifiers__native_dsep)

#define _PATH_CSHELL    fixpre_base_path(fixpre_known_path__c_shell)

#define _PATH_DEVNULL   fixpre_base_path(fixpre_known_path__devnull)
#define _PATH_TTY       fixpre_base_path(fixpre_known_path__tty)

//_PATH_*
// ...

/**
 * Iterate over valid `enum fixpre_known_path` numbers (w/modifiers set to 0).
 */
void fixpre_enumerate_known_base_paths(void(*callback)(enum fixpre_known_path, const char* value));

/**
 * Iterate over known cached paths (all of them).
 */
void fixpre_enumerate_cached_paths(void(*callback)(enum fixpre_known_path, const char* suffix, const char* value));

/* END_DECLS */
#ifdef __cplusplus
}

/**
 * Bonus C++ API (better memory management, only that and nothing more)
 */
namespace fixpre
{

/** See `fixpre_path` */
std::string Path(int path_kind_with_optional_modifiers, const std::string& suffix = {});

/** See `fixpre_enumerate_known_base_paths` */
using OnKnownPath = std::function<void(enum fixpre_known_path, const std::string& value)>;
void EnumerateKnownBasePaths(OnKnownPath callback);

/** See `fixpre_enumerate_cached_paths` */
using OnCachedPath = std::function<void(enum fixpre_known_path, const std::string& suffix, const std::string& value)>;
void EnumerateCachedPaths(OnCachedPath callback);

} // namespace fixpre
#endif

#endif // _PATHS_H_
