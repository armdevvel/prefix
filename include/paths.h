#ifndef _PATHS_H_
#define	_PATHS_H_

/* BEGIN_DECLS */
#ifdef __cplusplus
extern "C" {
#endif

/**
 * Why the whimsical "fixpre"? Unfortunately, "prefix" is too common a word,
 * and while macros only affect specific translation units, symbols must be
 * unique within a linked binary (shared library or executable).
 * 
 * Also, it's an acronym for "fix prefix", which is what libprefix is written to do.
 */

/**
 * Special path request flags. The list may be expanded over time, but
 * there will always be enough free bits to accommodate the path family.
 */
enum fixpre_path_modifiers {
    fixpre_path_modifiers__profile_dir = (1 << 31), /* per-user; flips sign */
    fixpre_path_modifiers__native_dsep = (1 << 30), /* '\\' instead of '/' */
    fixpre_path_modifiers__native_psep = (1 << 29), /* ';' instead of ':' */
};

/**
 * A bitwise 'or' of the modifiers above, with a generous reservation.
 */
#define _PREFIX_PATH_TUNING_MASK 0x7F000000

#define _PREFIX_PATH_MEMBER_BITS 16
#define _PREFIX_PATH_MEMBER_MASK ((1 << _PREFIX_PATH_MEMBER_BITS) - 1)
#define _PREFIX_PATH_FAMILY_MASK (~(_PREFIX_PATH_MEMBER_MASK | _PREFIX_PATH_CUSTOM_MASK))

enum fixpre_path_families {
    /* Executable and dynamic library lookup paths, i.e. PATH. */
    fixpre_path_families__binpath = 0,

    /* Known Windows filesystem paths (Windows, default shell) */
    fixpre_path_families__windows = 1 << _PREFIX_PATH_MEMBER_BITS,

    /* Known Windows OS devices and kernel-driven filesystems. */
    fixpre_path_families__devices = 2 << _PREFIX_PATH_MEMBER_BITS,

    /* Known directories within simulated *nix sysroot. */
    fixpre_path_families__sysroot = 3 << _PREFIX_PATH_MEMBER_BITS,

    /* Pipe name prefices of simulated /sys, /proc, etc. */
    fixpre_path_families__proc_fs = 4 << _PREFIX_PATH_MEMBER_BITS,
};

/**
 * Well-known paths within (real or simulated) sysroot. RELATIVE.
 * Obvious #ifndef..#endif spaghetti for user-injected overrides.
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
 * Now the zoo.
 */
enum fixpre_known_path {
    fixpre_known_path__defpath = fixpre_path_families__binpath,
    fixpre_known_path__stdpath,
    fixpre_known_path__devnull = fixpre_path_families__devices,
    fixpre_known_path__tty,
};

/**
 * Initial sysroot location options. Normal (package-managed, production)
 * application code should't need any of them, but they may be useful for
 * standalone/self-contained installation, confinement within the current
 * user profile or disambiguation between multiple sysroots ("production"
 * where most packages are installed vs. "debug" where the AUT is staged).
 * 
 * Despite bit separation, flags below represent complete, self-contained
 * policies representing distinct use cases. (Combine if you feel lucky.)
 */
enum fixpre_config_options {
    /**
     * Default mode: libprefix uses its own symbols to identify the canary
     * binary (DLL or EXE) image it is linked into, locates the image file
     * within the file system, checks whether it is placed under some "bin"
     * (more precisely, _SUFFIX_PATH_BIN) directory, and if it is, assumes
     * the base directory of the _SUFFIX_PATH_BIN relative path to be the
     * simulated root. (The difference from simply choosing the parent dir
     * is that if _SUFFIX_PATH_BIN contains multiple path elements -- e.g.
     * "my/bin/" -- the parent of "my", rather than that of "bin", becomes
     * the assumed sysroot.)
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
};

/**
 * Custom path resolution options. Call before any call to fixpre_path(), or never.
 * If called multiple times, only the argument passed to the last call applies.
 */
int fixpre_configure(enum fixpre_config_options options);

/**
 * Actual path resolution function. `_PATH_*` macros contain calls to it internally.
 * It is NOT the caller's responsibility to free returned memory; designing otherwise
 * would destroy compatibility with macros normally expected to be literal strings.
 */
const char* fixpre_path(enum fixpre_known_path, const char* suffix);

/**
 * Toybox uses: _PATH_DEFPATH (all around), _PATH_UTMP (getty); hardcodes _PATH_KLOG.
 * _PATH_STDPATH stays unused. Our policy is to query _PATH_STDPATH from the registry
 *   or environment and then vet (whitelist) components that gets into _PATH_DEFPATH.
 * 
 * From Linux, we can adopt: _PATH_DEVNULL (nul), _PATH_TTY (con).
 * Once `toysh` is stable, it will be harmless to add: _PATH_BSHELL
 * Adding `cmd.exe` as _PATH_CSHELL will probably make a nice joke.
 */

//_PATH_*
//_PATH_*
//_PATH_*
// ...

/**
 * Returns the user profile path or an empty string if the path cannot be determined.
 * In case of success and if the argument is nonzero, also sets the HOME environment
 * variable for the process and its children accordingly.
 */
const char* fixpre_userprofile(int nix_compat);

/* END_DECLS */
#ifdef __cplusplus
}
#endif

#endif // _PATHS_H_
